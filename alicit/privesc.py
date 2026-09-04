#!/usr/bin/env python3
"""
privesc.py - M365 Privilege Escalation Engine

Three-layer architecture:
1. Deterministic permission graph (edge table + recon)
2. Foundation-Sec-8B reasoning layer
3. Top-3 path ranking with probability scores

Integrates with postexp.py: run_privesc(token_mgr, recon_data) returns JSON.

Project: AIlicit
"""

import os
import sys
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime
import requests

# ============================================================
# CONFIGURATION
# ============================================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
    probability: float  # 0.0-1.0 percentage
    impact: str
    stealth_score: float
    time_estimate: str
    narrative: str
    reasoning: str

# ============================================================
# DETERMINISTIC EDGE EXPANDER
# ============================================================

class EdgeExpander:
    """Expands all possible escalation edges from recon data."""
    
    # Known M365 escalation edge table
    EDGE_TABLE = [
        {
            "id": "edge_dir_rw_group_owner",
            "name": "Group Ownership Escalation",
            "desc": "Add self as owner of a writable group, then join role-assignment group",
            "scopes": ["Directory.ReadWrite.All"],
            "gain": "Group Admin -> Domain Admin via role-assignment",
            "confidence": 0.95,
            "stealth": 0.6,
            "reversible": True,
            "graph_call": "POST /groups/{group_id}/owners/$ref"
        },
        {
            "id": "edge_app_rw_owner",
            "name": "Application Ownership Escalation",
            "desc": "Take ownership of an enterprise app and grant it privileged API roles",
            "scopes": ["Application.ReadWrite.All"],
            "gain": "App Admin -> Global Admin via app role assignment",
            "confidence": 0.9,
            "stealth": 0.7,
            "reversible": True,
            "graph_call": "POST /applications/{app_id}/owners/$ref"
        },
        {
            "id": "edge_mail_rw_forwarding",
            "name": "Mail Forwarding Rule (Persistence)",
            "desc": "Create a forwarding rule for exfiltration and persistence",
            "scopes": ["Mail.ReadWrite"],
            "gain": "Persistence + Email Exfiltration",
            "confidence": 0.85,
            "stealth": 0.4,
            "reversible": True,
            "graph_call": "POST /me/mailFolders/inbox/messageRules"
        },
        {
            "id": "edge_dir_rw_guest_invite",
            "name": "Guest User Invitation",
            "desc": "Invite external guest user with privileged role",
            "scopes": ["Directory.ReadWrite.All"],
            "gain": "Guest Access -> Potential Admin",
            "confidence": 0.8,
            "stealth": 0.5,
            "reversible": True,
            "graph_call": "POST /invitations"
        },
        {
            "id": "edge_contacts_rw",
            "name": "Contacts Modification",
            "desc": "Modify shared contacts / mail contacts for persistence",
            "scopes": ["Contacts.ReadWrite"],
            "gain": "Persistence via contact redirection",
            "confidence": 0.7,
            "stealth": 0.6,
            "reversible": True,
            "graph_call": "PATCH /contacts/{contact_id}"
        },
        {
            "id": "edge_app_role_grant",
            "name": "Application Role Grant",
            "desc": "Grant application a privileged API role",
            "scopes": ["Application.ReadWrite.All"],
            "gain": "App Role -> Admin via app consent",
            "confidence": 0.75,
            "stealth": 0.5,
            "reversible": True,
            "graph_call": "POST /applications/{app_id}/appRoles"
        }
    ]
    
    def __init__(self, recon_data: ReconData):
        self.recon = recon_data
        self.edges = []
    
    def expand(self) -> List[EscalationEdge]:
        """Expand all possible edges based on recon data."""
        self.edges = []
        
        for edge_def in self.EDGE_TABLE:
            if not self._has_scopes(edge_def["scopes"]):
                continue
            
            if edge_def["id"] == "edge_dir_rw_group_owner":
                self._expand_group_owner(edge_def)
            elif edge_def["id"] == "edge_app_rw_owner":
                self._expand_app_owner(edge_def)
            elif edge_def["id"] == "edge_mail_rw_forwarding":
                self._expand_mail_forwarding(edge_def)
            else:
                self._expand_generic(edge_def)
        
        return self.edges
    
    def _has_scopes(self, required: List[str]) -> bool:
        return all(scope in self.recon.granted_scopes for scope in required)
    
    def _expand_group_owner(self, edge_def: Dict):
        for group in self.recon.groups:
            if group.get("is_writable", False) or not group.get("is_owner", False):
                self.edges.append(EscalationEdge(
                    path_id=f"{edge_def['id']}_{group.get('id', 'unknown')}",
                    name=edge_def["name"],
                    description=f"{edge_def['desc']} - Group: {group.get('displayName', 'Unknown')}",
                    required_scopes=edge_def["scopes"],
                    prereq_objects=[group.get("id", "")],
                    action=f"Add self as owner of {group.get('displayName', 'Unknown')}",
                    gain=edge_def["gain"],
                    confidence=edge_def["confidence"],
                    stealth_score=edge_def["stealth"],
                    reversibility=edge_def["reversible"],
                    graph_call=edge_def["graph_call"].replace("{group_id}", group.get("id", "")),
                    preconditions={"group_id": group.get("id"), "group_name": group.get("displayName")}
                ))
    
    def _expand_app_owner(self, edge_def: Dict):
        for app in self.recon.applications:
            if not app.get("is_owner", False):
                self.edges.append(EscalationEdge(
                    path_id=f"{edge_def['id']}_{app.get('id', 'unknown')}",
                    name=edge_def["name"],
                    description=f"{edge_def['desc']} - App: {app.get('displayName', 'Unknown')}",
                    required_scopes=edge_def["scopes"],
                    prereq_objects=[app.get("id", "")],
                    action=f"Take ownership of {app.get('displayName', 'Unknown')}",
                    gain=edge_def["gain"],
                    confidence=edge_def["confidence"],
                    stealth_score=edge_def["stealth"],
                    reversibility=edge_def["reversible"],
                    graph_call=edge_def["graph_call"].replace("{app_id}", app.get("id", "")),
                    preconditions={"app_id": app.get("id"), "app_name": app.get("displayName")}
                ))
    
    def _expand_mail_forwarding(self, edge_def: Dict):
        self.edges.append(EscalationEdge(
            path_id=edge_def["id"],
            name=edge_def["name"],
            description=edge_def["desc"],
            required_scopes=edge_def["scopes"],
            prereq_objects=[],
            action="Create forwarding rule in inbox",
            gain=edge_def["gain"],
            confidence=edge_def["confidence"],
            stealth_score=edge_def["stealth"],
            reversibility=edge_def["reversible"],
            graph_call=edge_def["graph_call"],
            preconditions={}
        ))
    
    def _expand_generic(self, edge_def: Dict):
        self.edges.append(EscalationEdge(
            path_id=edge_def["id"],
            name=edge_def["name"],
            description=edge_def["desc"],
            required_scopes=edge_def["scopes"],
            prereq_objects=[],
            action=edge_def["name"],
            gain=edge_def["gain"],
            confidence=edge_def["confidence"],
            stealth_score=edge_def["stealth"],
            reversibility=edge_def["reversible"],
            graph_call=edge_def["graph_call"],
            preconditions={}
        ))

# ============================================================
# FOUNDATION-SEC-8B REASONING LAYER
# ============================================================

class Sec8BReasoner:
    """Reasoning layer using Foundation-Sec-8B model."""
    
    def __init__(self, model=None):
        self.model = model
    
    def select_paths(self, edges: List[EscalationEdge], recon_data: ReconData) -> List[RankedPath]:
        """Select top 3 escalation paths using AI reasoning."""
        
        if not edges:
            return []
        
        # If no model, fallback to deterministic ranking
        if not self.model:
            return self._fallback_selection(edges)
        
        # Build prompt for top-3 selection
        edges_json = json.dumps([asdict(e) for e in edges], indent=2)
        recon_json = json.dumps(asdict(recon_data), indent=2)
        
        prompt = f"""
You are an AI security analyst. Select the top 3 most probable privilege escalation paths from these deterministic options.

RECON DATA:
{recon_json}

CANDIDATE PATHS:
{edges_json}

SELECTION CRITERIA:
1. Likelihood of success (confidence)
2. Stealth (least noise)
3. Speed to final privilege

Return ONLY valid JSON with top 3 paths:
{{
    "top_paths": [
        {{
            "path_id": "edge_...",
            "name": "Path name",
            "description": "Description",
            "steps": ["step 1", "step 2"],
            "probability": 0.95,
            "impact": "what privilege is gained",
            "stealth_score": 0.7,
            "time_estimate": "2-3 minutes",
            "narrative": "human-readable explanation",
            "reasoning": "why this path is selected"
        }}
    ]
}}
"""
        
        try:
            # Use the model to generate response
            response = self.model.generate(prompt)
            data = json.loads(response)
            
            ranked_paths = []
            for path_data in data.get("top_paths", [])[:3]:
                # Find matching edge
                edge = next((e for e in edges if e.path_id == path_data.get("path_id")), None)
                if edge:
                    ranked_paths.append(RankedPath(
                        path_id=path_data["path_id"],
                        name=path_data.get("name", edge.name),
                        description=path_data.get("description", edge.description),
                        steps=path_data.get("steps", [edge.action]),
                        probability=min(1.0, max(0.0, float(path_data.get("probability", edge.confidence)))),
                        impact=path_data.get("impact", edge.gain),
                        stealth_score=float(path_data.get("stealth_score", edge.stealth_score)),
                        time_estimate=path_data.get("time_estimate", "2-3 minutes"),
                        narrative=path_data.get("narrative", edge.description),
                        reasoning=path_data.get("reasoning", "Selected by AI reasoning layer.")
                    ))
            
            return ranked_paths
            
        except Exception as e:
            logger.warning(f"AI selection failed: {e}")
            return self._fallback_selection(edges)
    
    def _fallback_selection(self, edges: List[EscalationEdge]) -> List[RankedPath]:
        """Fallback: select top 3 by confidence."""
        sorted_edges = sorted(edges, key=lambda e: e.confidence, reverse=True)[:3]
        
        return [
            RankedPath(
                path_id=e.path_id,
                name=e.name,
                description=e.description,
                steps=[e.action],
                probability=e.confidence,
                impact=e.gain,
                stealth_score=e.stealth_score,
                time_estimate="2-3 minutes",
                narrative=e.description,
                reasoning="Selected by confidence score (fallback)."
            )
            for e in sorted_edges
        ]

# ============================================================
# MAIN ORCHESTRATOR (Agent-Free)
# ============================================================

class PrivilegeEscalationEngine:
    """Main orchestrator for privilege escalation (no agent)."""
    
    def __init__(self, graph_client=None, model=None):
        self.graph_client = graph_client
        self.model = model
        self.recon_data = None
        self.edges = []
        self.ranked_paths = []
    
    def recon(self) -> ReconData:
        """Perform reconnaissance and collect data."""
        # In production: call actual Graph API + parallel_recon
        return ReconData(
            granted_scopes=[
                "Directory.ReadWrite.All",
                "Application.ReadWrite.All",
                "Mail.ReadWrite",
                "Contacts.ReadWrite"
            ],
            user={
                "id": "user-001",
                "userPrincipalName": "security@test.com",
                "displayName": "Security User"
            },
            groups=[
                {
                    "id": "group-001",
                    "displayName": "Admin-SG-01",
                    "is_writable": True,
                    "is_owner": False
                },
                {
                    "id": "group-002",
                    "displayName": "Domain Admins",
                    "is_writable": False,
                    "is_owner": False
                }
            ],
            applications=[
                {
                    "id": "app-001",
                    "displayName": "EntraID-Admin-App",
                    "is_owner": False
                }
            ],
            mail_rules=[],
            contacts=[],
            misconfigs=[
                {
                    "type": "writable_group",
                    "description": "Admin-SG-01 is writable by non-owners",
                    "severity": "high"
                }
            ]
        )
    
    def run(self, recon_data: Optional[ReconData] = None, dry_run: bool = True) -> Dict:
        """Run the complete privilege escalation workflow (agent-free)."""
        
        logger.info("=" * 60)
        logger.info("PRIVILEGE ESCALATION ENGINE STARTING (AGENT-FREE)")
        logger.info("=" * 60)
        
        # Phase 1: Reconnaissance
        logger.info("\n[PHASE 1] RECONNAISSANCE")
        self.recon_data = recon_data if recon_data else self.recon()
        logger.info(f"[+] Granted scopes: {self.recon_data.granted_scopes}")
        logger.info(f"[+] Groups found: {len(self.recon_data.groups)}")
        logger.info(f"[+] Applications found: {len(self.recon_data.applications)}")
        logger.info(f"[+] Misconfigurations: {len(self.recon_data.misconfigs)}")
        
        # Phase 2: Edge Expansion
        logger.info("\n[PHASE 2] DETERMINISTIC EDGE EXPANSION")
        expander = EdgeExpander(self.recon_data)
        self.edges = expander.expand()
        logger.info(f"[+] Found {len(self.edges)} candidate escalation paths")
        
        # Phase 3: AI Path Selection (Top 3)
        logger.info("\n[PHASE 3] AI PATH SELECTION (Sec-8B)")
        reasoner = Sec8BReasoner(self.model)
        self.ranked_paths = reasoner.select_paths(self.edges, self.recon_data)
        
        if not self.ranked_paths:
            logger.error("[-] No escalation paths found")
            return {"status": "failed", "reason": "No paths found"}
        
        logger.info(f"[+] Top {len(self.ranked_paths)} paths selected")
        for idx, path in enumerate(self.ranked_paths, 1):
            logger.info(f"    [{idx}] {path.name} - {path.probability*100:.1f}%")
        
        # Phase 4: Summary
        logger.info("\n" + "=" * 60)
        logger.info("[+] ESCALATION ANALYSIS COMPLETE")
        logger.info("=" * 60)
        
        return {
            "status": "success",
            "recon": asdict(self.recon_data),
            "total_paths_found": len(self.edges),
            "top_3_paths": [asdict(p) for p in self.ranked_paths]
        }

# ============================================================
# INTEGRATION WITH POSTEXP.PY
# ============================================================

def run_privesc(token_mgr, recon_data: Dict) -> Dict:
    """
    Integration point for postexp.py.
    
    Args:
        token_mgr: TokenManager instance (for Graph API calls)
        recon_data: Dict from parallel_recon in postexp.py
    
    Returns:
        Dict with top 3 paths and probabilities
    """
    # Convert recon_data dict to ReconData
    recon = ReconData(
        granted_scopes=recon_data.get("granted_scopes", []),
        user=recon_data.get("user", {}),
        groups=recon_data.get("groups", []),
        applications=recon_data.get("applications", []),
        mail_rules=recon_data.get("mail_rules", []),
        contacts=recon_data.get("contacts", []),
        misconfigs=recon_data.get("misconfigs", [])
    )
    
    # Initialize engine with token_mgr as graph_client
    engine = PrivilegeEscalationEngine(graph_client=token_mgr)
    result = engine.run(recon_data=recon, dry_run=True)
    
    return result

# ============================================================
# COMMAND-LINE ENTRY POINT
# ============================================================

def main():
    """Command-line entry point."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║        PRIVILEGE ESCALATION ENGINE - AIlicit                  ║
    ║              Agent-Free · Top 3 Paths                         ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    engine = PrivilegeEscalationEngine()
    result = engine.run()
    
    print("\n" + json.dumps(result, indent=2))
    
    # Display top 3 paths clearly
    print("\n" + "=" * 60)
    print("TOP 3 PRIVESC PATHS")
    print("=" * 60)
    for idx, path in enumerate(result.get("top_3_paths", []), 1):
        print(f"\n[{idx}] {path['name']}")
        print(f"    Probability: {path['probability']*100:.1f}%")
        print(f"    Impact: {path['impact']}")
        print(f"    Steps: {' -> '.join(path['steps'])}")
        print(f"    Reasoning: {path['reasoning']}")
        print(f"    Narrative: {path['narrative']}")

if __name__ == "__main__":
    main()