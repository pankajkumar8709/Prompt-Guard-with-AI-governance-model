"""Chat UI with History Sidebar"""

CHAT_UI_WITH_HISTORY = """<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Prompt-Guard Chat</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, -apple-system, sans-serif; background: #0b1220; color: #e5e7eb; height: 100vh; overflow: hidden; }
.container { display: flex; height: 100vh; }
.sidebar { width: 280px; background: #111827; border-right: 1px solid #1f2937; display: flex; flex-direction: column; }
.sidebar-header { padding: 16px; border-bottom: 1px solid #1f2937; }
.sidebar-header h2 { font-size: 14px; color: #9ca3af; margin-bottom: 12px; }
.new-chat-btn { width: 100%; padding: 10px; background: #60a5fa; color: #000; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
.new-chat-btn:hover { background: #3b82f6; }
.sessions-list { flex: 1; overflow-y: auto; padding: 8px; }
.session-item { padding: 12px; margin-bottom: 4px; background: #1f2937; border-radius: 8px; cursor: pointer; border: 1px solid transparent; }
.session-item:hover { background: #374151; }
.session-item.active { border-color: #60a5fa; background: #1e3a5f; }
.session-title { font-size: 13px; font-weight: 600; margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.session-meta { font-size: 11px; color: #9ca3af; }
.delete-btn { float: right; color: #f87171; cursor: pointer; padding: 2px 6px; }
.delete-btn:hover { color: #ef4444; }
.main { flex: 1; display: flex; flex-direction: column; }
.header { padding: 16px; background: #111827; border-bottom: 1px solid #1f2937; }
.header h1 { font-size: 18px; }
.chat-area { flex: 1; overflow-y: auto; padding: 20px; }
.message { margin-bottom: 16px; display: flex; }
.message.user { justify-content: flex-end; }
.message-content { max-width: 70%; padding: 12px 16px; border-radius: 12px; }
.message.user .message-content { background: rgba(96,165,250,0.2); border: 1px solid rgba(96,165,250,0.3); }
.message.assistant .message-content { background: #1f2937; border: 1px solid #374151; }
.message-header { font-size: 11px; color: #9ca3af; margin-bottom: 6px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 10px; font-weight: 600; margin-left: 8px; }
.badge.safe { background: #065f46; color: #34d399; }
.badge.blocked { background: #7f1d1d; color: #f87171; }
.input-area { padding: 16px; background: #111827; border-top: 1px solid #1f2937; display: flex; gap: 12px; }
.input-area input { flex: 1; padding: 12px; background: #1f2937; border: 1px solid #374151; border-radius: 8px; color: #e5e7eb; outline: none; }
.input-area button { padding: 12px 24px; background: #60a5fa; color: #000; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
.input-area button:hover { background: #3b82f6; }
.input-area button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
</head>
<body>
<div class="container">
  <div class="sidebar">
    <div class="sidebar-header">
      <h2>Chat History</h2>
      <button class="new-chat-btn" onclick="newChat()">+ New Chat</button>
    </div>
    <div class="sessions-list" id="sessionsList"></div>
  </div>
  <div class="main">
    <div class="header">
      <h1>🛡️ Prompt-Guard Chat</h1>
    </div>
    <div class="chat-area" id="chatArea"></div>
    <div class="input-area">
      <input id="messageInput" placeholder="Type a message..." onkeypress="if(event.key==='Enter') sendMessage()"/>
      <button onclick="sendMessage()" id="sendBtn">Send</button>
    </div>
  </div>
</div>
<script>
let currentSession = 'session_' + Date.now();
let sessions = {};

async function loadSessions() {
  try {
    const r = await fetch('/chat/sessions');
    const data = await r.json();
    const list = document.getElementById('sessionsList');
    list.innerHTML = '';
    data.sessions.forEach(s => {
      sessions[s.session_id] = s;
      const div = document.createElement('div');
      div.className = 'session-item' + (s.session_id === currentSession ? ' active' : '');
      div.innerHTML = `
        <span class="delete-btn" onclick="deleteSession('${s.session_id}', event)">×</span>
        <div class="session-title">${s.last_message || 'New Chat'}</div>
        <div class="session-meta">${s.message_count} messages</div>
      `;
      div.onclick = () => loadSession(s.session_id);
      list.appendChild(div);
    });
  } catch(e) { console.error(e); }
}

async function loadSession(sid) {
  currentSession = sid;
  try {
    const r = await fetch(`/chat/history/${sid}`);
    const data = await r.json();
    const area = document.getElementById('chatArea');
    area.innerHTML = '';
    data.history.forEach(msg => {
      addMessageToUI(msg.role, msg.content, msg.risk_level, msg.action);
    });
    loadSessions();
  } catch(e) { console.error(e); }
}

async function deleteSession(sid, e) {
  e.stopPropagation();
  if (!confirm('Delete this chat?')) return;
  try {
    await fetch(`/chat/history/${sid}`, { method: 'DELETE' });
    if (sid === currentSession) newChat();
    else loadSessions();
  } catch(e) { console.error(e); }
}

function newChat() {
  currentSession = 'session_' + Date.now();
  document.getElementById('chatArea').innerHTML = '';
  loadSessions();
}

function addMessageToUI(role, text, risk, action) {
  const area = document.getElementById('chatArea');
  const div = document.createElement('div');
  div.className = 'message ' + role;
  let badge = '';
  if (role === 'assistant') {
    if (action === 'BLOCK') badge = '<span class="badge blocked">BLOCKED</span>';
    else if (risk === 'SAFE') badge = '<span class="badge safe">SAFE</span>';
  }
  div.innerHTML = `
    <div class="message-content">
      <div class="message-header">${role === 'user' ? 'You' : 'Assistant'}${badge}</div>
      <div>${text}</div>
    </div>
  `;
  area.appendChild(div);
  area.scrollTop = area.scrollHeight;
}

async function sendMessage() {
  const input = document.getElementById('messageInput');
  const btn = document.getElementById('sendBtn');
  const msg = input.value.trim();
  if (!msg) return;
  
  input.value = '';
  btn.disabled = true;
  addMessageToUI('user', msg);
  
  try {
    const r = await fetch('/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, session_id: currentSession })
    });
    const data = await r.json();
    addMessageToUI('assistant', data.response, data.risk_level, data.action);
    loadSessions();
  } catch(e) {
    addMessageToUI('assistant', 'Error: ' + e.message);
  } finally {
    btn.disabled = false;
    input.focus();
  }
}

loadSessions();
document.getElementById('messageInput').focus();
</script>
</body>
</html>
"""
