import React, { useState, useRef, useCallback, useId, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import './Chat.css';
import { sendChat } from '../api/sentinel';
import { DecisionBadge, RiskBadge, ThreatTag } from '../components/ThreatBadge';
import ReceiptViewer from '../components/ReceiptViewer';

const DECISION_BG = {
  ALLOW:      'chat-bubble allow-theme',
  SANITIZE:   'chat-bubble sanitize-theme',
  QUARANTINE: 'chat-bubble block-theme',
  BLOCK:      'chat-bubble block-theme',
};

function UserBubble({ text }) {
  return (
    <div className="chat-message-row user-row">
      <div className="chat-bubble user-bubble">
        <div style={{ whiteSpace: 'pre-wrap' }}>{text}</div>
      </div>
      <div className="bubble-avatar">👤</div>
    </div>
  );
}

function AssistantBubble({ msg }) {
  const [showReceipt, setShowReceipt] = useState(false);
  
  const isBlocked = msg.decision === 'BLOCK' || msg.decision === 'QUARANTINE';
  const isSanitized = msg.decision === 'SANITIZE';

  if (isBlocked) {
    return (
      <div className="chat-message-row assistant-row">
        <div className="bubble-avatar sentinel-avatar">🛡️</div>
        <div className="chat-content">
          <div className="blocked-card">
            <div className="blocked-header">
              <span style={{ fontSize: 18 }}>🛑</span>
              <strong>SENTINEL-X SECURITY BLOCK</strong>
            </div>
            <div className="blocked-body">
              <p>This request was blocked before reaching the AI model.</p>
              <p><strong>Reason:</strong> {msg.input_analysis?.receipt?.threats_detected?.[0] || 'Policy Violation'}</p>
              <p><strong>Risk:</strong> {msg.input_analysis?.risk?.score} / 100</p>
              <p><strong>Action:</strong> REQUEST BLOCKED</p>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowReceipt(v => !v)}>
              {showReceipt ? 'Hide Security Receipt' : 'View Security Receipt'}
            </button>
            {showReceipt && (
              <div className="receipt-container mt-2">
                <ReceiptViewer receipt={msg.receipt} />
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="chat-message-row assistant-row">
      <div className="bubble-avatar sentinel-avatar">🛡️</div>
      <div className="chat-content" style={{ maxWidth: '85%' }}>
        
        {isSanitized && msg.input_analysis?.sanitized_text && (
          <div className="sanitized-notice">
            🛡️ <span>Sensitive entity protected by SENTINEL-X before reaching the AI.</span>
          </div>
        )}

        <div className="chat-bubble ai-bubble markdown-body">
          {msg.response ? (
            <ReactMarkdown>{msg.response}</ReactMarkdown>
          ) : (
            <span style={{color: 'var(--text-muted)'}}>Empty response</span>
          )}
        </div>

        <div className="bubble-actions">
           <button 
             className="security-receipt-btn"
             onClick={() => setShowReceipt(v => !v)}
           >
             ✓ SECURED
           </button>
           {msg.llm_latency_ms && <span className="latency-text">LLM: {msg.llm_latency_ms.toFixed(0)}ms</span>}
           <span className="latency-text">Total: {msg.total_latency_ms?.toFixed(0)}ms</span>
        </div>

        {showReceipt && (
          <div className="receipt-container mt-2">
             <ReceiptViewer receipt={msg.receipt} />
          </div>
        )}
      </div>
    </div>
  );
}

export default function Chat() {
  const [messages,     setMessages]     = useState([]);
  const [input,        setInput]        = useState('');
  const [loading,      setLoading]      = useState(false);
  const [error,        setError]        = useState(null);
  const [showConfig,   setShowConfig]   = useState(false);
  
  const bottomRef = useRef(null);
  const sessionId = useId().replace(/:/g, '') + '-chat';

  const scrollToBottom = () => {
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
  };

  const send = useCallback(async (textOverride) => {
    const textToSend = textOverride || input;
    if (!textToSend.trim() || loading) return;
    
    const userMsg = textToSend.trim();
    if (!textOverride) setInput('');
    setError(null);
    setMessages(prev => [...prev, { role: 'user', text: userMsg }]);
    setLoading(true);
    scrollToBottom();
    try {
      const data = await sendChat(userMsg, sessionId, null);
      setMessages(prev => [...prev, { role: 'assistant', ...data }]);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
      scrollToBottom();
    }
  }, [input, loading, sessionId]);

  useEffect(() => {
    const onReject = (e) => {
      if (e.detail.sessionId === sessionId) {
        setMessages(prev => [...prev, { 
          role: 'assistant', 
          decision: 'BLOCK', 
          response: null,
          input_analysis: {
              receipt: { threats_detected: ['Session Terminated by Admin'] },
              risk: { score: 100 }
          }
        }]);
      }
    };
    
    window.addEventListener('quarantine-rejected', onReject);
    return () => window.removeEventListener('quarantine-rejected', onReject);
  }, [sessionId]);

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { 
      e.preventDefault(); 
      send(); 
    }
  };

  return (
    <div className="chat-app-container">
      {/* Sidebar / History Panel */}
      <div className="chat-sidebar">
        <button className="btn btn-primary new-chat-btn" onClick={() => setMessages([])}>
          + New Chat
        </button>
        <div className="history-list">
          <div className="history-group">Today</div>
          <div className="history-item active">Current Conversation</div>
        </div>
        <div style={{ flex: 1 }} />
        <div className="sidebar-footer">
          <button className="btn btn-ghost" style={{ width: '100%', textAlign: 'left' }} onClick={() => setShowConfig(!showConfig)}>
            ⚙️ Protection Status
          </button>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="chat-main">
        {showConfig && (
          <div className="security-config-bar">
            <strong>SENTINEL-X Protection:</strong> Input Firewall: ON | Output Firewall: ON | Session Risk: ON
          </div>
        )}

        <div className="chat-messages-scroll">
          {messages.length === 0 && (
            <div className="welcome-screen">
               <h1 className="welcome-title">SENTINEL-X</h1>
               <p className="welcome-subtitle">Secure AI, protected by design.</p>
               <p className="welcome-desc">Ask anything. Every message is screened before it reaches the AI.</p>
               
               <div className="security-status-indicator">
                 ● SENTINEL-X PROTECTION ACTIVE
               </div>

               <div className="suggested-prompts">
                 {[
                   'Explain quantum computing simply',
                   'Help me debug this Python code',
                   'Summarize this paragraph',
                   'Explain recursion with an example'
                 ].map((ex, i) => (
                   <button key={i} className="prompt-chip" onClick={() => send(ex)}>
                     {ex}
                   </button>
                 ))}
               </div>
            </div>
          )}

          {error && (
            <div className="chat-error-banner">
              ⚠️ AI PROVIDER UNAVAILABLE. SENTINEL-X security services are still operational. ({error})
            </div>
          )}

          {messages.map((msg, i) =>
            msg.role === 'user'
              ? <UserBubble key={i} text={msg.text} />
              : <AssistantBubble key={i} msg={msg} />
          )}

          {loading && (
            <div className="chat-message-row assistant-row">
              <div className="bubble-avatar sentinel-avatar">🛡️</div>
              <div className="chat-content">
                 <div className="typing-indicator">
                    <span></span><span></span><span></span>
                 </div>
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Composer */}
        <div className="chat-composer-wrapper">
          <div className="chat-composer">
            <textarea
              className="composer-input"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKey}
              placeholder="Message AI..."
              rows={input.split('\n').length > 1 ? Math.min(input.split('\n').length, 5) : 1}
              disabled={loading}
            />
            <button 
              className="composer-send-btn" 
              onClick={() => send()} 
              disabled={loading || !input.trim()}
            >
              ➤
            </button>
          </div>
          <div className="composer-footer">
            Protected by SENTINEL-X
          </div>
        </div>
      </div>
    </div>
  );
}
