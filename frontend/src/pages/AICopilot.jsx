import { useState, useRef, useEffect } from 'react';
import { Send, Sparkles, Shield, Search, Loader } from 'lucide-react';

const SUGGESTED_QUESTIONS = [
  "Is CVE-2026-0300 being exploited in the wild?",
  "Which of my tracked CVEs have the highest exploitation probability?",
  "Are there any active incidents I should prioritize right now?",
  "What threat actors are associated with ransomware in my CVE data?",
  "Summarise the risk posture of my environment today",
];

const MessageBubble = ({ msg }) => {
  const isUser = msg.role === 'user';
  return (
    <div style={{
      display: 'flex',
      justifyContent: isUser ? 'flex-end' : 'flex-start',
      marginBottom: '1.25rem',
      gap: '0.75rem',
      alignItems: 'flex-start',
    }}>
      {!isUser && (
        <div style={{
          width: '32px', height: '32px', borderRadius: '50%',
          background: 'linear-gradient(135deg, var(--accent-gold), #b8921a)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0, marginTop: '2px',
          boxShadow: '0 0 12px rgba(184,146,42,0.3)',
        }}>
          <Sparkles size={16} color="#0a0a0a" />
        </div>
      )}

      <div style={{
        maxWidth: '75%',
        background: isUser
          ? 'linear-gradient(135deg, rgba(184,146,42,0.15), rgba(184,146,42,0.08))'
          : 'rgba(255,255,255,0.04)',
        border: `1px solid ${isUser ? 'rgba(184,146,42,0.3)' : 'rgba(255,255,255,0.07)'}`,
        borderRadius: isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
        padding: '0.875rem 1.125rem',
        fontSize: '0.9rem',
        lineHeight: '1.6',
        color: 'var(--text-primary)',
        whiteSpace: 'pre-wrap',
      }}>
        {msg.content}
        {msg.meta && (
          <div style={{
            marginTop: '0.75rem',
            paddingTop: '0.75rem',
            borderTop: '1px solid rgba(255,255,255,0.06)',
            display: 'flex', gap: '1rem', flexWrap: 'wrap',
          }}>
            {msg.meta.cves_referenced?.length > 0 && (
              <span style={{ fontSize: '0.75rem', color: 'var(--accent-gold)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <Shield size={12} /> {msg.meta.cves_referenced.join(', ')}
              </span>
            )}
            {msg.meta.iocs_checked?.length > 0 && (
              <span style={{ fontSize: '0.75rem', color: '#81e6d9', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <Search size={12} /> IOC checked: {msg.meta.iocs_checked.join(', ')}
              </span>
            )}
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {msg.meta.context_used} context sources
            </span>
          </div>
        )}
      </div>

      {isUser && (
        <div style={{
          width: '32px', height: '32px', borderRadius: '50%',
          background: 'rgba(255,255,255,0.08)',
          border: '1px solid rgba(255,255,255,0.12)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0, marginTop: '2px',
          fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)',
          fontFamily: 'JetBrains Mono, monospace',
        }}>
          YOU
        </div>
      )}
    </div>
  );
};

const AICopilot = () => {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: "I'm ThreatLens AI — your on-call security analyst. Ask me about any CVE, IOC, incident, or threat actor in your environment. I have live access to your platform data.\n\nTry asking: \"Is CVE-2026-0300 being actively exploited?\" or \"What's my highest priority right now?\"",
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const ask = async (question) => {
    const q = question || input.trim();
    if (!q || loading) return;

    setInput('');
    setError(null);
    setMessages(prev => [...prev, { role: 'user', content: q }]);
    setLoading(true);

    try {
      const res = await fetch('http://127.0.0.1:8000/api/copilot/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || `Server error ${res.status}`);
      }

      const data = await res.json();
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.answer,
        meta: {
          context_used: data.context_used,
          cves_referenced: data.cves_referenced,
          iocs_checked: data.iocs_checked,
        }
      }]);
    } catch (err) {
      setError(err.message);
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `⚠ Error: ${err.message}`,
      }]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      ask();
    }
  };

  return (
    <div className="page-container" style={{
      padding: '24px',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      gap: '1.5rem',
    }}>

      {/* Header */}
      <div>
        <div className="label-small">AI-Powered</div>
        <h1>Analyst <span className="italic-serif">Copilot</span></h1>
      </div>

      {/* Suggested questions — only show if just the welcome message */}
      {messages.length === 1 && (
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          {SUGGESTED_QUESTIONS.map((q, i) => (
            <button
              key={i}
              onClick={() => ask(q)}
              style={{
                background: 'rgba(184,146,42,0.06)',
                border: '1px solid rgba(184,146,42,0.2)',
                borderRadius: '20px',
                padding: '0.4rem 0.9rem',
                fontSize: '0.78rem',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
              onMouseEnter={e => {
                e.target.style.background = 'rgba(184,146,42,0.12)';
                e.target.style.color = 'var(--accent-gold)';
                e.target.style.borderColor = 'rgba(184,146,42,0.4)';
              }}
              onMouseLeave={e => {
                e.target.style.background = 'rgba(184,146,42,0.06)';
                e.target.style.color = 'var(--text-secondary)';
                e.target.style.borderColor = 'rgba(184,146,42,0.2)';
              }}
            >
              {q}
            </button>
          ))}
        </div>
      )}

      {/* Chat window */}
      <div className="glass-panel" style={{
        flex: 1,
        overflow: 'auto',
        padding: '1.5rem',
        minHeight: '400px',
        maxHeight: 'calc(100vh - 340px)',
      }}>
        {messages.map((msg, i) => (
          <MessageBubble key={i} msg={msg} />
        ))}

        {loading && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
            <div style={{
              width: '32px', height: '32px', borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--accent-gold), #b8921a)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0,
              boxShadow: '0 0 12px rgba(184,146,42,0.3)',
            }}>
              <Loader size={16} color="#0a0a0a" style={{ animation: 'spin 1s linear infinite' }} />
            </div>
            <div style={{
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.07)',
              borderRadius: '16px 16px 16px 4px',
              padding: '0.875rem 1.125rem',
              display: 'flex', gap: '4px', alignItems: 'center',
            }}>
              {[0, 1, 2].map(i => (
                <div key={i} style={{
                  width: '6px', height: '6px', borderRadius: '50%',
                  background: 'var(--accent-gold)',
                  animation: `bounce 1.2s ease-in-out ${i * 0.2}s infinite`,
                  opacity: 0.7,
                }} />
              ))}
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="glass-panel" style={{ padding: '0.75rem 1rem', display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
        <textarea
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Ask about any CVE, IOC, threat actor, or incident… (Enter to send)"
          rows={1}
          style={{
            flex: 1,
            background: 'transparent',
            border: 'none',
            outline: 'none',
            resize: 'none',
            color: 'var(--text-primary)',
            fontSize: '0.9rem',
            lineHeight: '1.5',
            fontFamily: 'inherit',
            padding: '0.25rem 0',
            minHeight: '24px',
            maxHeight: '120px',
            overflow: 'auto',
          }}
          onInput={e => {
            e.target.style.height = 'auto';
            e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
          }}
        />
        <button
          onClick={() => ask()}
          disabled={!input.trim() || loading}
          style={{
            width: '40px', height: '40px',
            borderRadius: '50%',
            background: input.trim() && !loading
              ? 'linear-gradient(135deg, var(--accent-gold), #b8921a)'
              : 'rgba(255,255,255,0.06)',
            border: 'none',
            cursor: input.trim() && !loading ? 'pointer' : 'not-allowed',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
            transition: 'all 0.2s',
            boxShadow: input.trim() && !loading ? '0 0 12px rgba(184,146,42,0.3)' : 'none',
          }}
        >
          <Send size={16} color={input.trim() && !loading ? '#0a0a0a' : 'var(--text-muted)'} />
        </button>
      </div>

      <style>{`
        @keyframes bounce {
          0%, 80%, 100% { transform: translateY(0); }
          40% { transform: translateY(-6px); }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default AICopilot;