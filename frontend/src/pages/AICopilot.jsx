import { useState, useRef, useEffect } from 'react';
import { Send, Loader2, RotateCw } from 'lucide-react';
import { PageHeader, Button, Badge, Input } from '../components/ui';
import CveDrawer from '../components/CveDrawer';

const API = 'http://127.0.0.1:8000';

// Questions the Copilot's context can answer (backend: top 10 CVEs by risk, 5 open incidents, 5 OSINT alerts)
const SUGGESTED_QUESTIONS = [
  'Which of the highest-risk CVEs should I patch first, and why?',
  'Summarise the open incidents and what to check first.',
  'What do the latest OSINT alerts have in common?',
];

const Turn = ({ msg, onOpenCve, onRetry }) => {
  if (msg.role === 'user') {
    return (
      <div className="turn turn-user">
        <div className="turn-label">You</div>
        <div className="turn-text">{msg.content}</div>
      </div>
    );
  }
  if (msg.error) {
    return (
      <div className="turn turn-error" role="alert">
        <div className="turn-label">Copilot</div>
        <div className="turn-text">Could not get an answer: {msg.error}</div>
        <Button size="sm" icon={RotateCw} onClick={onRetry} style={{ marginTop: 'var(--s2)' }}>Ask again</Button>
      </div>
    );
  }
  const { meta } = msg;
  return (
    <div className="turn">
      <div className="turn-label">Copilot · GPT-4o</div>
      <div className="turn-text">{msg.content}</div>
      {meta && (
        <div className="turn-meta">
          {meta.cves_referenced?.length > 0 && (
            <span className="turn-refs">
              <span className="muted small">CVEs</span>
              {meta.cves_referenced.map(id => (
                <button key={id} type="button" className="cve-chip mono" onClick={() => onOpenCve(id)}>{id}</button>
              ))}
            </span>
          )}
          {meta.iocs_checked?.length > 0 && (
            <span className="turn-refs">
              <span className="muted small">IOCs checked</span>
              {meta.iocs_checked.map(ioc => <Badge key={ioc} mono>{ioc}</Badge>)}
            </span>
          )}
          <span className="muted small">{meta.context_used} context source{meta.context_used === 1 ? '' : 's'}</span>
        </div>
      )}
    </div>
  );
};

const AICopilot = () => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [topCve, setTopCve] = useState(null);
  const [selectedCve, setSelectedCve] = useState(null);
  const [openError, setOpenError] = useState(null);
  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  // One suggestion names the real highest-risk CVE, so the example always exists in this database
  useEffect(() => {
    fetch(`${API}/api/overview`).then(r => (r.ok ? r.json() : null))
      .then(d => setTopCve(d?.topThreats?.[0]?.cve_id || null)).catch(() => {});
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: 'end' });
  }, [messages, loading]);

  const ask = async (question) => {
    const q = (question ?? input).trim();
    if (!q || loading) return;

    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: q }]);
    setLoading(true);

    try {
      const res = await fetch(`${API}/api/copilot/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Server error ${res.status}`);
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.answer,
        meta: { context_used: data.context_used, cves_referenced: data.cves_referenced, iocs_checked: data.iocs_checked },
      }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: 'assistant', error: err.message, question: q }]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  };

  const openCve = (cveId) => {
    setOpenError(null);
    fetch(`${API}/api/cves/${encodeURIComponent(cveId)}`)
      .then(res => (res.ok ? res.json() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then(setSelectedCve)
      .catch(e => setOpenError(`Could not open ${cveId} (${e.message}).`));
  };

  const suggestions = topCve ? [`Is ${topCve} being exploited in the wild?`, ...SUGGESTED_QUESTIONS] : SUGGESTED_QUESTIONS;

  return (
    <div className="page-container copilot">
      <PageHeader
        title="AI Copilot"
        description="Ask GPT-4o about your data. It sees the 10 highest-risk CVEs, the 5 newest open incidents and the 5 newest OSINT alerts, plus full details of any CVE ID you mention."
      />

      <section className="card copilot-transcript" aria-label="Conversation" aria-live="polite">
        {messages.length === 0 && (
          <div className="copilot-start">
            <h2 className="card-title">Start with a question</h2>
            <p className="muted">Each question uses one GPT-4o request. Answers can be wrong; check them against the CVE and incident details.</p>
            <div className="copilot-suggestions">
              {suggestions.map(q => <Button key={q} size="sm" onClick={() => ask(q)}>{q}</Button>)}
            </div>
          </div>
        )}
        {messages.map((msg, i) => (
          <Turn key={i} msg={msg} onOpenCve={openCve} onRetry={() => ask(msg.question)} />
        ))}
        {loading && (
          <div className="turn" role="status">
            <div className="turn-label">Copilot · GPT-4o</div>
            <div className="turn-text muted" style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)' }}>
              <Loader2 size={14} className="spin" aria-hidden="true" /> Answering…
            </div>
          </div>
        )}
        {openError && <div role="alert" className="inline-error">{openError}</div>}
        <div ref={bottomRef} />
      </section>

      <form className="copilot-input" onSubmit={e => { e.preventDefault(); ask(); }}>
        <Input
          ref={inputRef}
          multiline rows={2}
          label="Question" hideLabel
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(); } }}
          placeholder="Ask about a CVE, IOC, incident or threat actor"
          hint="Enter to send, Shift+Enter for a new line"
          className="copilot-field"
        />
        <Button type="submit" variant="primary" icon={loading ? Loader2 : Send} className={loading ? 'is-busy' : undefined}
          disabled={!input.trim() || loading}>
          Send
        </Button>
      </form>

      <CveDrawer cve={selectedCve} onClose={() => setSelectedCve(null)} />
    </div>
  );
};

export default AICopilot;
