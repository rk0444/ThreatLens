import { useState, useEffect, useCallback } from 'react';
import { HashRouter as Router, Routes, Route, useLocation, useNavigate } from 'react-router-dom';
import { Sparkles, X } from 'lucide-react';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import { Badge, Button, Modal } from './components/ui';
import { useWebSocket } from './hooks/useWebSocket';

// Pages
import Overview from './pages/Overview';
import GlobalThreats from './pages/GlobalThreats';
import ThreatActors from './pages/ThreatActors';
import Endpoints from './pages/Endpoints';
import Incidents from './pages/Incidents';
import Settings from './pages/Settings';
import Onboarding from './pages/Onboarding';
import AICopilot from './pages/AICopilot';
import AttackMap from './pages/AttackMap';
import IOCHunter from './pages/IOCHunter';

function AppLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);
  const [toast, setToast] = useState(null);
  const [criticalAlert, setCriticalAlert] = useState(null);
  
  const isOnboarding = location.pathname === '/onboarding';

  useEffect(() => {
    const checkFirstLaunch = async () => {
      try {
        const assetsRes = await fetch('http://127.0.0.1:8000/api/assets');
        const assets = await assetsRes.json();
        
        let hasApiKeys = false;
        if (window.electronAPI) {
          const env = await window.electronAPI.readEnv();
          hasApiKeys = Object.keys(env).length > 0;
        }

        if (assets.length === 0 && !hasApiKeys && location.pathname !== '/onboarding') {
          navigate('/onboarding');
        }
      } catch (e) {
        console.error("Failed to check first launch status", e);
      } finally {
        setChecking(false);
      }
    };

    checkFirstLaunch();
  }, [navigate, location.pathname]);

  // Global Keyboard Shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
        // Allow refresh
        return;
      }
      if (e.ctrlKey || e.metaKey) {
        switch (e.key) {
          case '1': e.preventDefault(); navigate('/'); break;
          case '2': e.preventDefault(); navigate('/global'); break;
          case '3': e.preventDefault(); navigate('/actors'); break;
          case '4': e.preventDefault(); navigate('/endpoints'); break;
          case '5': e.preventDefault(); navigate('/incidents'); break;
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [navigate]);

  // Global alerts, on the shared connection every page uses
  useWebSocket(useCallback(msg => {
    if (msg.type === 'MORNING_BRIEF_GENERATED') {
      setToast({ title: 'Morning Brief', message: 'GPT-4o brief is ready.' });
      setTimeout(() => setToast(null), 5000);
    } else if (msg.type === 'NEW_INCIDENT' && msg.data?.severity === 'Critical') {
      setCriticalAlert(msg.data);
      setTimeout(() => setCriticalAlert(null), 5000); // auto-dismiss after 5 s
    }
  }, []));

  if (checking) return null; // or a loading spinner

  return (
    <div className={isOnboarding ? "onboarding-layout" : "app-container"}>
      <a href="#main" className="skip-link" onClick={e => { e.preventDefault(); document.getElementById('main')?.focus(); }}>Skip to content</a>
      {!isOnboarding && <Sidebar />}
      <div className={isOnboarding ? "onboarding-wrapper" : "main-wrapper"}>
        {!isOnboarding && <TopBar />}
        <main id="main" tabIndex={-1} className={isOnboarding ? "onboarding-content" : location.pathname === '/attackmap' ? "content content-full" : "content"}>
          <Routes location={location}>
              <Route path="/" element={<Overview />} />
              <Route path="/global" element={<GlobalThreats />} />
              <Route path="/actors" element={<ThreatActors />} />
              <Route path="/endpoints" element={<Endpoints />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/onboarding" element={<Onboarding />} />
              <Route path="/copilot" element={<AICopilot />} />
              <Route path="/attackmap" element={<AttackMap />} />
              <Route path="/ioc" element={<IOCHunter />} />
          </Routes>
        </main>
      </div>

      {/* Morning Brief toast */}
      {toast && (
        <div className="toast" role="status">
          <Sparkles size={16} aria-hidden="true" />
          <div>
            <div className="toast-title">{toast.title}</div>
            <div className="toast-text">{toast.message}</div>
          </div>
          <Button variant="ghost" size="sm" icon={X} iconOnly onClick={() => setToast(null)}>Dismiss</Button>
        </div>
      )}

      {/* Critical incident alert */}
      <Modal
        open={!!criticalAlert}
        onClose={() => setCriticalAlert(null)}
        className="modal-critical"
        title={<span style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Badge severity="critical" /> New incident</span>}
        footer={<>
          <Button onClick={() => setCriticalAlert(null)}>Dismiss</Button>
          <Button variant="primary" onClick={() => { setCriticalAlert(null); navigate('/incidents'); }}>View incident</Button>
        </>}
      >
        {criticalAlert && (
          <>
            <p>
              <span className="mono">#{criticalAlert.id}</span> {criticalAlert.type} on <span className="mono">{criticalAlert.machine_hostname}</span>
            </p>
            <p style={{ color: 'var(--text-3)', marginTop: 'var(--s2)', fontSize: 'var(--fs-sm)' }}>This alert closes by itself after 5 seconds.</p>
          </>
        )}
      </Modal>
    </div>
  );
}

function App() {
  return (
    <Router>
      <AppLayout />
    </Router>
  );
}

export default App;
