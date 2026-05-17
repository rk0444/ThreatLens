import { useState, useEffect, useRef } from 'react';
import { HashRouter as Router, Routes, Route, useLocation, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { Brain, AlertOctagon, X } from 'lucide-react';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';

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

const PageWrapper = ({ children }) => (
  <motion.div
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
    transition={{ duration: 0.2 }}
    style={{ width: '100%', height: '100%' }}
  >
    {children}
  </motion.div>
);

function AppLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);
  const [toast, setToast] = useState(null);
  const [criticalAlert, setCriticalAlert] = useState(null);
  const wsRef = useRef(null);
  
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

  // Global WebSocket
  useEffect(() => {
    wsRef.current = new WebSocket('ws://127.0.0.1:8000/ws/events');
    wsRef.current.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'MORNING_BRIEF_GENERATED') {
          setToast({ title: 'AI Morning Brief', message: 'Your daily intelligence briefing is ready.' });
          setTimeout(() => setToast(null), 5000);
        } else if (msg.type === 'NEW_INCIDENT' && msg.data.severity === 'Critical') {
          setCriticalAlert(msg.data);
          // Auto dismiss after 5s
          setTimeout(() => setCriticalAlert(null), 5000);
        }
      } catch (e) {}
    };
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, []);

  if (checking) return null; // or a loading spinner

  return (
    <div className={isOnboarding ? "onboarding-layout" : "app-container"}>
      {!isOnboarding && <Sidebar />}
      <div className={isOnboarding ? "onboarding-wrapper" : "main-wrapper"}>
        {!isOnboarding && <TopBar />}
        <main className={isOnboarding ? "onboarding-content" : "content"}>
          <AnimatePresence mode="wait">
            <Routes location={location} key={location.pathname}>
              <Route path="/" element={<PageWrapper><Overview /></PageWrapper>} />
              <Route path="/global" element={<PageWrapper><GlobalThreats /></PageWrapper>} />
              <Route path="/actors" element={<PageWrapper><ThreatActors /></PageWrapper>} />
              <Route path="/endpoints" element={<PageWrapper><Endpoints /></PageWrapper>} />
              <Route path="/incidents" element={<PageWrapper><Incidents /></PageWrapper>} />
              <Route path="/settings" element={<PageWrapper><Settings /></PageWrapper>} />
              <Route path="/onboarding" element={<PageWrapper><Onboarding /></PageWrapper>} />
              <Route path="/copilot" element={<PageWrapper><AICopilot /></PageWrapper>} />
              <Route path="/attackmap" element={<PageWrapper><AttackMap /></PageWrapper>} />
              <Route path="/ioc" element={<PageWrapper><IOCHunter /></PageWrapper>} />
            </Routes>
          </AnimatePresence>
        </main>
      </div>

      {/* Morning Brief Toast */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: 50, x: '100%' }}
            animate={{ opacity: 1, y: 0, x: 0 }}
            exit={{ opacity: 0, y: 50, x: '100%' }}
            style={{
              position: 'fixed', bottom: '2rem', right: '2rem', zIndex: 9999,
              background: 'var(--bg-surface)', border: '1px solid var(--accent-gold)', borderRadius: '8px',
              padding: '1rem', display: 'flex', alignItems: 'center', gap: '1rem', boxShadow: '0 10px 25px rgba(0,0,0,0.5)'
            }}
          >
            <Brain size={24} color="var(--accent-gold)" />
            <div>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>{toast.title}</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{toast.message}</div>
            </div>
            <button onClick={() => setToast(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', marginLeft: '1rem' }}>
              <X size={16} />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Critical Overlay */}
      <AnimatePresence>
        {criticalAlert && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, zIndex: 10000,
              background: 'rgba(229, 62, 62, 0.95)', display: 'flex', alignItems: 'center', justifyContent: 'center',
              backdropFilter: 'blur(10px)'
            }}
          >
            <div style={{ textAlign: 'center', color: '#fff', maxWidth: '600px' }}>
              <AlertOctagon size={120} color="#fff" style={{ margin: '0 auto 2rem' }} />
              <h1 style={{ fontSize: '4rem', marginBottom: '1rem', fontFamily: 'DM Serif Display', fontWeight: 'bold' }}>CRITICAL ALERT</h1>
              <p style={{ fontSize: '1.5rem', marginBottom: '3rem' }}>Incident #{criticalAlert.id}: {criticalAlert.type} on {criticalAlert.machine_hostname}</p>
              <button 
                onClick={() => {
                  setCriticalAlert(null);
                  navigate('/incidents');
                }}
                style={{
                  background: '#fff', color: '#E53E3E', border: 'none', padding: '16px 32px',
                  borderRadius: '8px', fontSize: '1.25rem', fontWeight: 'bold', cursor: 'pointer'
                }}
              >
                View Incident Details
              </button>
              <button
                onClick={() => setCriticalAlert(null)}
                style={{
                  display: 'block', margin: '2rem auto 0', background: 'transparent', border: 'none',
                  color: 'rgba(255,255,255,0.7)', cursor: 'pointer', fontSize: '1rem'
                }}
              >
                Dismiss (Auto-dismissing in 5s)
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
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
