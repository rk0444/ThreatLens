
import { HashRouter as Router, Routes, Route } from 'react-router-dom';
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

function App() {
  return (
    <Router>
      <div className="app-container">
        <Sidebar />
        <div className="main-wrapper">
          <TopBar />
          <main className="content">
            <Routes>
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

      </div>
    </Router>
  );
}

export default App;

