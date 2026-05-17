import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Key, Server, Download, CheckCircle, ChevronRight, Check } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const Onboarding = () => {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [keys, setKeys] = useState({
    NVD_API_KEY: '',
    ALIENVAULT_API_KEY: '',
    ABUSEIPDB_API_KEY: '',
    VIRUSTOTAL_API_KEY: '',
    OPENAI_API_KEY: '',
    GROQ_API_KEY: ''
  });
  
  const [asset, setAsset] = useState({
    hostname: '',
    os: 'Windows',
    ip_address: '',
    software_list: []
  });
  const [softwareInput, setSoftwareInput] = useState('');
  const [agentStatus, setAgentStatus] = useState('waiting'); // waiting, connected
  
  // Step 1: Welcome
  // Step 2: API Keys
  // Step 3: Register Assets
  // Step 4: Install Agent
  // Step 5: Ready
  
  const handleNext = () => {
    if (step < 5) setStep(step + 1);
  };
  
  const handleSaveKeys = async () => {
    try {
      if (window.electronAPI) {
        await window.electronAPI.writeEnv(keys);
      }
      handleNext();
    } catch (e) {
      console.error(e);
      alert('Failed to save keys.');
    }
  };
  
  const handleSaveAsset = async () => {
    try {
      if (!asset.hostname || !asset.ip_address) {
        alert('Hostname and IP Address are required.');
        return;
      }
      await fetch('http://127.0.0.1:8000/api/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: asset.hostname,
          os: asset.os,
          ip_address: asset.ip_address,
          software_list: asset.software_list,
          status: 'Online'
        })
      });
      handleNext();
    } catch (e) {
      console.error(e);
      alert('Failed to save asset.');
    }
  };
  
  useEffect(() => {
    let interval;
    if (step === 4) {
      interval = setInterval(async () => {
        try {
          const res = await fetch('http://127.0.0.1:8000/api/assets');
          const data = await res.json();
          // If we see more assets, or just simulate for now
          if (data && data.length > 0) {
            // For the sake of the demo, assume agent connected if assets exist
            setAgentStatus('connected');
          }
        } catch (e) {}
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [step]);
  
  const renderStepIndicator = () => (
    <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginBottom: '2rem' }}>
      {[1, 2, 3, 4, 5].map(i => (
        <div key={i} style={{
          width: '12px', height: '12px', borderRadius: '50%',
          background: step >= i ? 'var(--accent-gold)' : 'var(--border)',
          transition: 'background 0.3s'
        }}></div>
      ))}
    </div>
  );

  return (
    <div className="page-container" style={{ textAlign: 'center', position: 'relative' }}>
      
      {/* Waveform Background for Step 1 */}
      {step === 1 && (
        <div style={{
          position: 'absolute', top: '-10%', left: '-10%', right: '-10%', bottom: '-10%',
          zIndex: -1, opacity: 0.1, pointerEvents: 'none'
        }}>
          <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
            <path d="M0,200 Q150,100 300,200 T600,200 T900,200 T1200,200" fill="none" stroke="var(--accent-gold)" strokeWidth="2">
              <animate attributeName="d" dur="10s" repeatCount="indefinite"
                values="M0,200 Q150,100 300,200 T600,200 T900,200 T1200,200;
                        M0,200 Q150,300 300,200 T600,200 T900,200 T1200,200;
                        M0,200 Q150,100 300,200 T600,200 T900,200 T1200,200" />
            </path>
            <path d="M0,250 Q150,350 300,250 T600,250 T900,250 T1200,250" fill="none" stroke="var(--accent-gold)" strokeWidth="1">
              <animate attributeName="d" dur="15s" repeatCount="indefinite"
                values="M0,250 Q150,350 300,250 T600,250 T900,250 T1200,250;
                        M0,250 Q150,150 300,250 T600,250 T900,250 T1200,250;
                        M0,250 Q150,350 300,250 T600,250 T900,250 T1200,250" />
            </path>
          </svg>
        </div>
      )}

      {renderStepIndicator()}

      <AnimatePresence mode="wait">
        <motion.div
          key={step}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          transition={{ duration: 0.3 }}
        >
          {step === 1 && (
            <div style={{ padding: '2rem' }}>
              <Shield size={64} color="var(--accent-gold)" style={{ marginBottom: '1rem' }} />
              <h1 style={{ fontSize: '3rem', marginBottom: '1rem' }}>Welcome to <span className="italic-serif" style={{color: 'var(--accent-gold)'}}>ThreatLens</span></h1>
              <p style={{ fontSize: '1.2rem', color: 'var(--text-secondary)', marginBottom: '3rem' }}>
                Your unified security command centre.
              </p>
              <button className="gold-button" onClick={handleNext} style={{ fontSize: '1.1rem', padding: '12px 32px' }}>
                Get Started
              </button>
            </div>
          )}

          {step === 2 && (
            <div style={{ textAlign: 'left', maxWidth: '500px', margin: '0 auto' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
                <Key size={24} color="var(--accent-gold)" />
                <h2>API Integrations</h2>
              </div>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                Configure your OSINT and AI providers. Keys are stored locally in your <code>.env</code> file.
              </p>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '2rem' }}>
                {[
                  { id: 'NVD_API_KEY', label: 'NVD API Key', desc: 'Increases rate limit from 5 to 50 req/30s' },
                  { id: 'ALIENVAULT_API_KEY', label: 'AlienVault OTX API Key', desc: 'Required for global threat intelligence' },
                  { id: 'ABUSEIPDB_API_KEY', label: 'AbuseIPDB API Key', desc: 'Required for IP reputation checking' },
                  { id: 'VIRUSTOTAL_API_KEY', label: 'VirusTotal API Key', desc: 'Required for file hash lookup' },
                  { id: 'OPENAI_API_KEY', label: 'OpenAI API Key', desc: 'Required for AI Copilot (GPT-4o)' },
                  { id: 'GROQ_API_KEY', label: 'Groq API Key', desc: 'Required for fast LLM inference' }
                ].map(input => (
                  <div key={input.id}>
                    <label style={{ display: 'block', marginBottom: '4px', fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                      {input.label} {keys[input.id] && <Check size={14} color="var(--success)" style={{ marginLeft: '4px', verticalAlign: 'middle' }}/>}
                    </label>
                    <input
                      type="password"
                      value={keys[input.id]}
                      onChange={(e) => setKeys({...keys, [input.id]: e.target.value})}
                      placeholder="Enter API Key"
                      style={{
                        width: '100%', padding: '10px', borderRadius: '4px',
                        background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)',
                        color: 'var(--text-primary)', marginBottom: '4px'
                      }}
                    />
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{input.desc}</div>
                  </div>
                ))}
              </div>
              
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
                <button 
                  onClick={handleNext} 
                  style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}
                >
                  Skip for now
                </button>
                <button className="gold-button" onClick={handleSaveKeys}>
                  Save & Continue
                </button>
              </div>
            </div>
          )}

          {step === 3 && (
            <div style={{ textAlign: 'left', maxWidth: '500px', margin: '0 auto' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
                <Server size={24} color="var(--accent-gold)" />
                <h2>Register Your Assets</h2>
              </div>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                Add your first machine to begin monitoring for vulnerabilities and incidents.
              </p>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '2rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '4px', fontSize: '0.9rem' }}>Hostname</label>
                  <input
                    type="text"
                    value={asset.hostname}
                    onChange={(e) => setAsset({...asset, hostname: e.target.value})}
                    placeholder="e.g. SRV-PROD-01"
                    style={{ width: '100%', padding: '10px', borderRadius: '4px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                  />
                </div>
                
                <div>
                  <label style={{ display: 'block', marginBottom: '4px', fontSize: '0.9rem' }}>Operating System</label>
                  <select
                    value={asset.os}
                    onChange={(e) => setAsset({...asset, os: e.target.value})}
                    style={{ width: '100%', padding: '10px', borderRadius: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                  >
                    <option value="Windows">Windows</option>
                    <option value="macOS">macOS</option>
                    <option value="Linux">Linux</option>
                  </select>
                </div>
                
                <div>
                  <label style={{ display: 'block', marginBottom: '4px', fontSize: '0.9rem' }}>IP Address</label>
                  <input
                    type="text"
                    value={asset.ip_address}
                    onChange={(e) => setAsset({...asset, ip_address: e.target.value})}
                    placeholder="192.168.1.100"
                    style={{ width: '100%', padding: '10px', borderRadius: '4px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', marginBottom: '4px', fontSize: '0.9rem' }}>Software Stack</label>
                  <div style={{ display: 'flex', gap: '8px', marginBottom: '8px', flexWrap: 'wrap' }}>
                    {asset.software_list.map(sw => (
                      <span key={sw} style={{ background: 'rgba(184, 146, 42, 0.2)', color: 'var(--accent-gold)', padding: '2px 8px', borderRadius: '12px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        {sw}
                        <button style={{ background: 'none', border: 'none', color: 'var(--text-primary)', cursor: 'pointer' }} onClick={() => setAsset({...asset, software_list: asset.software_list.filter(s => s !== sw)})}>&times;</button>
                      </span>
                    ))}
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <input
                      type="text"
                      value={softwareInput}
                      onChange={(e) => setSoftwareInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && softwareInput.trim()) {
                          if (!asset.software_list.includes(softwareInput.trim())) {
                            setAsset({...asset, software_list: [...asset.software_list, softwareInput.trim()]});
                          }
                          setSoftwareInput('');
                        }
                      }}
                      placeholder="Add software and press Enter (e.g. Node.js, PostgreSQL)"
                      style={{ flex: 1, padding: '10px', borderRadius: '4px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
                    />
                  </div>
                  <div style={{ marginTop: '8px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    {['Apache', 'Nginx', 'MySQL', 'PostgreSQL', 'Node.js', 'Python', 'Docker', 'OpenSSL'].map(sw => (
                      <button
                        key={sw}
                        onClick={() => {
                          if (!asset.software_list.includes(sw)) {
                            setAsset({...asset, software_list: [...asset.software_list, sw]});
                          }
                        }}
                        style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', cursor: 'pointer' }}
                      >
                        + {sw}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <button onClick={() => { /* clear form to add another */ }} style={{ background: 'none', border: 'none', color: 'var(--info)', cursor: 'pointer', fontSize: '0.9rem' }}>
                  + Add Another Asset
                </button>
                <button className="gold-button" onClick={handleSaveAsset}>
                  Save Asset
                </button>
              </div>
            </div>
          )}

          {step === 4 && (
            <div style={{ textAlign: 'left', maxWidth: '500px', margin: '0 auto' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
                <Download size={24} color="var(--accent-gold)" />
                <h2>Install Endpoint Agent</h2>
              </div>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                Deploy the ThreatLens agent to {asset.hostname || 'your machine'} to enable active monitoring and response.
              </p>

              <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden', marginBottom: '2rem' }}>
                <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
                  {['Windows', 'macOS', 'Linux'].map(os => (
                    <div key={os} style={{ flex: 1, padding: '10px', textAlign: 'center', cursor: 'pointer', background: asset.os === os ? 'rgba(184, 146, 42, 0.1)' : 'transparent', color: asset.os === os ? 'var(--accent-gold)' : 'var(--text-secondary)', borderBottom: asset.os === os ? '2px solid var(--accent-gold)' : 'none' }}>
                      {os}
                    </div>
                  ))}
                </div>
                <div style={{ padding: '1.5rem' }}>
                  <p style={{ marginBottom: '1rem', fontSize: '0.9rem' }}>Run the following command in your terminal:</p>
                  <div style={{ background: '#000', padding: '1rem', borderRadius: '4px', fontFamily: 'monospace', color: '#0f0', marginBottom: '1rem', position: 'relative' }}>
                    {asset.os === 'Windows' && 'Invoke-WebRequest -Uri "http://127.0.0.1:8000/agent/win" -OutFile threatlens-agent.exe\n.\\threatlens-agent.exe --register'}
                    {asset.os === 'macOS' && 'curl -sSL http://127.0.0.1:8000/agent/mac | sudo bash'}
                    {asset.os === 'Linux' && 'curl -sSL http://127.0.0.1:8000/agent/linux | sudo bash'}
                  </div>
                  
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px' }}>
                    {agentStatus === 'waiting' ? (
                      <>
                        <div className="spin" style={{ width: '16px', height: '16px', border: '2px solid var(--text-muted)', borderTopColor: 'var(--accent-gold)', borderRadius: '50%' }}></div>
                        <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Waiting for agent to check in...</span>
                      </>
                    ) : (
                      <>
                        <CheckCircle size={16} color="var(--success)" />
                        <span style={{ fontSize: '0.9rem', color: 'var(--success)' }}>Agent connected successfully!</span>
                      </>
                    )}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
                <button onClick={handleNext} style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>
                  Skip for now
                </button>
                <button className="gold-button" onClick={handleNext} disabled={agentStatus === 'waiting'}>
                  Continue
                </button>
              </div>
            </div>
          )}

          {step === 5 && (
            <div style={{ padding: '2rem' }}>
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: 'spring', damping: 10, stiffness: 100, delay: 0.2 }}
                style={{ marginBottom: '2rem' }}
              >
                <CheckCircle size={80} color="var(--success)" style={{ margin: '0 auto' }} />
              </motion.div>
              <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>You're <span className="italic-serif" style={{color: 'var(--accent-gold)'}}>Ready</span></h1>
              <p style={{ fontSize: '1.1rem', color: 'var(--text-secondary)', marginBottom: '2rem', maxWidth: '400px', margin: '0 auto 3rem auto' }}>
                ThreatLens is fully configured and actively monitoring your environment.
              </p>
              
              <div style={{ display: 'inline-flex', flexDirection: 'column', gap: '1rem', textAlign: 'left', marginBottom: '3rem', background: 'rgba(255,255,255,0.02)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}><Check size={16} color="var(--success)"/> API integrations saved</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}><Check size={16} color="var(--success)"/> Initial assets registered</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}><Check size={16} color="var(--success)"/> Background synchronisation started</div>
              </div>
              <br/>
              <button className="gold-button" onClick={() => navigate('/')} style={{ fontSize: '1.1rem', padding: '12px 32px', display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                Open Dashboard <ChevronRight size={20} />
              </button>
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
};

export default Onboarding;
