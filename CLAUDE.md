# ThreatLens

Desktop cybersecurity platform: FastAPI + SQLite backend, React (Vite) frontend, wrapped in Electron.

## Structure

- `backend/main.py` — the whole API. All routes (~44) are defined inline here, plus the `lifespan` that starts APScheduler jobs: NVD sync (15 min), OSINT (30 min), CISA KEV (6 h), MITRE (7 d). WebSocket at `/ws/events`.
- `backend/database/` — `db.py` (engine, `get_db`, SQLite pragmas; DB file `threatlens.sqlite`), `models.py` (SQLAlchemy), `schemas.py` (Pydantic), `mitre_attack.json`.
- `backend/services/` — one module per integration: `nvd`, `cisa_kev`, `epss`, `mitre_attack`, `osint`, `abuseipdb`, `virustotal`, `scoring`, `asset_filter`.
- `agent/` — endpoint agent scripts (process/network monitors, sandbox).
- `frontend/src/` — `App.jsx` (routes), `pages/` (Overview, GlobalThreats, ThreatActors, Endpoints, Incidents, Settings, Onboarding, AICopilot, AttackMap, IOCHunter), `components/`, `hooks/useWebSocket.js`, `utils/riskScore.js`.
- Root: `main.js` / `preload.js` (Electron), `package.json` (Electron scripts + electron-builder config), `migrate.py`.
- Config: copy `.env.example` to `.env`.

## Running

Backend (from repo root):

```powershell
$env:PYTHONPATH = "E:\Project\ThreatLens"
.venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload --reload-dir backend
```

Frontend (Vite on 127.0.0.1:5173, strict port):

```powershell
cd frontend; npm run dev
```

Electron (all three together): `npm run dev` at the root. Build: `npm run build` (Vite build, then electron-builder; output in `build/`).

## Rules and notes

- Windows, PowerShell only. No grep/curl; Select-String has no -Recurse.
- Always use .venv\Scripts\python
- Before uvicorn: $env:PYTHONPATH = "E:\Project\ThreatLens"
- Multiline Python goes in a saved file, never python -c
- Non-ASCII characters: edit files via Python, not shell
- All routes are inline in backend/main.py; imports use `from backend.X`; DB via Depends(db.get_db)
- Risk score is a nine-component weighted formula computed only in backend/services/scoring.py (test: backend/tests/test_scoring.py)
  - The API returns risk_score/risk_band; the frontend displays them and never recomputes (frontend/src/utils/riskScore.js only maps score to colour). Uses EPSS percentile, and KEV floors: KEV >= 61 (HIGH), KEV + affected asset >= 86 (CRITICAL). The "no patch" factor is fixed at 0 (no source states that no patch exists)
- No guessed data in scores, graphs or stats: only published fields (NVD CVSS/CWE/CPE/reference tags, EPSS, CISA KEV, MITRE ATT&CK, OTX structured fields, real incident tags). Never infer from description keywords; show an empty state instead
  - Exploited = KEV or NVD "Exploit" reference; ransomware = KEV only; asset match = NVD CPE product vs asset software (backend/services/asset_filter.py)
- Don't kill the backend while a sync job is running, and don't `git stash`: `threatlens.sqlite-shm` is tracked and a stale one causes "disk I/O error" on startup (fix: move the -shm file aside)
- Groq API is restricted; don't use it
- AI Copilot uses GPT-4o via GPT4O_API_KEY
- Remaining work: Settings page, UI polish, Electron packaging (electron-builder)
