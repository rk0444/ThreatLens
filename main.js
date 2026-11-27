/* eslint-env node */
const { app, BrowserWindow, Tray, Menu, nativeImage, Notification, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const isDev = !app.isPackaged;

let mainWindow;
let tray;
let backendProcess = null;  // only in the installed app; `npm run dev` starts the backend itself
let monitorProcesses = [];  // agent/network_monitor.py and agent/process_monitor.py
let quitting = false;

const API = 'http://127.0.0.1:8000';
// The installed app's folder is read-only, so its data (.env, database, Python packages, logs) lives in user data
const dataDir = () => app.getPath('userData');
const envPath = () => (isDev ? path.join(__dirname, '.env') : path.join(dataDir(), '.env'));

function readEnvFile() {
  const env = {};
  if (fs.existsSync(envPath())) {
    fs.readFileSync(envPath(), 'utf8').split(/\r?\n/).forEach(line => {
      const match = line.match(/^([^=#]+)=(.*)$/);
      if (match) env[match[1].trim()] = match[2].trim();
    });
  }
  return env;
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const appUrl = () => (isDev ? 'http://127.0.0.1:5173' : `file://${path.join(__dirname, 'frontend/dist/index.html')}`);
const LOADING_PAGE = 'data:text/html;charset=utf-8,' + encodeURIComponent(`<!doctype html>
<html><body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
background:#0D1B2A;color:#cbd5e1;font-family:Segoe UI,sans-serif">
<div style="text-align:center"><div style="font-size:22px;color:#e0b84a;margin-bottom:10px">ThreatLens</div>
<div>Starting ThreatLens services…</div>
<div style="font-size:12px;color:#64748b;margin-top:8px">The first launch installs components and can take a few minutes.</div>
</div></body></html>`);

function logTo(name) {
  const dir = path.join(dataDir(), 'logs');
  fs.mkdirSync(dir, { recursive: true });
  return fs.createWriteStream(path.join(dir, `${name}.log`), { flags: 'a' });
}

function run(cmd, args, log) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { windowsHide: true });
    child.stdout.pipe(log, { end: false });
    child.stderr.pipe(log, { end: false });
    child.on('error', reject);
    child.on('exit', code => (code === 0 ? resolve() : reject(new Error(`${cmd} ${args.join(' ')} exited with ${code}`))));
  });
}

async function waitForBackend(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { if ((await fetch(`${API}/`)).ok) return true; } catch { /* not up yet */ }
    await sleep(1000);
  }
  return false;
}

// Installed app: private Python environment in user data (never the system Python), then backend, then monitor
async function startServices() {
  const resources = process.resourcesPath;
  const venv = path.join(dataDir(), 'python');
  const py = path.join(venv, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  const requirements = path.join(resources, 'backend', 'requirements.txt');
  const stamp = path.join(venv, 'requirements.installed');
  const setupLog = logTo('setup');
  try {
    if (!fs.existsSync(py)) await run('python', ['-m', 'venv', venv], setupLog);
    const wanted = fs.readFileSync(requirements, 'utf8');
    if (!fs.existsSync(stamp) || fs.readFileSync(stamp, 'utf8') !== wanted) {
      await run(py, ['-m', 'pip', 'install', '-r', requirements], setupLog);
      fs.writeFileSync(stamp, wanted);
    }
  } catch (err) {
    dialog.showErrorBox('ThreatLens could not start its services',
      `Python 3 is required to run ThreatLens.\n\n${err.message}\n\nDetails: ${path.join(dataDir(), 'logs', 'setup.log')}`);
    return;
  }

  const env = { ...process.env, ...readEnvFile(), PYTHONPATH: resources, THREATLENS_DATA_DIR: dataDir(), PYTHONUNBUFFERED: '1' };
  const backendLog = logTo('backend');
  backendProcess = spawn(py, ['-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', '8000'],
    { cwd: resources, env, windowsHide: true });
  backendProcess.stdout.pipe(backendLog);
  backendProcess.stderr.pipe(backendLog);
  backendProcess.on('exit', () => { backendProcess = null; });

  if (!(await waitForBackend(10 * 60 * 1000)) || quitting) return;  // first start syncs feeds before answering
  if (mainWindow) mainWindow.loadURL(appUrl());
  for (const [script, logName] of [['network_monitor.py', 'monitor'], ['process_monitor.py', 'process-monitor']]) {
    const log = logTo(logName);
    const child = spawn(py, ['-u', path.join(resources, 'agent', script)], { cwd: resources, env, windowsHide: true });
    child.stdout.pipe(log);
    child.stderr.pipe(log);
    child.on('exit', () => { monitorProcesses = monitorProcesses.filter(p => p !== child); });
    monitorProcesses.push(child);
  }
}

// Quit: stop the monitor, ask the backend to finish running syncs and close the database, then exit.
// A hard kill during a database write is what leaves the SQLite files unusable.
async function stopServices() {
  monitorProcesses.forEach(p => p.kill());
  try {
    await fetch(`${API}/api/system/shutdown`, { method: 'POST', signal: AbortSignal.timeout(150000) });
  } catch { /* backend not running */ }
  for (let i = 0; i < 20 && backendProcess; i++) await sleep(250);
  if (backendProcess) backendProcess.kill();
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 768,
    backgroundColor: '#0D1B2A',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false, // Sometimes helpful for dev
    },
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0D1B2A',
      symbolColor: '#F0F4F8'
    }
  });

  // The installed app shows a holding page until its backend answers (first launch installs Python packages);
  // pages loaded before then would show nothing, since they don't retry
  const firstUrl = isDev ? appUrl() : LOADING_PAGE;
  console.log(`Loading URL: ${firstUrl}`);
  mainWindow.loadURL(firstUrl);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (isDev) {
      mainWindow.webContents.openDevTools();
    }
  });

  // Error handling for failed loads
  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
    console.error('Failed to load:', errorCode, errorDescription);
    if (isDev) {
      setTimeout(() => {
        console.log('Retrying load...');
        mainWindow.loadURL(appUrl());
      }, 1000);
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createTray() {
  const iconPath = path.join(__dirname, 'assets', 'icon.png');
  const icon = fs.existsSync(iconPath) ? nativeImage.createFromPath(iconPath) : nativeImage.createEmpty();
  tray = new Tray(icon);
  
  const contextMenu = Menu.buildFromTemplate([
    { label: 'ThreatLens V2.0', enabled: false },
    { type: 'separator' },
    { label: 'Open Dashboard', click: () => { if (mainWindow) mainWindow.show(); } },
    { label: 'System Status', click: () => { 
        new Notification({ title: 'ThreatLens Status', body: 'All systems operational. Actively monitoring.' }).show();
    } },
    { type: 'separator' },
    { label: 'Quit ThreatLens', click: () => { app.quit(); } }
  ]);
  tray.setToolTip('ThreatLens - Active Monitoring');
  tray.setContextMenu(contextMenu);
}

// IPC Handlers
ipcMain.on('notify', (event, { title, body }) => {
  new Notification({ title, body }).show();
});

ipcMain.handle('get-status', async () => {
  return { status: 'System Operational', timestamp: new Date().toISOString() };
});

ipcMain.handle('read-env', async () => readEnvFile());

ipcMain.handle('write-env', async (event, envData) => {
  const updatedEnv = { ...readEnvFile(), ...envData };
  const envString = Object.entries(updatedEnv)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  fs.writeFileSync(envPath(), envString, 'utf8');
  return true;
});

ipcMain.handle('get-app-info', async () => {
  return {
    version: app.getVersion(),
    buildDate: new Date().toISOString().split('T')[0], // Approximation for now
  };
});

ipcMain.handle('toggle-auto-launch', async (event, enable) => {
  app.setLoginItemSettings({
    openAtLogin: enable,
    path: app.getPath('exe')
  });
  return app.getLoginItemSettings().openAtLogin;
});


app.whenReady().then(() => {
  createWindow();
  createTray();
  if (!isDev) startServices();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', (event) => {
  if (quitting) return;
  event.preventDefault();
  quitting = true;
  if (mainWindow) mainWindow.hide();  // feels closed at once; a running sync may need a few seconds to finish
  stopServices().finally(() => app.quit());
});
