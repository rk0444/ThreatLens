/* eslint-env node */
const { app, BrowserWindow, Tray, Menu, nativeImage, Notification, ipcMain } = require('electron');
const fs = require('fs');
const path = require('path');
const isDev = !app.isPackaged;

let mainWindow;
let tray;

// Note: Backend is now started by concurrently in package.json for better dev experience (reload, etc)
// If you want Electron to manage it in production, we'll need to package the python binary.

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

  const startUrl = isDev 
    ? 'http://127.0.0.1:5173' 
    : `file://${path.join(__dirname, 'frontend/dist/index.html')}`;

  console.log(`Loading URL: ${startUrl}`);
  mainWindow.loadURL(startUrl);

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
        mainWindow.loadURL(startUrl);
      }, 1000);
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function installPythonDependencies() {
  if (app.isPackaged) {
    const { exec } = require('child_process');
    const reqPath = path.join(process.resourcesPath, 'backend', 'requirements.txt');
    if (fs.existsSync(reqPath)) {
      console.log('Installing Python dependencies...');
      exec(`python -m pip install -r "${reqPath}"`, (error, stdout, stderr) => {
        if (error) {
          console.error(`Failed to install dependencies: ${error}`);
          return;
        }
        console.log('Dependencies installed successfully.');
      });
    }
  }
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

ipcMain.handle('read-env', async () => {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    const content = fs.readFileSync(envPath, 'utf8');
    const env = {};
    content.split('\n').forEach(line => {
      const match = line.match(/^([^=]+)=(.*)$/);
      if (match) env[match[1].trim()] = match[2].trim();
    });
    return env;
  }
  return {};
});

ipcMain.handle('write-env', async (event, envData) => {
  const envPath = path.join(__dirname, '.env');
  let currentEnv = {};
  if (fs.existsSync(envPath)) {
    const content = fs.readFileSync(envPath, 'utf8');
    content.split('\n').forEach(line => {
      const match = line.match(/^([^=]+)=(.*)$/);
      if (match) currentEnv[match[1].trim()] = match[2].trim();
    });
  }
  const updatedEnv = { ...currentEnv, ...envData };
  const envString = Object.entries(updatedEnv)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  fs.writeFileSync(envPath, envString, 'utf8');
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
  installPythonDependencies();
  createWindow();
  createTray();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

