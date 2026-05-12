/* eslint-env node */
const { app, BrowserWindow, Tray, Menu, nativeImage, Notification, ipcMain } = require('electron');
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

function createTray() {
  const icon = nativeImage.createEmpty(); 
  tray = new Tray(icon);
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Open ThreatLens', click: () => { if (mainWindow) mainWindow.show(); } },
    { label: 'Check Status', click: () => { 
        new Notification({ title: 'ThreatLens V2.0', body: 'System is running.' }).show();
    } },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.quit(); } }
  ]);
  tray.setToolTip('ThreatLens V2.0');
  tray.setContextMenu(contextMenu);
}

// IPC Handlers
ipcMain.on('notify', (event, { title, body }) => {
  new Notification({ title, body }).show();
});

ipcMain.handle('get-status', async () => {
  return { status: 'System Operational', timestamp: new Date().toISOString() };
});


app.whenReady().then(() => {
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

