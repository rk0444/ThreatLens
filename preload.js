/* eslint-env node */
const { contextBridge, ipcRenderer } = require('electron');


contextBridge.exposeInMainWorld('electronAPI', {
    sendNotification: (title, body) => ipcRenderer.send('notify', { title, body }),
    getSystemStatus: () => ipcRenderer.invoke('get-status'),
    readEnv: () => ipcRenderer.invoke('read-env'),
    writeEnv: (envData) => ipcRenderer.invoke('write-env', envData),
    getAppInfo: () => ipcRenderer.invoke('get-app-info'),
    toggleAutoLaunch: (enable) => ipcRenderer.invoke('toggle-auto-launch', enable)
});
