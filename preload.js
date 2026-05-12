/* eslint-env node */
const { contextBridge, ipcRenderer } = require('electron');


contextBridge.exposeInMainWorld('electronAPI', {
    sendNotification: (title, body) => ipcRenderer.send('notify', { title, body }),
    getSystemStatus: () => ipcRenderer.invoke('get-status'),
    // Add more native APIs here
});
