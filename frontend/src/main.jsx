import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
// Bundled, not Google Fonts: the desktop app must look the same offline
import '@fontsource/ibm-plex-sans/latin-400.css'
import '@fontsource/ibm-plex-sans/latin-500.css'
import '@fontsource/ibm-plex-sans/latin-600.css'
import '@fontsource/ibm-plex-mono/latin-400.css'
import '@fontsource/ibm-plex-mono/latin-500.css'
import './index.css'
import { applyTheme, getThemePreference } from './utils/theme'
import App from './App.jsx'

applyTheme(getThemePreference())

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
