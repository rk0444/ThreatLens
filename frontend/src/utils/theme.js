// Theme preference: 'system' (follows the OS), 'dark' or 'light'. Kept per machine in localStorage.
const KEY = 'threatlens_theme';

export const getThemePreference = () => {
  try {
    const value = localStorage.getItem(KEY);
    return value === 'dark' || value === 'light' ? value : 'system';
  } catch {
    return 'system';
  }
};

const systemDark = () => window.matchMedia('(prefers-color-scheme: dark)').matches;

export const applyTheme = (preference) => {
  const root = document.documentElement;
  if (preference === 'dark' || preference === 'light') root.dataset.theme = preference;
  else delete root.dataset.theme; // index.css then follows prefers-color-scheme
  // The desktop window's title-bar buttons are drawn by Windows; tell it which theme the page shows
  const effective = preference === 'dark' || preference === 'light' ? preference : (systemDark() ? 'dark' : 'light');
  window.electronAPI?.setWindowTheme?.(effective);
};

// Windows switching light/dark matters while the preference is "system"
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => applyTheme(getThemePreference()));

export const setThemePreference = (preference) => {
  try {
    if (preference === 'system') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, preference);
  } catch { /* storage blocked: the choice lasts for this session only */ }
  applyTheme(preference);
};
