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

export const applyTheme = (preference) => {
  const root = document.documentElement;
  if (preference === 'dark' || preference === 'light') root.dataset.theme = preference;
  else delete root.dataset.theme; // index.css then follows prefers-color-scheme
};

export const setThemePreference = (preference) => {
  try {
    if (preference === 'system') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, preference);
  } catch { /* storage blocked: the choice lasts for this session only */ }
  applyTheme(preference);
};
