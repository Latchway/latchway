export type Theme = "light" | "dark";

const STORAGE_KEY = "latchway.console.theme";

/** The operator's explicit theme choice, if any. Storage can be unavailable (private mode, blocked site data). */
export function storedTheme(): Theme | undefined {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    return value === "light" || value === "dark" ? value : undefined;
  } catch {
    return undefined;
  }
}

/** The theme on screen: an explicit choice, otherwise the operating system preference. */
export function effectiveTheme(): Theme {
  const explicit = document.documentElement.dataset.theme;
  if (explicit === "light" || explicit === "dark") return explicit;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

/** Applies a stored choice before first render so the console never flashes the other theme. */
export function applyStoredTheme(): void {
  const theme = storedTheme();
  if (theme) document.documentElement.dataset.theme = theme;
}

export function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // The choice still applies for this page view.
  }
}
