/** Saves text as a file in the browser. The content never leaves the page. */
export function downloadText(filename: string, contents: string, type = "text/csv;charset=utf-8"): void {
  const url = URL.createObjectURL(new Blob([contents], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
