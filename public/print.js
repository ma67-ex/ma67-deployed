// Loaded by the printable report page (/report/:id). External file because the
// app's CSP (script-src 'self') blocks inline handlers.
document.getElementById('print-btn').addEventListener('click', () => window.print());
