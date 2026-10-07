// aichat/static/common.js
// Shared UI utilities used by index.html and admin.html

/**
 * Escapes special HTML characters to prevent XSS.
 * @param {*} str - String or value to escape
 * @returns {string} Escaped HTML string
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Escapes special characters for safe embedding in inline JS attribute strings.
 * Escapes backslashes, quotes, ampersands, angle brackets, and newlines to prevent
 * HTML entity decoding breakouts (e.g. x&#39;);window.pwned=1;//).
 * @param {*} str - String or value to escape
 * @returns {string} Escaped JS string
 */
function escapeJs(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/&/g, '\\u0026')
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
}

/**
 * Formats an ISO datetime string into human-readable relative time in Portuguese.
 * @param {string} isoStr - ISO timestamp string (e.g. '2026-10-07 12:00:00' or ISO 8601)
 * @returns {string} Relative time string (e.g. 'há 5m', 'agora', 'nunca')
 */
function formatRelativeTime(isoStr) {
  if (!isoStr) return 'nunca';
  try {
    const d = new Date(String(isoStr).replace(' ', 'T'));
    const now = new Date();
    const diffSec = Math.floor((now - d) / 1000);
    if (isNaN(diffSec) || diffSec < 0) return 'agora';
    if (diffSec < 60) return `há ${diffSec}s`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `há ${diffMin}m`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `há ${diffHours}h`;
    const diffDays = Math.floor(diffHours / 24);
    return `há ${diffDays}d`;
  } catch (e) {
    return 'nunca';
  }
}

/**
 * Robust clipboard copy supporting both modern navigator.clipboard and legacy fallback for HTTP/LAN.
 * @param {string} text - Text to copy
 * @param {Function} [onSuccess] - Callback on successful copy
 */
function copyTextToClipboard(text, onSuccess) {
  if (!text) return;
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      if (onSuccess) onSuccess();
    }).catch(() => {
      fallbackCopyText(text, onSuccess);
    });
  } else {
    fallbackCopyText(text, onSuccess);
  }
}

/**
 * Fallback clipboard copy using textarea element and document.execCommand('copy').
 * @param {string} text - Text to copy
 * @param {Function} [onSuccess] - Callback on successful copy
 */
function fallbackCopyText(text, onSuccess) {
  try {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    textArea.style.top = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    const successful = document.execCommand('copy');
    document.body.removeChild(textArea);
    if (successful && onSuccess) onSuccess();
  } catch (err) {
    console.warn('Fallback copy failed:', err);
  }
}
