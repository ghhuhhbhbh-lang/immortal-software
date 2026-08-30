/* Immortal Loader GUI — shared with dashboard when same-origin; override via host. */
(function (w) {
  var isFile = typeof location !== 'undefined' && location.protocol === 'file:';
  var isLocal = typeof location !== 'undefined' &&
    (location.hostname === 'localhost' || location.hostname === '127.0.0.1' || location.hostname === '');

  w.IMMORTAL_API = w.IMMORTAL_API ||
    (isFile || isLocal ? 'http://127.0.0.1:3000' : (location.origin || 'http://127.0.0.1:3000'));

  try {
    w.IMMORTAL_PORTAL = w.IMMORTAL_PORTAL || new URL('../dashboard/index.html', document.baseURI).href;
  } catch (_) {
    w.IMMORTAL_PORTAL = '../dashboard/index.html';
  }

  w.IMMORTAL_SECURE_STORAGE = w.IMMORTAL_SECURE_STORAGE !== false;
  w.IMMORTAL_IS_WEBVIEW = !!(w.chrome && w.chrome.webview);
})(window);
