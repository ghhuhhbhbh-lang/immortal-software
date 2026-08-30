/* Immortal Loader GUI — shared with dashboard when same-origin; override via host. */
(function (w) {
  var host = (typeof location !== 'undefined' && location.hostname) || '';
  var isFile = typeof location !== 'undefined' && location.protocol === 'file:';
  var isVirtual = host === 'immortal.loader';
  var isLocal = host === 'localhost' || host === '127.0.0.1' || host === '' || isVirtual;

  w.IMMORTAL_API = w.IMMORTAL_API ||
    (isFile || isLocal ? 'http://127.0.0.1:3000' : (location.origin || 'http://127.0.0.1:3000'));

  try {
    w.IMMORTAL_PORTAL = w.IMMORTAL_PORTAL || new URL('../portal/index.html', document.baseURI).href;
    w.IMMORTAL_ADMIN = w.IMMORTAL_ADMIN || new URL('../dashboard/index.html', document.baseURI).href;
  } catch (_) {
    w.IMMORTAL_PORTAL = '../portal/index.html';
    w.IMMORTAL_ADMIN = '../dashboard/index.html';
  }

  w.IMMORTAL_SECURE_STORAGE = w.IMMORTAL_SECURE_STORAGE !== false;
  w.IMMORTAL_IS_WEBVIEW = !!(w.chrome && w.chrome.webview);
  w.IMMORTAL_LOADER_UI = '2.3.1';
})(window);
