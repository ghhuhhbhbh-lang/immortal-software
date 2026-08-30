/* Shared Immortal endpoints — loader + dashboard both read these. */
(function (w) {
  var host = (typeof location !== 'undefined' && location.hostname) || '';
  var isFile = typeof location !== 'undefined' && location.protocol === 'file:';
  var isVirtual = host === 'immortal.loader';
  var isLocal = host === 'localhost' || host === '127.0.0.1' || host === '' || isVirtual;

  w.IMMORTAL_API = w.IMMORTAL_API ||
    (isFile || isLocal ? 'http://127.0.0.1:3000' : (location.origin || 'https://api.immortal.local'));

  try {
    w.IMMORTAL_PORTAL = w.IMMORTAL_PORTAL || new URL('../portal/index.html', document.baseURI).href;
    w.IMMORTAL_LOADER = w.IMMORTAL_LOADER || new URL('../Emulator Loader GUI/index.html', document.baseURI).href;
  } catch (_) {
    w.IMMORTAL_PORTAL = '../portal/index.html';
    w.IMMORTAL_LOADER = '../Emulator Loader GUI/index.html';
  }

  w.IMMORTAL_ASSETS = w.IMMORTAL_ASSETS || {
    logo: 'assets/logo2.png',
    bg: 'assets/bg.png',
  };
  w.IMMORTAL_SECURE_STORAGE = w.IMMORTAL_SECURE_STORAGE !== false;
  w.IMMORTAL_UI_VERSION = '2.3.1';
})(window);
