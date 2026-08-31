/* Immortal Key Manager — sealed API channel (same authority as Loader) */
(function (w) {
  var sealed = ['h','t','t','p',':','/','/','1','2','7','.','0','.','0','.','1',':','3','0','0','0'].join('');
  try {
    Object.defineProperty(w, 'IMMORTAL_API', {
      value: sealed,
      writable: false,
      configurable: false,
      enumerable: false,
    });
  } catch (_) {
    w.IMMORTAL_API = sealed;
  }
  w.IMMORTAL_PRODUCT_SLUG = 'immortal-private';
  w.IMMORTAL_CLIENT = 'key-manager';
  w.IMMORTAL_KM = '2.5.1';
})(window);
