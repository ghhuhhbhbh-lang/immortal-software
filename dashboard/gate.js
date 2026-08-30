/* Packed key material — not a plaintext password. */
(function (w) {
  w.IMMORTAL_GATE = {
    salt: 'immortal.portal.v1',
    xor: 90,
    material: [109, 44, 22, 121, 52, 11, 104, 42, 119, 2, 55, 99, 17, 123, 45, 8, 110, 41],
    maxAttempts: 5,
    lockMs: 15 * 60 * 1000,
    sessionMs: 4 * 60 * 60 * 1000,
  };
})(window);
