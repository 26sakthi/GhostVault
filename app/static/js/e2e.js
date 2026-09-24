// Stretch S3: end-to-end encryption helpers (WebCrypto AES-256-GCM).
// The key never leaves the browser except inside the link's #fragment, which is not sent to the server.
window.VaultE2E = (() => {
  const available = () => Boolean(window.isSecureContext && window.crypto && crypto.subtle);

  const toB64 = (bytes) => {
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const fromB64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const toB64Url = (bytes) => toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const fromB64Url = (s) => fromB64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

  // Encrypt plaintext with a fresh key. Returns the payload for the server and the key for the link.
  async function encrypt(plaintext) {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext)));
    const payload = new Uint8Array(iv.length + ct.length);
    payload.set(iv);
    payload.set(ct, iv.length);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    return { payload: toB64(payload), fragment: `k=${toB64Url(raw)}` };
  }

  // Read and import the key from location.hash BEFORE anything is burned. Returns null if absent/invalid.
  async function keyFromHash(hash) {
    const m = /(?:^#|&)k=([A-Za-z0-9_-]{43})(?:&|$)/.exec(hash || "");
    if (!m) return null;
    let raw;
    try { raw = fromB64Url(m[1]); } catch { return null; }
    if (raw.length !== 32) return null;
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
  }

  async function decrypt(key, payloadB64) {
    const data = fromB64(payloadB64);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.subarray(0, 12) }, key, data.subarray(12));
    return new TextDecoder("utf-8", { fatal: true }).decode(pt);
  }

  async function sha256Hex(text) {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  return { available, encrypt, keyFromHash, decrypt, sha256Hex };
})();
