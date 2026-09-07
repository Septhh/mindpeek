/**
 * =============================================================================
 *  crypto-util.js — MindPeek
 *  Lapisan enkripsi tambahan DI ATAS HTTPS (defense-in-depth) + enkripsi
 *  localStorage. Dibuat sesuai TODO-Enkripsi-DH.md.
 * =============================================================================
 *
 *  KEPUTUSAN DESAIN (lihat TODO bagian "0. Keputusan Desain"):
 *
 *  1) Skema pertukaran kunci: CLASSIC DIFFIE-HELLMAN (modular exponentiation,
 *     prime RFC 3526 Group 14 / 2048-bit, generator g=2), pakai BigInt native
 *     JavaScript. Dipilih dibanding ECDH via crypto.subtle karena Google Apps
 *     Script (backend, lihat kode.gs) TIDAK punya crypto.subtle sama sekali —
 *     jadi ECDH di server harus ditulis manual dari nol (kurva eliptik),
 *     jauh lebih rawan salah. Classic DH modpow bisa pakai kode BigInt yang
 *     nyaris identik persis di client (browser) maupun server (Apps Script
 *     V8 runtime, yang juga sudah mendukung BigInt native).
 *
 *  2) Cipher simetris: Apps Script TIDAK punya AES built-in dan tidak ada
 *     library AES resmi di Utilities. Daripada port implementasi AES dari
 *     nol (risiko bug/timing tinggi untuk primitif block-cipher), dipakai
 *     KONSTRUKSI STREAM CIPHER BERBASIS HMAC-SHA256:
 *       keystream_block_i = HMAC-SHA256(encKey, iv || counter_i)
 *       ciphertext         = plaintext XOR keystream (mode mirip CTR)
 *       tag                = HMAC-SHA256(macKey, iv || ciphertext)   (encrypt-then-MAC)
 *     Ini memberi confidentiality + integrity setara AEAD, walau bukan
 *     literally "AES-256-GCM", karena hanya butuh SHA-256 & HMAC-SHA256yang
 *     tersedia native di KEDUA sisi:
 *       - Browser : crypto.subtle.digest / crypto.subtle.sign('HMAC', ...)
 *       - Apps Script : Utilities.computeDigest / computeHmacSha256Signature
 *     encKey dan macKey diturunkan independen dari shared secret DH lewat
 *     skema mirip HKDF-Expand (HMAC-SHA256 dengan label berbeda).
 *
 *  3) Kunci enkripsi localStorage BEDA dari kunci sesi jaringan (device-bound
 *     key, persisten di localStorage itu sendiri di bawah nama 'sp_dk').
 *     Catatan penting (lihat juga TODO): ini pada dasarnya OBFUSCATION, bukan
 *     keamanan absolut, karena kunci untuk dekripsi tetap harus bisa diakses
 *     oleh JavaScript di origin yang sama. Berguna mencegah data terbaca
 *     sekilas mentah-mentah di localStorage, tapi TIDAK melindungi dari XSS
 *     penuh di origin yang sama.
 * =============================================================================
 */

(function (global) {
  'use strict';

  // ---------------------------------------------------------------------
  // 0. Parameter DH publik — RFC 3526 MODP Group 14 (2048-bit), g = 2
  // ---------------------------------------------------------------------
  const DH_PRIME_HEX =
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC' +
    '74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F' +
    '14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F4' +
    '06B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8' +
    'A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F3' +
    '56208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C3290' +
    '5E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE' +
    '2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42D' +
    'AD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C' +
    '7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2' +
    'EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A' +
    '615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120' +
    'A93AD2CAFFFFFFFFFFFFFFFF';
  const DH_G = 2n;
  const DH_PRIME = BigInt('0x' + DH_PRIME_HEX);
  const DH_PRIME_BYTE_LEN = 256; // 2048 bit / 8
  const DH_PRIVATE_BITS = 256;   // ukuran eksponen privat (cukup untuk keamanan praktis)

  const SESSION_STORAGE_KEY = 'sp_dh_session';
  const SESSION_TTL_MS = 25 * 60 * 1000; // 25 menit (< 30 menit cache server)
  const DEVICE_KEY_STORAGE_NAME = 'sp_dk';

  // ---------------------------------------------------------------------
  // 1. Helper encoding: hex / bytes / base64 / BigInt / utf8
  // ---------------------------------------------------------------------
  function bytesToHex(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  function hexToBytes(hex) {
    if (hex.length % 2 !== 0) hex = '0' + hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToBigInt(bytes) {
    let hex = bytesToHex(bytes);
    if (hex === '') hex = '00';
    return BigInt('0x' + hex);
  }
  function bigIntToBytes(n, length) {
    let hex = n.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    let bytes = hexToBytes(hex);
    if (length) {
      if (bytes.length > length) {
        bytes = bytes.slice(bytes.length - length);
      } else if (bytes.length < length) {
        const padded = new Uint8Array(length);
        padded.set(bytes, length - bytes.length);
        bytes = padded;
      }
    }
    return bytes;
  }
  function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  function base64ToBytes(b64) {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  function utf8Encode(str) {
    return new TextEncoder().encode(str);
  }
  function utf8Decode(bytes) {
    return new TextDecoder().decode(bytes);
  }
  function concatBytes(...arrs) {
    let len = 0;
    for (const a of arrs) len += a.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) { out.set(a, off); off += a.length; }
    return out;
  }
  function u32be(n) {
    const b = new Uint8Array(4);
    b[0] = (n >>> 24) & 0xff; b[1] = (n >>> 16) & 0xff; b[2] = (n >>> 8) & 0xff; b[3] = n & 0xff;
    return b;
  }
  function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // ---------------------------------------------------------------------
  // 2. Modular exponentiation (identik dengan versi di kode.gs)
  // ---------------------------------------------------------------------
  function modPow(base, exp, mod) {
    base = ((base % mod) + mod) % mod;
    let result = 1n;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  // ---------------------------------------------------------------------
  // 3. Primitif hash/HMAC via Web Crypto (tersedia hanya via HTTPS/localhost)
  // ---------------------------------------------------------------------
  function assertSubtleAvailable() {
    if (!(global.crypto && global.crypto.subtle)) {
      throw new Error(
        'crypto.subtle tidak tersedia di context ini (butuh HTTPS atau localhost). ' +
        'Enkripsi MindPeek tidak bisa jalan di halaman non-secure.'
      );
    }
  }

  async function sha256(bytes) {
    assertSubtleAvailable();
    const digest = await global.crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(digest);
  }

  async function hmacSha256(keyBytes, msgBytes) {
    assertSubtleAvailable();
    const key = await global.crypto.subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await global.crypto.subtle.sign('HMAC', key, msgBytes);
    return new Uint8Array(sig);
  }

  function randomBytes(n) {
    assertSubtleAvailable();
    const out = new Uint8Array(n);
    global.crypto.getRandomValues(out);
    return out;
  }

  // ---------------------------------------------------------------------
  // 4. HKDF-Expand sederhana: turunkan encKey & macKey (masing2 32 byte)
  //    dari shared secret DH.
  // ---------------------------------------------------------------------
  async function deriveKeys(sharedSecretBigInt) {
    const secretBytes = bigIntToBytes(sharedSecretBigInt, DH_PRIME_BYTE_LEN);
    const prk = await sha256(secretBytes); // "extract"
    const encKey = await hmacSha256(prk, concatBytes(utf8Encode('MindPeek-enc'), new Uint8Array([1])));
    const macKey = await hmacSha256(prk, concatBytes(utf8Encode('MindPeek-mac'), new Uint8Array([1])));
    return { encKey, macKey };
  }

  // ---------------------------------------------------------------------
  // 5. Stream cipher berbasis HMAC (mode mirip CTR) + tag HMAC (E-t-M)
  // ---------------------------------------------------------------------
  async function symEncrypt(encKey, macKey, plaintextBytes) {
    const iv = randomBytes(16);
    const blocks = [];
    const nBlocks = Math.ceil(plaintextBytes.length / 32) || 1;
    for (let i = 0; i < nBlocks; i++) {
      blocks.push(await hmacSha256(encKey, concatBytes(iv, u32be(i))));
    }
    const keystream = concatBytes(...blocks).slice(0, plaintextBytes.length);
    const ciphertext = new Uint8Array(plaintextBytes.length);
    for (let i = 0; i < plaintextBytes.length; i++) ciphertext[i] = plaintextBytes[i] ^ keystream[i];
    const tag = await hmacSha256(macKey, concatBytes(iv, ciphertext));
    return {
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(ciphertext),
      tag: bytesToBase64(tag)
    };
  }

  async function symDecrypt(encKey, macKey, payload) {
    const iv = base64ToBytes(payload.iv);
    const ciphertext = base64ToBytes(payload.ciphertext);
    const tag = base64ToBytes(payload.tag);

    const expectedTag = await hmacSha256(macKey, concatBytes(iv, ciphertext));
    if (!constantTimeEqual(tag, expectedTag)) {
      throw new Error('Integritas pesan gagal diverifikasi (tag HMAC tidak cocok).');
    }

    const blocks = [];
    const nBlocks = Math.ceil(ciphertext.length / 32) || 1;
    for (let i = 0; i < nBlocks; i++) {
      blocks.push(await hmacSha256(encKey, concatBytes(iv, u32be(i))));
    }
    const keystream = concatBytes(...blocks).slice(0, ciphertext.length);
    const plaintext = new Uint8Array(ciphertext.length);
    for (let i = 0; i < ciphertext.length; i++) plaintext[i] = ciphertext[i] ^ keystream[i];
    return plaintext;
  }

  // ---------------------------------------------------------------------
  // 6. Sesi DH — state modul + cache di sessionStorage
  // ---------------------------------------------------------------------
  let session = null; // { sessionId, encKey: Uint8Array, macKey: Uint8Array, expiresAt }

  function saveSessionToStorage() {
    try {
      global.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({
        sessionId: session.sessionId,
        encKey: bytesToBase64(session.encKey),
        macKey: bytesToBase64(session.macKey),
        expiresAt: session.expiresAt
      }));
    } catch (e) { /* sessionStorage tidak tersedia — sesi cukup di memori saja */ }
  }

  function loadSessionFromStorage() {
    try {
      const raw = global.sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed.expiresAt || parsed.expiresAt < Date.now()) return null;
      return {
        sessionId: parsed.sessionId,
        encKey: base64ToBytes(parsed.encKey),
        macKey: base64ToBytes(parsed.macKey),
        expiresAt: parsed.expiresAt
      };
    } catch (e) {
      return null;
    }
  }

  function clearSession() {
    session = null;
    try { global.sessionStorage.removeItem(SESSION_STORAGE_KEY); } catch (e) { /* abaikan */ }
  }

  function hasValidSession() {
    return !!(session && session.expiresAt > Date.now());
  }

  /**
   * Jalankan handshake DH baru ke server: generate keypair, kirim public key,
   * terima public key server + sessionId, hitung shared secret, turunkan key.
   */
  async function dhHandshake(apiUrl) {
    const privateKey = bytesToBigInt(randomBytes(DH_PRIVATE_BITS / 8)) % DH_PRIME;
    const publicKey = modPow(DH_G, privateKey, DH_PRIME);

    const res = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      body: JSON.stringify({ action: 'dhInit', publicKey: publicKey.toString(16) })
    });
    const data = await res.json();
    if (!data.success) {
      throw new Error(data.message || 'Handshake DH gagal.');
    }

    const serverPublicKey = BigInt('0x' + data.serverPublicKey);
    const sharedSecret = modPow(serverPublicKey, privateKey, DH_PRIME);
    const { encKey, macKey } = await deriveKeys(sharedSecret);

    session = {
      sessionId: data.sessionId,
      encKey,
      macKey,
      expiresAt: Date.now() + SESSION_TTL_MS
    };
    saveSessionToStorage();
    return session.sessionId;
  }

  /**
   * Pastikan ada sesi DH yang valid (reuse dari sessionStorage kalau ada,
   * kalau tidak lakukan handshake baru). Dipanggil otomatis oleh secureFetch,
   * tapi bisa juga dipanggil manual lebih awal (mis. saat halaman load) untuk
   * mem-prefetch sesi sambil menampilkan UI loading.
   */
  async function ensureSession(apiUrl) {
    if (hasValidSession()) return session.sessionId;
    const cached = loadSessionFromStorage();
    if (cached) {
      session = cached;
      return session.sessionId;
    }
    return dhHandshake(apiUrl);
  }

  // ---------------------------------------------------------------------
  // 7. Payload jaringan: encryptPayload / decryptPayload / secureFetch
  // ---------------------------------------------------------------------
  async function encryptPayload(obj) {
    if (!hasValidSession()) {
      throw new Error('Tidak ada sesi DH aktif. Panggil ensureSession()/dhHandshake() dulu.');
    }
    const plaintext = utf8Encode(JSON.stringify(obj));
    const enc = await symEncrypt(session.encKey, session.macKey, plaintext);
    return { sessionId: session.sessionId, iv: enc.iv, ciphertext: enc.ciphertext, tag: enc.tag };
  }

  async function decryptPayload(respObj) {
    if (!hasValidSession()) {
      throw new Error('Tidak ada sesi DH aktif untuk mendekripsi respons.');
    }
    const plaintext = await symDecrypt(session.encKey, session.macKey, respObj);
    return JSON.parse(utf8Decode(plaintext));
  }

  /**
   * Helper utama dipakai halaman: kirim `action` + `data` terenkripsi ke
   * apiUrl, otomatis handshake kalau belum ada sesi, otomatis re-handshake
   * SEKALI kalau server bilang session_expired, lalu kembalikan objek hasil
   * (sudah didekripsi).
   */
  async function secureFetch(apiUrl, action, data, _retried) {
    await ensureSession(apiUrl);
    const encrypted = await encryptPayload(data || {});

    const res = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      body: JSON.stringify(Object.assign({ action: action }, encrypted))
    });
    const raw = await res.json();

    if (raw && raw.success === false && raw.code === 'session_expired' && !_retried) {
      clearSession();
      return secureFetch(apiUrl, action, data, true);
    }

    if (raw && raw.iv && raw.ciphertext && raw.tag) {
      return decryptPayload(raw);
    }
    // Respons tidak terenkripsi (mis. error umum sebelum sempat dienkripsi server)
    return raw;
  }

  // ---------------------------------------------------------------------
  // 8. Enkripsi localStorage — kunci device-bound (obfuscation, lihat catatan
  //    di atas file ini)
  // ---------------------------------------------------------------------
  function getOrCreateDeviceKeyRaw() {
    try {
      let b64 = global.localStorage.getItem(DEVICE_KEY_STORAGE_NAME);
      if (!b64) {
        b64 = bytesToBase64(randomBytes(32));
        global.localStorage.setItem(DEVICE_KEY_STORAGE_NAME, b64);
      }
      return base64ToBytes(b64);
    } catch (e) {
      throw new Error('localStorage tidak tersedia untuk device key.');
    }
  }

  let storageKeysPromise = null;
  async function getStorageKeys() {
    if (!storageKeysPromise) {
      storageKeysPromise = (async () => {
        const deviceKeyRaw = getOrCreateDeviceKeyRaw();
        // PBKDF2-lite: hash berulang deviceKey dengan label berbeda untuk
        // pisahkan enc key & mac key penyimpanan (independen dari kunci sesi DH).
        const prk = await sha256(deviceKeyRaw);
        const encKey = await hmacSha256(prk, utf8Encode('MindPeek-storage-enc'));
        const macKey = await hmacSha256(prk, utf8Encode('MindPeek-storage-mac'));
        return { encKey, macKey };
      })();
    }
    return storageKeysPromise;
  }

  async function encryptForStorage(obj) {
    const { encKey, macKey } = await getStorageKeys();
    const plaintext = utf8Encode(JSON.stringify(obj));
    const enc = await symEncrypt(encKey, macKey, plaintext);
    // Prefix "mpe1:" menandai format terenkripsi versi 1, memudahkan deteksi
    // data lama (pra-fitur ini) yang masih plain JSON saat migrasi/fallback.
    return 'mpe1:' + JSON.stringify(enc);
  }

  async function decryptFromStorage(str) {
    if (!str) return null;
    if (!str.startsWith('mpe1:')) {
      // Data lama dari sebelum fitur enkripsi ada, atau data korup — jangan
      // crash, anggap tidak valid supaya pemanggil bisa treat sebagai
      // "belum login" / "data tidak ada" (lihat TODO bagian 3-8).
      return null;
    }
    try {
      const enc = JSON.parse(str.slice(5));
      const { encKey, macKey } = await getStorageKeys();
      const plaintext = await symDecrypt(encKey, macKey, enc);
      return JSON.parse(utf8Decode(plaintext));
    } catch (e) {
      return null;
    }
  }

  // ---------------------------------------------------------------------
  // Export
  // ---------------------------------------------------------------------
  global.MPCrypto = {
    dhHandshake,
    ensureSession,
    hasValidSession,
    clearSession,
    encryptPayload,
    decryptPayload,
    secureFetch,
    encryptForStorage,
    decryptFromStorage
  };
})(window);
