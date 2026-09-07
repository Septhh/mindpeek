const SHEET_NAME = 'Users';
const ITERATIONS = 5000; // jumlah putaran hashing (key-stretching)

// Kolom dasar (akun) + kolom hasil tes (skor & interpretasi masing-masing kuesioner,
// dipisah kolomnya sesuai permintaan agar skor & interpretasi tidak tercampur)
const BASE_HEADERS = ['Email', 'Nama', 'TanggalLahir', 'JenjangPendidikan', 'PasswordHash', 'Salt', 'DibuatPada'];
const RESULT_HEADERS = ['PHQ-9', 'Interpretasi PHQ-9', 'PSS', 'Intepretasi PSS', 'SVS', 'Interpretasi SVS'];
const ALL_HEADERS = BASE_HEADERS.concat(RESULT_HEADERS);

/* =====================================================================
 * ENKRIPSI DH (lapisan tambahan di atas HTTPS) — lihat TODO-Enkripsi-DH.md
 *
 * Skema: classic Diffie-Hellman (modpow, RFC 3526 Group 14 / 2048-bit,
 * g=2) karena Apps Script tidak punya crypto.subtle (jadi ECDH manual di
 * sini akan jauh lebih rumit/rawan bug). Cipher simetris: stream cipher
 * berbasis HMAC-SHA256 (mode mirip CTR) + tag HMAC-SHA256 terpisah
 * (encrypt-then-MAC) sebagai pengganti AES-GCM, karena Apps Script juga
 * tidak punya AES built-in — hanya butuh SHA-256 & HMAC-SHA256 yang
 * tersedia native lewat Utilities, dan konstruksi yang identik dipakai
 * di crypto-util.js (client) supaya kedua sisi persis sinkron.
 * ===================================================================== */

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
const DH_SESSION_TTL_SECONDS = 1800; // 30 menit — sesuai TODO ("15-30 menit"), dalam batas CacheService

/* ---------------------- ROUTER ---------------------- */

function doPost(e) {
  try {
    const body = JSON.parse(e.postData.contents);
    const action = body.action;

    // Handshake DH: satu-satunya action yang dikirim & dibalas polos (belum
    // ada shared secret untuk enkripsi di titik ini — memang begitu cara
    // kerja key-exchange).
    if (action === 'dhInit') {
      return handleDhInit(body);
    }

    // Semua action lain WAJIB datang dalam bentuk terenkripsi:
    // { action, sessionId, iv, ciphertext, tag }
    const sessionData = loadDhSession(body.sessionId);
    if (!sessionData) {
      return respond({ success: false, code: 'session_expired', message: 'Sesi enkripsi kedaluwarsa atau tidak ditemukan. Mohon lakukan handshake ulang.' });
    }

    let innerData;
    try {
      const decrypted = symDecrypt(sessionData.encKey, sessionData.macKey, { iv: body.iv, ciphertext: body.ciphertext, tag: body.tag });
      innerData = JSON.parse(bytesToUtf8(decrypted));
    } catch (decErr) {
      return respond({ success: false, code: 'session_expired', message: 'Gagal mendekripsi payload (tag tidak valid / sesi rusak). Mohon handshake ulang.' });
    }

    let result;
    if (action === 'register') {
      result = registerUser(innerData);
    } else if (action === 'login') {
      result = loginUser(innerData);
    } else if (action === 'saveResults') {
      result = saveResults(innerData);
    } else if (action === 'getResults') {
      result = getResults(innerData);
    } else {
      result = { success: false, message: 'Aksi tidak dikenali.' };
    }

    return respondEncrypted(result, sessionData);
  } catch (err) {
    return respond({ success: false, message: 'Terjadi kesalahan server: ' + err.message });
  }
}

function doGet(e) {
  return respond({ status: 'MindPeek API aktif' });
}

/* ---------------------- DH HANDSHAKE ---------------------- */

function handleDhInit(body) {
  const clientPublicHex = body.publicKey;
  if (!clientPublicHex) {
    return respond({ success: false, message: 'publicKey wajib diisi.' });
  }

  const clientPublic = hexToBigInt(clientPublicHex);
  const serverPrivate = serverRandomPrivateKey();
  const serverPublic = modPow(DH_G, serverPrivate, DH_PRIME);
  const sharedSecret = modPow(clientPublic, serverPrivate, DH_PRIME);
  const keys = deriveKeys(sharedSecret);

  const sessionId = Utilities.getUuid();
  const cache = CacheService.getScriptCache();
  cache.put('dh_' + sessionId, JSON.stringify({
    encKey: keys.encKey,
    macKey: keys.macKey,
    createdAt: new Date().getTime()
  }), DH_SESSION_TTL_SECONDS);

  return respond({ success: true, sessionId: sessionId, serverPublicKey: bigIntToHex(serverPublic) });
}

function loadDhSession(sessionId) {
  if (!sessionId) return null;
  const cache = CacheService.getScriptCache();
  const raw = cache.get('dh_' + sessionId);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return { encKey: parsed.encKey, macKey: parsed.macKey };
  } catch (e) {
    return null;
  }
}

function respondEncrypted(obj, sessionData) {
  const plaintext = stringToUnsignedBytes(JSON.stringify(obj));
  const enc = symEncrypt(sessionData.encKey, sessionData.macKey, plaintext);
  return respond({ iv: enc.iv, ciphertext: enc.ciphertext, tag: enc.tag });
}

/* ---------------------- SHEET HELPER ---------------------- */

function getSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) {
    sheet = ss.insertSheet(SHEET_NAME);
    sheet.appendRow(ALL_HEADERS);
    sheet.setFrozenRows(1);
  }
  ensureResultColumns(sheet);
  return sheet;
}

// Kalau sheet dibuat sebelum fitur PHQ-9/PSS/SVS ada, tambahkan kolom yang belum ada
// di ujung kanan tanpa mengubah/menghapus kolom & data yang sudah ada.
function ensureResultColumns(sheet) {
  const lastCol = Math.max(sheet.getLastColumn(), 1);
  const headerRange = sheet.getRange(1, 1, 1, lastCol);
  let headerValues = headerRange.getValues()[0].map(function (h) { return String(h).trim(); });

  if (headerValues.length === 0 || headerValues.every(function (h) { return h === ''; })) {
    sheet.getRange(1, 1, 1, ALL_HEADERS.length).setValues([ALL_HEADERS]);
    sheet.setFrozenRows(1);
    return;
  }

  const missing = RESULT_HEADERS.filter(function (h) { return headerValues.indexOf(h) === -1; });
  if (missing.length > 0) {
    sheet.getRange(1, lastCol + 1, 1, missing.length).setValues([missing]);
  }
}

function getHeaderMap(sheet) {
  const lastCol = sheet.getLastColumn();
  const headerValues = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
  const map = {};
  headerValues.forEach(function (h, i) {
    map[String(h).trim()] = i; // index 0-based, sejajar dengan array row dari getValues()
  });
  return map;
}

function findRowIndexByEmail(sheet, email, emailColIndex) {
  const rows = sheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][emailColIndex]).toLowerCase() === email) {
      return i; // index di array "rows" (0-based, baris 1 sheet = index 0)
    }
  }
  return -1;
}

/* ---------------------- REGISTER ---------------------- */

function registerUser(data) {
  const name = (data.name || '').trim();
  const email = (data.email || '').trim().toLowerCase();
  const dob = (data.dob || '').trim();
  const education = (data.education || '').trim();
  const password = data.password || '';

  if (!name || !email || !dob || !education || !password) {
    return { success: false, message: 'Semua kolom wajib diisi.' };
  }
  if (password.length < 6) {
    return { success: false, message: 'Password minimal 6 karakter.' };
  }

  const sheet = getSheet();
  const rows = sheet.getDataRange().getValues();

  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0]).toLowerCase() === email) {
      return { success: false, message: 'Email sudah terdaftar.' };
    }
  }

  const salt = Utilities.getUuid();
  const hash = hashPassword(password, salt);

  // appendRow hanya mengisi 7 kolom dasar; kolom hasil tes (PHQ-9 dst.) dibiarkan
  // kosong sampai user menyelesaikan tesnya (lihat saveResults()).
  sheet.appendRow([email, name, dob, education, hash, salt, new Date()]);

  return { success: true, message: 'Registrasi berhasil.' };
}

/* ---------------------- LOGIN ---------------------- */

function loginUser(data) {
  const email = (data.email || '').trim().toLowerCase();
  const password = data.password || '';

  if (!email || !password) {
    return { success: false, message: 'Email dan password wajib diisi.' };
  }

  const sheet = getSheet();
  const rows = sheet.getDataRange().getValues();

  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    if (String(row[0]).toLowerCase() === email) {
      const storedHash = row[4];
      const salt = row[5];
      const computedHash = hashPassword(password, salt);

      if (computedHash === storedHash) {
        return {
          success: true,
          message: 'Login berhasil.',
          user: { email: row[0], name: row[1] }
        };
      }
      return { success: false, message: 'Password salah.' };
    }
  }

  return { success: false, message: 'Email tidak ditemukan.' };
}

/* ---------------------- SIMPAN HASIL TES (PHQ-9 + PSS + SVS) ---------------------- */

function saveResults(data) {
  const email = (data.email || '').trim().toLowerCase();
  if (!email) {
    return { success: false, message: 'Email wajib diisi.' };
  }

  const sheet = getSheet();
  const headerMap = getHeaderMap(sheet);
  const emailCol = headerMap['Email'];
  const rowIndex = findRowIndexByEmail(sheet, email, emailCol);

  if (rowIndex === -1) {
    return { success: false, message: 'Email tidak ditemukan.' };
  }

  // Skor & interpretasi masing-masing kuesioner disimpan di kolom TERPISAH,
  // supaya angka skor tidak tercampur dengan teks interpretasinya.
  const updates = {
    'PHQ-9': data.phq9Score,
    'Interpretasi PHQ-9': data.phq9Interpretation,
    'PSS': data.pssScore,
    'Intepretasi PSS': data.pssInterpretation,
    'SVS': data.svsScore,
    'Interpretasi SVS': data.svsInterpretation
  };

  const sheetRow = rowIndex + 1; // konversi index array (0-based) ke nomor baris sheet (1-based)
  Object.keys(updates).forEach(function (headerName) {
    const colIndex = headerMap[headerName];
    if (colIndex !== undefined && updates[headerName] !== undefined && updates[headerName] !== null) {
      sheet.getRange(sheetRow, colIndex + 1).setValue(updates[headerName]);
    }
  });

  return { success: true, message: 'Hasil tes berhasil disimpan.' };
}

/* ---------------------- AMBIL HASIL TES (untuk halaman utama) ---------------------- */

function getResults(data) {
  const email = (data.email || '').trim().toLowerCase();
  if (!email) {
    return { success: false, message: 'Email wajib diisi.' };
  }

  const sheet = getSheet();
  const headerMap = getHeaderMap(sheet);
  const emailCol = headerMap['Email'];
  const rows = sheet.getDataRange().getValues();
  const rowIndex = findRowIndexByEmail(sheet, email, emailCol);

  if (rowIndex === -1) {
    return { success: false, message: 'Email tidak ditemukan.' };
  }

  const row = rows[rowIndex];
  function val(headerName) {
    const idx = headerMap[headerName];
    return idx !== undefined ? row[idx] : '';
  }

  return {
    success: true,
    results: {
      phq9Score: val('PHQ-9'),
      phq9Interpretation: val('Interpretasi PHQ-9'),
      pssScore: val('PSS'),
      pssInterpretation: val('Intepretasi PSS'),
      svsScore: val('SVS'),
      svsInterpretation: val('Interpretasi SVS')
    }
  };
}

/* ---------------------- HASH + SALT UTIL (password akun) ---------------------- */

function hashPassword(password, salt) {
  let bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    password + salt,
    Utilities.Charset.UTF_8
  );
  // Key-stretching sederhana: hash ulang berkali-kali supaya brute-force lebih berat
  for (let i = 0; i < ITERATIONS - 1; i++) {
    bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  }
  return bytesToHex(bytes);
}

function bytesToHex(bytes) {
  return bytes.map(function (b) {
    const v = b < 0 ? b + 256 : b;
    const hex = v.toString(16);
    return hex.length === 1 ? '0' + hex : hex;
  }).join('');
}

/* =====================================================================
 * PRIMITIF DH + ENKRIPSI (byte array di sini SELALU "unsigned" [0..255]
 * kecuali sesaat sebelum/sesudah dilempar ke fungsi bawaan Utilities,
 * yang memakai byte signed [-128..127] — dikonversi via toSigned/toUnsigned)
 * ===================================================================== */

function toUnsigned(b) { return b < 0 ? b + 256 : b; }
function toSigned(b) { return b > 127 ? b - 256 : b; }

function hexToUnsignedBytes(hex) {
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const out = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.substr(i, 2), 16));
  return out;
}

function hexToBigInt(hex) {
  if (!hex) return 0n;
  return BigInt('0x' + hex);
}

function bigIntToHex(n) {
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return hex;
}

function bigIntToUnsignedBytes(n, length) {
  const hex = bigIntToHex(n);
  let bytes = hexToUnsignedBytes(hex);
  if (length) {
    if (bytes.length > length) {
      bytes = bytes.slice(bytes.length - length);
    } else if (bytes.length < length) {
      bytes = new Array(length - bytes.length).fill(0).concat(bytes);
    }
  }
  return bytes;
}

function unsignedBytesToBigInt(bytes) {
  const hex = bytesToHex(bytes); // bytesToHex sudah aman untuk input unsigned juga
  return BigInt('0x' + (hex || '00'));
}

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

function stringToUnsignedBytes(str) {
  const signed = Utilities.newBlob(str).getBytes(); // UTF-8 default
  return signed.map(toUnsigned);
}

function bytesToUtf8(unsignedBytes) {
  const signed = unsignedBytes.map(toSigned);
  return Utilities.newBlob(signed).getDataAsString('UTF-8');
}

function sha256(unsignedBytes) {
  const signed = unsignedBytes.map(toSigned);
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, signed);
  return digest.map(toUnsigned);
}

function hmacSha256(keyUnsignedBytes, msgUnsignedBytes) {
  const keySigned = keyUnsignedBytes.map(toSigned);
  const msgSigned = msgUnsignedBytes.map(toSigned);
  const sig = Utilities.computeHmacSha256Signature(msgSigned, keySigned);
  return sig.map(toUnsigned);
}

function concatUnsigned() {
  let out = [];
  for (let i = 0; i < arguments.length; i++) out = out.concat(arguments[i]);
  return out;
}

function u32be(n) {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
  return diff === 0;
}

function unsignedBytesToBase64(bytes) {
  return Utilities.base64Encode(bytes.map(toSigned));
}

function base64ToUnsignedBytes(b64) {
  const signed = Utilities.base64Decode(b64);
  return signed.map(toUnsigned);
}

// Apps Script tidak punya CSPRNG asli — entropy dibangun dari beberapa
// Utilities.getUuid() (masing2 122 bit acak) + waktu + Math.random(),
// lalu diwhiten lewat SHA-256. Ini keterbatasan yang diketahui & didoku-
// mentasikan (lihat TODO), bukan CSPRNG kelas kriptografi penuh — cukup
// memadai untuk private key sesi DH berumur pendek (≤30 menit, sekali pakai).
function randomUnsignedBytes(n) {
  let out = [];
  while (out.length < n) {
    const seedStr = Utilities.getUuid() + '|' + Utilities.getUuid() + '|' + new Date().getTime() + '|' + Math.random();
    out = out.concat(sha256(stringToUnsignedBytes(seedStr)));
  }
  return out.slice(0, n);
}

function serverRandomPrivateKey() {
  const bytes = randomUnsignedBytes(32); // 256-bit eksponen privat
  return unsignedBytesToBigInt(bytes) % DH_PRIME;
}

function deriveKeys(sharedSecretBigInt) {
  const secretBytes = bigIntToUnsignedBytes(sharedSecretBigInt, DH_PRIME_BYTE_LEN);
  const prk = sha256(secretBytes); // "extract"
  const encKey = hmacSha256(prk, concatUnsigned(stringToUnsignedBytes('MindPeek-enc'), [1]));
  const macKey = hmacSha256(prk, concatUnsigned(stringToUnsignedBytes('MindPeek-mac'), [1]));
  return { encKey: encKey, macKey: macKey };
}

// Stream cipher berbasis HMAC (mode mirip CTR) + tag HMAC (encrypt-then-MAC).
// Konstruksi ini HARUS identik dengan versi di crypto-util.js (client).
function symEncrypt(encKey, macKey, plaintextBytes) {
  const iv = randomUnsignedBytes(16);
  const nBlocks = Math.max(1, Math.ceil(plaintextBytes.length / 32));
  let keystream = [];
  for (let i = 0; i < nBlocks; i++) {
    keystream = keystream.concat(hmacSha256(encKey, concatUnsigned(iv, u32be(i))));
  }
  keystream = keystream.slice(0, plaintextBytes.length);
  const ciphertext = plaintextBytes.map(function (b, idx) { return b ^ keystream[idx]; });
  const tag = hmacSha256(macKey, concatUnsigned(iv, ciphertext));
  return {
    iv: unsignedBytesToBase64(iv),
    ciphertext: unsignedBytesToBase64(ciphertext),
    tag: unsignedBytesToBase64(tag)
  };
}

function symDecrypt(encKey, macKey, payload) {
  const iv = base64ToUnsignedBytes(payload.iv);
  const ciphertext = base64ToUnsignedBytes(payload.ciphertext);
  const tag = base64ToUnsignedBytes(payload.tag);

  const expectedTag = hmacSha256(macKey, concatUnsigned(iv, ciphertext));
  if (!constantTimeEqual(tag, expectedTag)) {
    throw new Error('Tag HMAC tidak valid.');
  }

  const nBlocks = Math.max(1, Math.ceil(ciphertext.length / 32));
  let keystream = [];
  for (let i = 0; i < nBlocks; i++) {
    keystream = keystream.concat(hmacSha256(encKey, concatUnsigned(iv, u32be(i))));
  }
  keystream = keystream.slice(0, ciphertext.length);
  return ciphertext.map(function (b, idx) { return b ^ keystream[idx]; });
}

/* ---------------------- RESPONSE HELPER (plain / tidak terenkripsi) ---------------------- */

function respond(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
