const SHEET_NAME = 'Users';
const ITERATIONS = 5000; // jumlah putaran hashing (key-stretching)

// Kolom dasar (akun) + kolom hasil tes (skor & interpretasi masing-masing kuesioner,
// dipisah kolomnya sesuai permintaan agar skor & interpretasi tidak tercampur)
const BASE_HEADERS = ['Email', 'Nama', 'TanggalLahir', 'JenjangPendidikan', 'PasswordHash', 'Salt', 'DibuatPada'];
const RESULT_HEADERS = ['PHQ-9', 'Interpretasi PHQ-9', 'PSS', 'Intepretasi PSS', 'SVS', 'Interpretasi SVS'];
const ALL_HEADERS = BASE_HEADERS.concat(RESULT_HEADERS);

/* ---------------------- ROUTER ---------------------- */

function doPost(e) {
  try {
    const body = JSON.parse(e.postData.contents);
    const action = body.action;

    if (action === 'register') {
      return respond(registerUser(body));
    } else if (action === 'login') {
      return respond(loginUser(body));
    } else if (action === 'saveResults') {
      return respond(saveResults(body));
    } else if (action === 'getResults') {
      return respond(getResults(body));
    } else {
      return respond({ success: false, message: 'Aksi tidak dikenali.' });
    }
  } catch (err) {
    return respond({ success: false, message: 'Terjadi kesalahan server: ' + err.message });
  }
}

function doGet(e) {
  return respond({ status: 'MindPeek API aktif' });
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

/* ---------------------- HASH + SALT UTIL ---------------------- */

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

/* ---------------------- RESPONSE HELPER ---------------------- */

function respond(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
