/**\n * TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0\n * Database
 */

function setupDatabaseSheets() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();

  var sheets = [
    {
      name: 'Data_Santri',
      headers: [
        'ID_Santri','NISN','Nama_Santri','Kelas','Wali_Kelas','Status',
        'Foto_URL','NIK','Tempat_Lahir','Tanggal_Lahir','Jenis_Kelamin',
        'Anak_Ke','Jumlah_Saudara','No_KK','Nama_Ayah','Pekerjaan_Ayah',
        'Nama_Ibu','Pekerjaan_Ibu','No_HP_Ortu','Alamat_Ortu','Alamat_Santri',
        'Status_Asrama','Kamar'
      ]
    },
    {
      name: 'Data_Users',
      headers: ['ID_User','Nama','Email','Password','Role','Status','Akses_Kelas','ID_Santri_Wali']
    },
    {
      name: 'Trx_Prestasi',
      headers: ['ID_Prestasi','Nama_Santri','Tanggal','Jenis_Prestasi','Uraian_Prestasi','Tingkat_Penghargaan','Tingkat_Juara','Tingkat_Lomba','Pembimbing','Link_Bukti','Status_Approval','Created_By']
    },
    {
      name: 'Trx_Pelanggaran',
      headers: ['ID_Pelanggaran','Nama_Santri','Tanggal','Jenis_Pelanggaran','Tingkat_Pelanggaran','Deskripsi','Kronologi','Tindak_Pembinaan','Tindak_Lanjut','Link_Bukti','Status_Approval','Created_By']
    },
    {
      name: 'Trx_Catatan_Wali',
      headers: ['ID_Catatan','Nama_Santri','Kelas','Tanggal','Kategori','Catatan','Created_By']
    },
    {
      name: 'Trx_Perizinan',
      headers: ['ID_Perizinan','Nama_Santri','Kelas','Jenis','Mulai','Selesai','Tujuan','Penanggung_Jawab','Alasan','Status','Created_By','Created_At']
    },
    {
      name: 'Trx_Kesehatan',
      headers: ['ID_Kesehatan','Nama_Santri','Kelas','Tanggal','Keluhan','Pemeriksaan','Diagnosa','Tindakan','Obat','Suhu','Berat_Badan','Status','Tindak_Lanjut','Created_By','Created_At']
    }
  ];

  sheets.forEach(function(def) {
    ensureSheetHeaders(ss, def.name, def.headers);
  });

  var userSheet = ss.getSheetByName('Data_Users');
  if (userSheet && userSheet.getLastRow() === 1) {
    var um=headerMap(userSheet), ur=new Array(userSheet.getLastColumn()).fill(''), uv={
      'ID_User':'USR-001','Nama':'Super Admin','Email':'superadmin','Password':makePasswordHash_('password123'),
      'Role':'superadmin','Status':'Aktif','Akses_Kelas':'All','Password_Salt':'','Failed_Login_Count':0,
      'Locked_Until':'','Last_Login_At':'','Updated_At':new Date(),'Updated_By':'SYSTEM'
    };
    Object.keys(uv).forEach(function(h){if(um[h])ur[um[h]-1]=uv[h];});
    userSheet.appendRow(ur);
  }

  // Headers utama sudah dipastikan lewat ensureSheetHeaders di atas.
  // Tambahkan hanya kolom lanjutan yang belum tercakup di definisi utama.
  var santriSheet = ss.getSheetByName('Data_Santri');
  if (santriSheet) {
    [
      'No_HP_Santri','Email_Santri','NIK_Ayah','Pendidikan_Ayah',
      'NIK_Ibu','Pendidikan_Ibu','Kewarganegaraan','Jenis_Tinggal',
      'Transportasi','No_KIP','No_KKS','No_KPS'
    ].forEach(function(h) { ensureColumn(santriSheet, h); });
  }

  initializeSecurityDatabase_();
  ensureDataIntegrityDatabase_();
  runDataIntegrityMigration_();
  ensureBackupDatabase_();
  ensureNotificationDatabase_();
  ensureWaliPortalDatabase_();
  ensureWebPushDatabase_();
  return {
    success: true,
    message: 'Database TAICIMASTER CLEAN V2 berhasil disiapkan.',
    sheets: sheets.map(function(x) { return x.name; })
  };
}

function ensureExtendedDatabase(){
  var ss=SpreadsheetApp.getActiveSpreadsheet();
  ensureDataIntegrityDatabase_();
  ensureSheetHeaders(ss,'Trx_Perizinan',['ID_Perizinan','Nama_Santri','Kelas','Jenis','Mulai','Selesai','Tujuan','Penanggung_Jawab','Alasan','Status','Status_Kembali','Returned_At','Returned_By','Created_By','Created_At']);
  ensureSheetHeaders(ss,'Trx_Kesehatan',['ID_Kesehatan','Nama_Santri','Kelas','Tanggal','Keluhan','Pemeriksaan','Diagnosa','Tindakan','Obat','Suhu','Berat_Badan','Status','Status_Kesehatan','Recovered_At','Recovered_By','Tindak_Lanjut','Created_By','Created_At']);
  var s=ss.getSheetByName('Data_Santri'); if(s){['Foto_URL','NIK','Tempat_Lahir','Tanggal_Lahir','Jenis_Kelamin','Anak_Ke','Jumlah_Saudara','No_KK','Nama_Ayah','Pekerjaan_Ayah','Nama_Ibu','Pekerjaan_Ibu','No_HP_Ortu','Alamat_Ortu','Alamat_Santri','Status_Asrama','Kamar','No_HP_Santri','Email_Santri','NIK_Ayah','Pendidikan_Ayah','NIK_Ibu','Pendidikan_Ibu','Kewarganegaraan','Jenis_Tinggal','Transportasi','No_KIP','No_KKS','No_KPS'].forEach(function(h){ensureColumn(s,h);});}
}

function ensureSheetHeaders(ss, name, headers) {
  var sheet = ss.getSheetByName(name);
  if (!sheet) sheet = ss.insertSheet(name);

  var lastColumn = sheet.getLastColumn();
  if (!sheet.getLastRow() || !lastColumn) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    formatDatabaseHeaderRange_(sheet, 1, headers.length);
    return;
  }

  var existing = sheet.getRange(1, 1, 1, lastColumn).getValues()[0].map(String);
  var known = {};
  existing.forEach(function (header) { known[header] = true; });
  var missing = headers.filter(function (header) { return !known[header]; });
  if (!missing.length) return;

  sheet.getRange(1, lastColumn + 1, 1, missing.length).setValues([missing]);
  formatDatabaseHeaderRange_(sheet, lastColumn + 1, missing.length);
}

function formatDatabaseHeaderRange_(sheet, startColumn, columnCount) {
  sheet.getRange(1, startColumn, 1, columnCount)
    .setFontWeight('bold')
    .setBackground('#7E22CE')
    .setFontColor('#FFFFFF');
}

function ensureColumn(sheet,header){var last=Math.max(1,sheet.getLastColumn()), hs=sheet.getRange(1,1,1,last).getValues()[0].map(String);if(hs.indexOf(header)<0)sheet.getRange(1,last+1).setValue(header).setFontWeight('bold').setBackground('#7E22CE').setFontColor('#FFFFFF');}

function headerMap(sheet){var hs=sheet.getRange(1,1,1,sheet.getLastColumn()).getValues()[0].map(String),m={};hs.forEach(function(h,i){m[h]=i+1;});return m;}

