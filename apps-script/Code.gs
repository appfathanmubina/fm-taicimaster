

/* ===== BEGIN Auth.gs ===== */
/** TAICIMASTER FM — Stage 2 Security FINAL v2.0 — Authentication */
function authenticateUser(emailOrUsername, password, rememberMe) {
  try {
    initializeSecurityDatabase_();
    emailOrUsername=String(emailOrUsername||'').trim(); password=String(password||'');
    if(!emailOrUsername || !password) return {success:false,message:'Email/Username dan password wajib diisi.'};
    var guard=loginGuard_(emailOrUsername);
    if(guard.blocked) return {success:false,code:'LOGIN_LOCKED',message:'Terlalu banyak percobaan login. Silakan coba lagi beberapa menit kemudian.'};
    var sheet=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Users');
    if(!sheet) return {success:false,message:'Sheet Data_Users tidak ditemukan.'};
    var data=sheet.getDataRange().getValues();
    for(var i=1;i<data.length;i++){
      var row=data[i], identity=String(row[2]||'').trim().toLowerCase();
      if(identity===emailOrUsername.toLowerCase()){
        var status=String(row[5]||'');
        if(status!=='Aktif'){recordLoginFailure_(guard);return {success:false,message:'Akun tidak aktif.'};}
        var lockedUntil=row[9];
        if(lockedUntil && new Date(lockedUntil).getTime()>Date.now()){return {success:false,code:'LOGIN_LOCKED',message:'Akun sementara dikunci karena terlalu banyak percobaan login.'};}
        if(!verifyPassword_(password,row[3])){recordLoginFailure_(guard); var next=Number(row[8]||0)+1; sheet.getRange(i+1,9).setValue(next); if(next>=SECURITY.MAX_LOGIN_ATTEMPTS){var until=new Date(Date.now()+SECURITY.LOGIN_WINDOW_SECONDS*1000); sheet.getRange(i+1,10).setValue(until);} return {success:false,message:'Email/Username atau Password salah.'};}
        if(String(row[3]).indexOf('v1$sha256$')!==0) migrateLegacyPassword_(sheet,i+1,password);
        clearLoginGuard_(guard);
        sheet.getRange(i+1,9).setValue(0); sheet.getRange(i+1,10).clearContent(); sheet.getRange(i+1,11).setValue(new Date()); if(headerMap(sheet)['Updated_At'])sheet.getRange(i+1,headerMap(sheet)['Updated_At']).setValue(new Date()); if(headerMap(sheet)['Updated_By'])sheet.getRange(i+1,headerMap(sheet)['Updated_By']).setValue(row[1]);
        var um=headerMap(sheet); var canonicalRole=(typeof normalizeRole_==='function'?normalizeRole_(row[4]):String(row[4]||'').trim().toLowerCase().replace(/[\s-]+/g,'_')); var user={id:row[0],name:row[1],email:row[2],role:canonicalRole,aksesKelas:row[6]||'All',waliSantriIds:um['ID_Santri_Wali']?String(row[um['ID_Santri_Wali']-1]||''):''};
        var token=createSession_(user); auditLog_({id:user.id,name:user.name,role:user.role},'LOGIN','SESSION','Login berhasil');
        var rememberToken = rememberMe ? createRememberToken_(user) : '';
        // Sertakan konfigurasi yang biasanya diminta lewat panggilan kedua setelah login.
        // Jika konfigurasi bermasalah, autentikasi tetap berhasil dan klien dapat memakai fallback lama.
        var systemConfig=null;
        try { systemConfig=getSystemConfig(); } catch(configError) { Logger.log('Konfigurasi login tidak dapat disertakan: '+String(configError)); }
        return {success:true,user:user,sessionToken:token,expiresIn:SECURITY.SESSION_TTL_SECONDS,rememberToken:rememberToken,rememberExpiresIn:rememberMe?SECURITY.REMEMBER_ME_TTL_SECONDS:0,systemConfig:systemConfig};
      }
    }
    recordLoginFailure_(guard); return {success:false,message:'Email/Username atau Password salah.'};
  }catch(err){return {success:false,message:'Terjadi kesalahan sistem: '+err.toString()};}
}

function changeOwnPassword(userId, oldPassword, newPassword, token) {
  try {
    var auth=requireSessionResult_(token); if(!auth.ok)return auth.response;
    var s=auth.session; if(String(userId)!==String(s.id))return {success:false,message:'Akses ditolak.'};
    newPassword=String(newPassword||''); if(newPassword.length<8)return {success:false,message:'Password baru minimal 8 karakter.'};
    if(!/[A-Za-z]/.test(newPassword)||!/[0-9]/.test(newPassword))return {success:false,message:'Password baru harus mengandung huruf dan angka.'};
    var sheet=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Users'),data=sheet.getDataRange().getValues();
    for(var i=1;i<data.length;i++)if(String(data[i][0])===String(userId)){
      if(!verifyPassword_(oldPassword,data[i][3]))return {success:false,message:'Password lama tidak sesuai.'};
      sheet.getRange(i+1,4).setValue(makePasswordHash_(newPassword)); if(typeof revokeRememberTokensForUser_==='function') revokeRememberTokensForUser_(userId); auditLog_(s,'CHANGE_PASSWORD','USER',String(userId));
      return {success:true,message:'Password berhasil diubah. Gunakan password baru untuk login berikutnya.'};
    }
    return {success:false,message:'User tidak ditemukan.'};
  }catch(e){return {success:false,message:'Gagal mengubah password: '+e.toString()};}
}


/* ===== BEGIN BackupRecovery.gs ===== */
/**
 * TAICIMASTER FM — Stage 7 Audit Log, Backup & Recovery FINAL v7.0
 * Backup, recovery, health-check and maintenance service.
 * Builds on Stage 1–6 contracts without changing existing APIs.
 */

var STAGE7_VERSION = '7.0';
var STAGE7_BACKUP_FOLDER_PROPERTY = 'TAICIMASTER_BACKUP_FOLDER_ID';
var STAGE7_BACKUP_FOLDER_NAME = 'TAICIMASTER FM - Backup';
var STAGE7_BACKUP_RETENTION_PROPERTY = 'TAICIMASTER_BACKUP_RETENTION_DAYS';
var STAGE7_BACKUP_DEFAULT_RETENTION_DAYS = 30;
var STAGE7_BACKUP_TRIGGER_HANDLER = 'automaticDailyBackup';

function ensureBackupDatabase_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sh = ss.getSheetByName('Backup_Log');
  if (!sh) {
    sh = ss.insertSheet('Backup_Log');
    sh.appendRow(['ID_Backup','Timestamp','Type','File_ID','File_Name','File_URL','Size_Bytes','Status','Created_By','Detail']);
    sh.getRange(1,1,1,10).setFontWeight('bold').setBackground('#7E22CE').setFontColor('#FFFFFF');
  } else {
    ['ID_Backup','Timestamp','Type','File_ID','File_Name','File_URL','Size_Bytes','Status','Created_By','Detail'].forEach(function(h){ ensureColumn(sh,h); });
  }
  return sh;
}

function getOrCreateBackupFolder_() {
  var props = PropertiesService.getScriptProperties();
  var id = props.getProperty(STAGE7_BACKUP_FOLDER_PROPERTY);
  if (id) {
    try { return DriveApp.getFolderById(id); } catch (e) { props.deleteProperty(STAGE7_BACKUP_FOLDER_PROPERTY); }
  }
  var folders = DriveApp.getFoldersByName(STAGE7_BACKUP_FOLDER_NAME);
  var folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(STAGE7_BACKUP_FOLDER_NAME);
  props.setProperty(STAGE7_BACKUP_FOLDER_PROPERTY, folder.getId());
  return folder;
}

function getBackupSettings(token) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  ensureBackupDatabase_();
  var props = PropertiesService.getScriptProperties();
  var retention = Number(props.getProperty(STAGE7_BACKUP_RETENTION_PROPERTY) || STAGE7_BACKUP_DEFAULT_RETENTION_DAYS);
  var triggers = ScriptApp.getProjectTriggers().filter(function(t){ return t.getHandlerFunction() === STAGE7_BACKUP_TRIGGER_HANDLER; });
  var folder = getOrCreateBackupFolder_();
  return {success:true,version:STAGE7_VERSION,retentionDays:retention,automaticBackupEnabled:triggers.length>0,triggerCount:triggers.length,folder:{id:folder.getId(),name:folder.getName(),url:folder.getUrl()}};
}

function setBackupRetention(token, days) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  var value = Math.max(7, Math.min(365, Number(days || STAGE7_BACKUP_DEFAULT_RETENTION_DAYS)));
  PropertiesService.getScriptProperties().setProperty(STAGE7_BACKUP_RETENTION_PROPERTY, String(value));
  auditLog_(auth.session,'UPDATE_BACKUP_RETENTION','BACKUP',String(value));
  return getBackupSettings(token);
}

function installDailyBackupTrigger(token) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  ensureBackupDatabase_();
  var triggers = ScriptApp.getProjectTriggers();
  triggers.forEach(function(t){ if(t.getHandlerFunction() === STAGE7_BACKUP_TRIGGER_HANDLER) ScriptApp.deleteTrigger(t); });
  ScriptApp.newTrigger(STAGE7_BACKUP_TRIGGER_HANDLER).timeBased().everyDays(1).atHour(2).create();
  auditLog_(auth.session,'ENABLE_DAILY_BACKUP','BACKUP','Daily backup trigger installed');
  return getBackupSettings(token);
}

function disableDailyBackupTrigger(token) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  ScriptApp.getProjectTriggers().forEach(function(t){ if(t.getHandlerFunction() === STAGE7_BACKUP_TRIGGER_HANDLER) ScriptApp.deleteTrigger(t); });
  auditLog_(auth.session,'DISABLE_DAILY_BACKUP','BACKUP','Daily backup trigger removed');
  return getBackupSettings(token);
}

function automaticDailyBackup() {
  try {
    var result = createSpreadsheetBackup_('AUTOMATIC', 'SYSTEM');
    Logger.log(JSON.stringify(result));
    return result;
  } catch (e) {
    Logger.log('Automatic backup failed: ' + e);
    return {success:false,message:String(e)};
  }
}

function createManualBackup(token) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  var result = createSpreadsheetBackup_('MANUAL', auth.session.name || auth.session.id);
  if (result.success) auditLog_(auth.session,'CREATE_MANUAL_BACKUP','BACKUP',result.fileId+'|'+result.fileName);
  return result;
}

function createSpreadsheetBackup_(type, createdBy) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss || !ss.getId()) throw new Error('Spreadsheet aktif tidak ditemukan.');
  ensureBackupDatabase_();
  var folder = getOrCreateBackupFolder_();
  var tz = Session.getScriptTimeZone() || 'Asia/Jakarta';
  var stamp = Utilities.formatDate(new Date(), tz, 'yyyyMMdd_HHmmss');
  var name = 'TAICIMASTER_BACKUP_' + type + '_' + stamp;
  var copied = DriveApp.getFileById(ss.getId()).makeCopy(name, folder);
  var file = DriveApp.getFileById(copied.getId());
  var size = 0;
  try { size = file.getSize(); } catch (ignore) {}
  var log = ensureBackupDatabase_();
  log.appendRow(['BKP-'+stamp+'-'+Utilities.getUuid().substring(0,8),new Date(),type,file.getId(),file.getName(),file.getUrl(),size,'SUCCESS',createdBy,'Spreadsheet snapshot']);
  purgeOldBackups_();
  return {success:true,version:STAGE7_VERSION,fileId:file.getId(),fileName:file.getName(),url:file.getUrl(),folderUrl:folder.getUrl(),sizeBytes:size,type:type};
}

function listBackups(token, limit) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  var folder = getOrCreateBackupFolder_();
  var files = folder.getFiles();
  var rows=[];
  while(files.hasNext()) {
    var f=files.next();
    rows.push({id:f.getId(),name:f.getName(),url:f.getUrl(),sizeBytes:f.getSize(),createdAt:f.getDateCreated()});
  }
  rows.sort(function(a,b){ return b.createdAt.getTime()-a.createdAt.getTime(); });
  var n=Math.max(1,Math.min(100,Number(limit||30)));
  return {success:true,data:rows.slice(0,n).map(function(x){x.createdAt=Utilities.formatDate(x.createdAt,Session.getScriptTimeZone()||'Asia/Jakarta','dd/MM/yyyy HH:mm:ss');return x;})};
}

function deleteBackup(token, fileId) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  var folder = getOrCreateBackupFolder_();
  var file = DriveApp.getFileById(String(fileId||''));
  var parents = file.getParents();
  var belongs=false;
  while(parents.hasNext()){ if(parents.next().getId()===folder.getId()){belongs=true;break;} }
  if(!belongs) return {success:false,message:'File backup tidak berada pada folder backup resmi.'};
  file.setTrashed(true);
  auditLog_(auth.session,'DELETE_BACKUP','BACKUP',String(fileId));
  return {success:true,message:'Backup dipindahkan ke Trash.'};
}

function purgeOldBackups_() {
  try {
    var folder=getOrCreateBackupFolder_();
    var retention=Number(PropertiesService.getScriptProperties().getProperty(STAGE7_BACKUP_RETENTION_PROPERTY)||STAGE7_BACKUP_DEFAULT_RETENTION_DAYS);
    var cutoff=Date.now()-retention*24*60*60*1000;
    var files=folder.getFiles();
    while(files.hasNext()) { var f=files.next(); if(f.getDateCreated().getTime()<cutoff) f.setTrashed(true); }
  } catch(e) { Logger.log('Backup retention cleanup failed: '+e); }
}

function verifyBackup(token, fileId) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  try {
    var folder=getOrCreateBackupFolder_();
    var file=DriveApp.getFileById(String(fileId||''));
    var parents=file.getParents(), belongs=false;
    while(parents.hasNext()){if(parents.next().getId()===folder.getId()){belongs=true;break;}}
    if(!belongs) return {success:false,message:'Backup bukan milik folder backup resmi.'};
    var backup=SpreadsheetApp.openById(file.getId());
    var sheets=backup.getSheets().map(function(s){return {name:s.getName(),rows:s.getLastRow(),columns:s.getLastColumn()};});
    auditLog_(auth.session,'VERIFY_BACKUP','BACKUP',file.getId());
    return {success:true,fileId:file.getId(),fileName:file.getName(),data:{spreadsheetName:backup.getName(),sheets:sheets}};
  } catch(e){return {success:false,message:'Verifikasi backup gagal: '+e.toString()};}
}

function restoreBackup(token, fileId, confirmationCode) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  if (String(confirmationCode||'').trim().toUpperCase() !== 'RESTORE') return {success:false,message:'Kode konfirmasi salah. Ketik RESTORE untuk menjalankan pemulihan.'};
  var lock=LockService.getScriptLock(); lock.waitLock(30000);
  try {
    var folder=getOrCreateBackupFolder_();
    var file=DriveApp.getFileById(String(fileId||''));
    var parents=file.getParents(), belongs=false;
    while(parents.hasNext()){if(parents.next().getId()===folder.getId()){belongs=true;break;}}
    if(!belongs) return {success:false,message:'Backup bukan milik folder backup resmi.'};
    var backup=SpreadsheetApp.openById(file.getId());
    var active=SpreadsheetApp.getActiveSpreadsheet();
    // Safety snapshot immediately before destructive restore.
    createSpreadsheetBackup_('PRE_RESTORE', auth.session.name || auth.session.id);
    var activeSheets=active.getSheets();
    var backupSheets=backup.getSheets();
    var backupNames={}; backupSheets.forEach(function(s){backupNames[s.getName()]=true;});
    // Ensure backup sheets exist and restore their content/formatting.
    backupSheets.forEach(function(src){
      var dst=active.getSheetByName(src.getName());
      if(!dst) dst=active.insertSheet(src.getName());
      restoreSheetContent_(src,dst);
    });
    // Remove sheets that did not exist in the selected backup, but always keep at least one sheet.
    activeSheets.forEach(function(dst){
      if(!backupNames[dst.getName()] && active.getSheets().length>1) active.deleteSheet(dst);
    });
    SpreadsheetApp.flush();
    auditLog_(auth.session,'RESTORE_BACKUP','BACKUP',file.getId()+'|'+file.getName());
    return {success:true,message:'Pemulihan selesai. Backup sebelum pemulihan juga dibuat otomatis.',restoredFrom:file.getName()};
  } catch(e) {
    return {success:false,message:'Pemulihan gagal: '+e.toString()};
  } finally { try{lock.releaseLock();}catch(ignore){} }
}

function restoreSheetContent_(src,dst) {
  var srcRows=Math.max(1,src.getMaxRows()), srcCols=Math.max(1,src.getMaxColumns());
  if(dst.getMaxRows()<srcRows) dst.insertRowsAfter(dst.getMaxRows(),srcRows-dst.getMaxRows());
  if(dst.getMaxColumns()<srcCols) dst.insertColumnsAfter(dst.getMaxColumns(),srcCols-dst.getMaxColumns());
  dst.clear({contentsOnly:false});
  var range=src.getDataRange();
  if(range.getNumRows()>0 && range.getNumColumns()>0){
    var target=dst.getRange(1,1,range.getNumRows(),range.getNumColumns());
    target.setValues(range.getValues());
    target.setNumberFormats(range.getNumberFormats());
    target.setBackgrounds(range.getBackgrounds());
    target.setFontColors(range.getFontColors());
    target.setFontWeights(range.getFontWeights());
    target.setHorizontalAlignments(range.getHorizontalAlignments());
    target.setVerticalAlignments(range.getVerticalAlignments());
  }
  for(var c=1;c<=Math.min(src.getMaxColumns(),dst.getMaxColumns());c++){
    try{dst.setColumnWidth(c,src.getColumnWidth(c));}catch(ignore){}
  }
}

function runSystemHealthCheck(token) {
  var auth = requireSessionResult_(token, ['superadmin','supervisor']);
  if (!auth.ok) return auth.response;
  try {
    var ss=SpreadsheetApp.getActiveSpreadsheet();
    var required=['Data_Santri','Data_Users','Trx_Prestasi','Trx_Pelanggaran','Trx_Catatan_Wali','Trx_Perizinan','Trx_Kesehatan','Audit_Log'];
    var checks=[]; var ok=true;
    required.forEach(function(name){var sh=ss.getSheetByName(name);var pass=!!sh;checks.push({item:'Sheet '+name,status:pass?'OK':'ERROR',detail:pass?(sh.getLastRow()-1)+' data':'Sheet tidak ditemukan'});if(!pass)ok=false;});
    var duplicateSummary=checkDuplicateIds_();
    duplicateSummary.forEach(function(x){checks.push(x);if(x.status!=='OK')ok=false;});
    var backupFolderOk=true; try{getOrCreateBackupFolder_();}catch(e){backupFolderOk=false;}
    checks.push({item:'Backup folder',status:backupFolderOk?'OK':'ERROR',detail:backupFolderOk?'Folder tersedia':'Folder tidak dapat diakses'}); if(!backupFolderOk)ok=false;
    var triggerCount=ScriptApp.getProjectTriggers().filter(function(t){return t.getHandlerFunction()===STAGE7_BACKUP_TRIGGER_HANDLER;}).length;
    checks.push({item:'Daily backup trigger',status:triggerCount?'OK':'WARNING',detail:triggerCount+' trigger aktif'});
    var result={success:true,healthy:ok,data:{checkedAt:new Date(),checks:checks,stage:STAGE7_VERSION}};
    auditLog_(auth.session,'SYSTEM_HEALTH_CHECK','SYSTEM',ok?'HEALTHY':'ISSUES_FOUND');
    return result;
  } catch(e){return {success:false,message:'Health check gagal: '+e.toString()};}
}

function checkDuplicateIds_(){
  var ss=SpreadsheetApp.getActiveSpreadsheet();
  var defs=[['Data_Santri',0,'ID_Santri'],['Data_Users',0,'ID_User'],['Trx_Prestasi',0,'ID_Prestasi'],['Trx_Pelanggaran',0,'ID_Pelanggaran'],['Trx_Catatan_Wali',0,'ID_Catatan'],['Trx_Perizinan',0,'ID_Perizinan'],['Trx_Kesehatan',0,'ID_Kesehatan']];
  return defs.map(function(d){var sh=ss.getSheetByName(d[0]);if(!sh||sh.getLastRow()<=1)return {item:'Duplicate '+d[2],status:'OK',detail:'Tidak ada data untuk diperiksa'};var vals=sh.getRange(2,1,sh.getLastRow()-1,Math.min(sh.getLastColumn(),1)).getValues().map(function(r){return String(r[0]||'').trim();}).filter(Boolean);var seen={},dups=[];vals.forEach(function(v){if(seen[v])dups.push(v);seen[v]=true;});return {item:'Duplicate '+d[2],status:dups.length?'ERROR':'OK',detail:dups.length?(dups.length+' ID duplikat: '+dups.slice(0,5).join(', ')):('Checked '+vals.length+' ID')};});
}

function getStage7Status(token){
  var auth=requireSessionResult_(token,['superadmin']); if(!auth.ok)return auth.response;
  return {success:true,version:STAGE7_VERSION,backup:getBackupSettings(token),health:runSystemHealthCheck(token)};
}


/* ===== BEGIN Biodata.gs ===== */
function ensureBiodataColumns_(){
  var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri');
  if(!sh)return null;
  ['Foto_URL','NISN','NIK','Tempat_Lahir','Tanggal_Lahir','Jenis_Kelamin','Anak_Ke','Jumlah_Saudara','No_KK','Nama_Ayah','NIK_Ayah','Pendidikan_Ayah','Pekerjaan_Ayah','Nama_Ibu','NIK_Ibu','Pendidikan_Ibu','Pekerjaan_Ibu','No_HP_Ortu','No_HP_Santri','Email_Santri','Alamat_Ortu','Alamat_Santri','Kewarganegaraan','Jenis_Tinggal','Transportasi','Status_Asrama','Kamar','No_KIP','No_KKS','No_KPS'].forEach(function(h){ensureColumn(sh,h);});
  return sh;
}

/**
 * TAICIMASTER FM — Biodata Santri
 * Stage 11.11 — Form lengkap, pembatasan kelas Wali Kelas,
 * kelengkapan biodata dan upload foto per santri.
 */

function normalizeRoleServer(role) {
  var raw = String(role || '').trim().toLowerCase().replace(/[ _-]+/g, '');
  var map = {
    'walikelas': 'walikelas',
    'adminprestasi': 'admin_prestasi',
    'adminpelanggaran': 'admin_pelanggaran',
    'adminperizinan': 'admin_perizinan',
    'adminkesehatan': 'admin_kesehatan',
    'superadmin': 'superadmin',
    'supervisor': 'supervisor'
  };
  return map[raw] || String(role || '').trim().toLowerCase();
}

var BIODATA_FIELDS_ = [
  {h:'Nama_Santri', k:'nama', label:'Nama Lengkap', required:true},
  {h:'Kelas', k:'kelas', label:'Kelas', required:true},
  {h:'Wali_Kelas', k:'waliKelas', label:'Wali Kelas', required:true},
  {h:'Status', k:'status', label:'Status Santri', required:true},
  {h:'NISN', k:'nisn', label:'NISN', required:true},
  {h:'NIK', k:'nik', label:'NIK', required:true},
  {h:'Tempat_Lahir', k:'tempatLahir', label:'Tempat Lahir', required:true},
  {h:'Tanggal_Lahir', k:'tanggalLahir', label:'Tanggal Lahir', type:'date', required:true},
  {h:'Jenis_Kelamin', k:'jenisKelamin', label:'Jenis Kelamin', required:true},
  {h:'Anak_Ke', k:'anakKe', label:'Anak Ke-', required:true},
  {h:'Jumlah_Saudara', k:'jumlahSaudara', label:'Jumlah Saudara', required:true},
  {h:'No_KK', k:'noKK', label:'No. KK', required:true},
  {h:'Nama_Ayah', k:'namaAyah', label:'Nama Ayah', required:true},
  {h:'NIK_Ayah', k:'nikAyah', label:'NIK Ayah'},
  {h:'Pendidikan_Ayah', k:'pendidikanAyah', label:'Pendidikan Ayah'},
  {h:'Pekerjaan_Ayah', k:'pekerjaanAyah', label:'Pekerjaan Ayah', required:true},
  {h:'Nama_Ibu', k:'namaIbu', label:'Nama Ibu', required:true},
  {h:'NIK_Ibu', k:'nikIbu', label:'NIK Ibu'},
  {h:'Pendidikan_Ibu', k:'pendidikanIbu', label:'Pendidikan Ibu'},
  {h:'Pekerjaan_Ibu', k:'pekerjaanIbu', label:'Pekerjaan Ibu', required:true},
  {h:'No_HP_Ortu', k:'noHpOrtu', label:'No. HP Orang Tua', required:true},
  {h:'No_HP_Santri', k:'noHpSantri', label:'No. HP Santri'},
  {h:'Email_Santri', k:'emailSantri', label:'Email Santri'},
  {h:'Alamat_Ortu', k:'alamatOrtu', label:'Alamat Orang Tua', required:true},
  {h:'Alamat_Santri', k:'alamatSantri', label:'Alamat Santri', required:true},
  {h:'Kewarganegaraan', k:'kewarganegaraan', label:'Kewarganegaraan'},
  {h:'Jenis_Tinggal', k:'jenisTinggal', label:'Jenis Tinggal'},
  {h:'Transportasi', k:'transportasi', label:'Transportasi'},
  {h:'Status_Asrama', k:'statusAsrama', label:'Status Asrama', required:true},
  {h:'Kamar', k:'kamar', label:'Kamar', required:true},
  {h:'No_KIP', k:'noKip', label:'No. KIP'},
  {h:'No_KKS', k:'noKks', label:'No. KKS'},
  {h:'No_KPS', k:'noKps', label:'No. KPS'},
  {h:'Foto_URL', k:'fotoUrl', label:'Foto Santri', photo:true, required:true}
];

function biodataFieldMap_(){
  var m={}; BIODATA_FIELDS_.forEach(function(f){m[f.h]=f.k;}); return m;
}

function biodataCompleteness_(row, m) {
  var required = BIODATA_FIELDS_.filter(function(f){return f.required;});
  var complete = 0, missing = [];
  required.forEach(function(f){
    var v = m[f.h] ? row[m[f.h]-1] : '';
    if(String(v == null ? '' : v).trim() !== '') complete++;
    else missing.push(f.label);
  });
  var pct = required.length ? Math.round((complete / required.length) * 100) : 0;
  return {percent:pct, complete:complete, total:required.length, missing:missing};
}

function getBiodataSantri(nama, role, aksesKelas, token){
  var a=requireCapability_(token,'biodata.view'); if(!a.ok)return a.response;
  var s=a.session;
  try {
    var sh=ensureBiodataColumns_();
    if(!sh)return {success:false,message:'Sheet Data_Santri tidak ditemukan.'};
    var m=headerMap(sh), d=sh.getDataRange().getValues(), target=String(nama||'').trim().toLowerCase();
    for(var i=1;i<d.length;i++){
      var rowName=String(m['Nama_Santri']?d[i][m['Nama_Santri']-1]:'').trim();
      if(rowName.toLowerCase()!==target)continue;
      var kelas=String(m['Kelas']?d[i][m['Kelas']-1]:'').trim();
      if(s.role==='walikelas' && s.aksesKelas!=='All' && kelas.toLowerCase()!==String(s.aksesKelas||'').trim().toLowerCase())
        return {success:false,message:'Anda hanya dapat mengakses biodata santri pada kelas yang menjadi tanggung jawab Anda.'};
      var data={};
      BIODATA_FIELDS_.forEach(function(f){
        if(m[f.h]){
          var v=d[i][m[f.h]-1];
          if(f.type==='date' && v){
            try{v=Utilities.formatDate(new Date(v),Session.getScriptTimeZone(),'yyyy-MM-dd');}catch(_e){}
          }
          data[f.k]=v || '';
        }
      });
      data.completeness=biodataCompleteness_(d[i],m);
      return {success:true,data:data};
    }
    return {success:false,message:'Santri tidak ditemukan.'};
  }catch(e){return {success:false,message:e.toString()};}
}

function getBiodataCompletenessWaliKelas(token){
  var a=requireCapability_(token,'biodata.view'); if(!a.ok)return a.response;
  if(a.session.role!=='walikelas' && a.session.role!=='superadmin' && a.session.role!=='supervisor')
    return {success:false,message:'Fitur pencapaian kelengkapan biodata tidak tersedia untuk role Anda.'};
  try{
    var sh=ensureBiodataColumns_();
    if(!sh)return {success:true,data:[]};
    var m=headerMap(sh), rows=sh.getDataRange().getValues(), out=[];
    for(var i=1;i<rows.length;i++){
      var kelas=String(m['Kelas']?rows[i][m['Kelas']-1]:'').trim();
      if(a.session.role==='walikelas' && a.session.aksesKelas!=='All' &&
         kelas.toLowerCase()!==String(a.session.aksesKelas||'').trim().toLowerCase()) continue;
      var c=biodataCompleteness_(rows[i],m);
      out.push({
        id:m['ID_Santri']?rows[i][m['ID_Santri']-1]:'',
        nama:m['Nama_Santri']?rows[i][m['Nama_Santri']-1]:'',
        kelas:kelas,
        fotoUrl:m['Foto_URL']?rows[i][m['Foto_URL']-1]:'',
        percent:c.percent, complete:c.complete, total:c.total, missing:c.missing
      });
    }
    out.sort(function(a,b){return a.percent-b.percent || String(a.nama).localeCompare(String(b.nama));});
    return {success:true,data:out};
  }catch(e){return {success:false,message:'Gagal memuat pencapaian biodata: '+e.toString()};}
}

function simpanBiodataSantri(data,fileObj,token){
  var a=requireCapability_(token,'biodata.edit'); if(!a.ok)return a.response;
  var s=a.session, d=data||{};
  try{
    var sh=ensureBiodataColumns_();
    if(!sh)return {success:false,message:'Sheet Data_Santri tidak ditemukan.'};
    var m=headerMap(sh), rows=sh.getDataRange().getValues(), row=-1;
    for(var i=1;i<rows.length;i++){
      if(String(m['Nama_Santri']?rows[i][m['Nama_Santri']-1]:'').trim().toLowerCase()===String(d.nama||'').trim().toLowerCase()){row=i+1;break;}
    }
    if(row<0)return {success:false,message:'Santri tidak ditemukan.'};
    var kelas=String(m['Kelas']?sh.getRange(row,m['Kelas']).getValue():'').trim();
    if(s.role==='walikelas' && s.aksesKelas!=='All' && kelas.toLowerCase()!==String(s.aksesKelas||'').trim().toLowerCase())
      return {success:false,message:'Wali Kelas hanya dapat mengedit biodata santri pada kelasnya sendiri.'};

    // Field identitas/administratif yang tidak boleh diubah Wali Kelas.
    var locked=['nama','kelas','waliKelas','status'];
    var byKey={}; BIODATA_FIELDS_.forEach(function(f){byKey[f.k]=f;});
    Object.keys(d).forEach(function(k){
      if(!byKey[k] || locked.indexOf(k)>=0 || k==='fotoUrl')return;
      if(m[byKey[k].h])sh.getRange(row,m[byKey[k].h]).setValue(d[k] == null ? '' : d[k]);
    });

    // Upload foto disimpan pada Foto_URL milik santri yang sedang diedit.
    if(fileObj && fileObj.data){
      if(!m['Foto_URL'])ensureColumn(sh,'Foto_URL');
      m=headerMap(sh);
      var blob=Utilities.newBlob(Utilities.base64Decode(fileObj.data),fileObj.mimeType||'image/jpeg',fileObj.fileName||('foto-'+d.nama+'.jpg'));
      var folderId=PropertiesService.getScriptProperties().getProperty('BIODATA_FOTO_FOLDER_ID');
      var folder=folderId ? DriveApp.getFolderById(folderId) : DriveApp.getRootFolder();
      var f=folder.createFile(blob);
      f.setName('Foto Santri - '+String(d.nama));
      sh.getRange(row,m['Foto_URL']).setValue(f.getUrl());
    }

    var updated=sh.getRange(row,1,1,sh.getLastColumn()).getValues()[0];
    return {success:true,message:'Biodata santri berhasil diperbarui.',completeness:biodataCompleteness_(updated,headerMap(sh))};
  }catch(e){return {success:false,message:e.toString()};}
}


/* ===== BEGIN Bridge.gs ===== */
/**
 * TAICIMASTER FM PWA Bridge — migration-only patch.
 * Add this file to the existing Apps Script project as Bridge.gs.
 * The dispatcher is fail-closed and maps only explicitly named server functions.
 */
var TAICI_PWA_ALLOWED_ORIGINS_ = ['https://appfathanmubina.github.io'];
var TAICI_PWA_RPC_ = {
  authenticateUser: authenticateUser,
  restoreRememberedSession: restoreRememberedSession,
  revokeRememberToken: revokeRememberToken,
  logoutUser: logoutUser,
  changeOwnPassword: changeOwnPassword,
  getSystemConfig: getSystemConfig,
  getDashboardStats: getDashboardStats,
  getDashboardTodayInfo: getDashboardTodayInfo,
  getDashboardAnalytics: getDashboardAnalytics,
  getSantriList: getSantriList,
  getPrestasiList: getPrestasiList,
  getPelanggaranList: getPelanggaranList,
  getPerizinanList: getPerizinanList,
  getKesehatanList: getKesehatanList,
  getRiwayatCatatanWaliKelas: getRiwayatCatatanWaliKelas,
  getRekapClassList: getRekapClassList,
  getRekapPerAnak: getRekapPerAnak,
  getRekapPerKelas: getRekapPerKelas,
  getBiodataCompletenessWaliKelas: getBiodataCompletenessWaliKelas,
  getWaliKelasClassSummary: getWaliKelasClassSummary,
  getUserList: getUserList,
  getAuditLog: getAuditLog,
  getPendingPrestasiList: getPendingPrestasiList,
  simpanPrestasi: simpanPrestasi,
  updatePrestasi: updatePrestasi,
  deletePrestasi: deletePrestasi,
  updatePrestasiApprovalStatus: updatePrestasiApprovalStatus,
  simpanPelanggaran: simpanPelanggaran,
  updatePelanggaran: updatePelanggaran,
  deletePelanggaran: deletePelanggaran,
  simpanPerizinan: simpanPerizinan,
  updatePerizinan: updatePerizinan,
  deletePerizinan: deletePerizinan,
  bulkMarkPerizinanReturned: bulkMarkPerizinanReturned,
  simpanKesehatan: simpanKesehatan,
  updateKesehatan: updateKesehatan,
  deleteKesehatan: deleteKesehatan,
  bulkMarkKesehatanRecovered: bulkMarkKesehatanRecovered,
  getBiodataSantri: getBiodataSantri,
  simpanBiodataSantri: simpanBiodataSantri,
  simpanCatatanWaliKelas: simpanCatatanWaliKelas,
  updateCatatanWaliKelas: updateCatatanWaliKelas,
  deleteCatatanWaliKelas: deleteCatatanWaliKelas,
  addNewUser: addNewUser,
  getStage7Status: getStage7Status,
  updateFeatureToggle: updateFeatureToggle,
  cleanupExpiredSessions: cleanupExpiredSessions,
  getBackupSettings: getBackupSettings,
  setBackupRetention: setBackupRetention,
  listBackups: listBackups,
  createManualBackup: createManualBackup,
  verifyBackup: verifyBackup,
  restoreBackup: restoreBackup,
  runSystemHealthCheck: runSystemHealthCheck,
  exportRekapCsv: exportRekapCsv,
  generateRekapPdf: generateRekapPdf,
  installDailyBackupTrigger: installDailyBackupTrigger,
  disableDailyBackupTrigger: disableDailyBackupTrigger,
  getStage8Status: getStage8Status,
  getWhatsAppSettings: getWhatsAppSettings,
  saveWhatsAppSettings: saveWhatsAppSettings,
  testWhatsAppConnection: testWhatsAppConnection,
  processWhatsAppQueue: processWhatsAppQueue,
  installWhatsAppQueueTrigger: installWhatsAppQueueTrigger,
  disableWhatsAppQueueTrigger: disableWhatsAppQueueTrigger,
  getNotificationQueue: getNotificationQueue,
  retryWhatsAppNotification: retryWhatsAppNotification,
  getWaliPortalBootstrap: getWaliPortalBootstrap,
  getWaliChildProfile: getWaliChildProfile,
  getWaliChildTimeline: getWaliChildTimeline,
  getWaliPortalNotifications: getWaliPortalNotifications,
  getWebPushIdentity: getWebPushIdentity,
  getUserNotifications: getUserNotifications,
  markUserNotificationRead: markUserNotificationRead,
  getWebPushStatus: getWebPushStatus,
  saveWebPushSettings: saveWebPushSettings,
  retryFailedWebPushNotifications: retryFailedWebPushNotifications
};

function getTaiciPwaBridgeConfig() {
  return { version: '11.28.6-migration.1', allowedOrigins: TAICI_PWA_ALLOWED_ORIGINS_.slice() };
}

function taiciPwaBridgeCall(name, args) {
  name = String(name || '');
  if (!Object.prototype.hasOwnProperty.call(TAICI_PWA_RPC_, name)) {
    throw new Error('API tidak diizinkan pada PWA bridge: ' + name);
  }
  if (!Array.isArray(args)) throw new Error('Format argumen bridge tidak valid.');
  if (args.length > 12) throw new Error('Jumlah argumen melebihi batas.');
  var encoded;
  try { encoded = JSON.stringify(args); } catch (e) { throw new Error('Argumen bridge tidak dapat diserialisasi.'); }
  if (!encoded || encoded.length > 5000000) throw new Error('Payload bridge terlalu besar.');
  // All protected endpoints must continue enforcing their own session/capability checks.
  return TAICI_PWA_RPC_[name].apply(null, args);
}


/* ===== BEGIN Code.gs ===== */
/**
 * TAICIMASTER FM — Stage 4 Core Modules & Role Permission FINAL v4.0
 * Core / Entry Point
 */
const CONFIG = {
  SPREADSHEET_ID: SpreadsheetApp.getActiveSpreadsheet().getId(),
  DRIVE_PRESTASI_FOLDER_ID: '1-9nYDEK1gwRaGUfld3_5-Lpg_F98Bcu3',
  DRIVE_PELANGGARAN_FOLDER_ID: '19sfdP9Gdg7VmtL7GL2BffR5yCAhrN6pw',
  APP_NAME: 'TAICIMASTER FM',
  THEME_COLOR: '#7E22CE',
  REPORT_SERVICE_VERSION: '6.0',
  BACKUP_RECOVERY_VERSION: '7.0',
  NOTIFICATION_VERSION: '8.0',
  WALI_PORTAL_VERSION: '9.0',
  PRODUCTION_VERSION: '11.0'
};

function doGet(e) {
  // PWA bridge endpoint; normal Apps Script UI remains the rollback path.
  if (e && e.parameter && e.parameter.bridge === '1') {
    return taiciPwaBridgeOutput_();
  }
  // Stage 11.26: expose a lightweight same-origin web-app manifest.
  // This does not alter the normal Apps Script HTML entry point.
  if (e && e.parameter && e.parameter.manifest === '1') {
    var manifest = {
      name: CONFIG.APP_NAME,
      short_name: 'TAICIMASTER FM',
      description: 'Sistem Perkembangan Santri - TAICIMASTER FM',
      start_url: './',
      scope: './',
      display: 'standalone',
      orientation: 'portrait-primary',
      background_color: '#F8FAFC',
      theme_color: CONFIG.THEME_COLOR,
      icons: [
        { src: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAssAAAMECAYAAABJwWgOAAAABGdBTUEAALGOfPtRkwAAACBjSFJNAACHDwAAjA8AAP1SAACBQAAAfXkAAOmLAAA85QAAGcxzPIV3AAAKL2lDQ1BJQ0MgUHJvZmlsZQAASMedlndUVNcWh8+9d3qhzTDSGXqTLjCA9C4gHQRRGGYGGMoAwwxNbIioQEQREQFFkKCAAaOhSKyIYiEoqGAPSBBQYjCKqKhkRtZKfHl57+Xl98e939pn73P32XuftS4AJE8fLi8FlgIgmSfgB3o401eFR9Cx/QAGeIABpgAwWempvkHuwUAkLzcXerrICfyL3gwBSPy+ZejpT6eD/0/SrFS+AADIX8TmbE46S8T5Ik7KFKSK7TMipsYkihlGiZkvSlDEcmKOW+Sln30W2VHM7GQeW8TinFPZyWwx94h4e4aQI2LER8QFGVxOpohvi1gzSZjMFfFbcWwyh5kOAIoktgs4rHgRm4iYxA8OdBHxcgBwpLgvOOYLFnCyBOJDuaSkZvO5cfECui5Lj25qbc2ge3IykzgCgaE/k5XI5LPpLinJqUxeNgCLZ/4sGXFt6aIiW5paW1oamhmZflGo/7r4NyXu7SK9CvjcM4jW94ftr/xS6gBgzIpqs+sPW8x+ADq2AiB3/w+b5iEAJEV9a7/xxXlo4nmJFwhSbYyNMzMzjbgclpG4oL/rfzr8DX3xPSPxdr+Xh+7KiWUKkwR0cd1YKUkpQj49PZXJ4tAN/zzE/zjwr/NYGsiJ5fA5PFFEqGjKuLw4Ubt5bK6Am8Kjc3n/qYn/MOxPWpxrkSj1nwA1yghI3aAC5Oc+gKIQARJ5UNz13/vmgw8F4psXpjqxOPefBf37rnCJ+JHOjfsc5xIYTGcJ+RmLa+JrCdCAACQBFcgDFaABdIEhMANWwBY4AjewAviBYBAO1gIWiAfJgA8yQS7YDApAEdgF9oJKUAPqQSNoASdABzgNLoDL4Dq4Ce6AB2AEjIPnYAa8AfMQBGEhMkSB5CFVSAsygMwgBmQPuUE+UCAUDkVDcRAPEkK50BaoCCqFKqFaqBH6FjoFXYCuQgPQPWgUmoJ+hd7DCEyCqbAyrA0bwwzYCfaGg+E1cBycBufA+fBOuAKug4/B7fAF+Dp8Bx6Bn8OzCECICA1RQwwRBuKC+CERSCzCRzYghUg5Uoe0IF1IL3ILGUGmkXcoDIqCoqMMUbYoT1QIioVKQ21AFaMqUUdR7age1C3UKGoG9QlNRiuhDdA2aC/0KnQcOhNdgC5HN6Db0JfQd9Dj6DcYDIaG0cFYYTwx4ZgEzDpMMeYAphVzHjOAGcPMYrFYeawB1g7rh2ViBdgC7H7sMew57CB2HPsWR8Sp4sxw7rgIHA+XhyvHNeHO4gZxE7h5vBReC2+D98Oz8dn4Enw9vgt/Az+OnydIE3QIdoRgQgJhM6GC0EK4RHhIeEUkEtWJ1sQAIpe4iVhBPE68QhwlviPJkPRJLqRIkpC0k3SEdJ50j/SKTCZrkx3JEWQBeSe5kXyR/Jj8VoIiYSThJcGW2ChRJdEuMSjxQhIvqSXpJLlWMkeyXPKk5A3JaSm8lLaUixRTaoNUldQpqWGpWWmKtKm0n3SydLF0k/RV6UkZrIy2jJsMWyZf5rDMRZkxCkLRoLhQWJQtlHrKJco4FUPVoXpRE6hF1G+o/dQZWRnZZbKhslmyVbJnZEdoCE2b5kVLopXQTtCGaO+XKC9xWsJZsmNJy5LBJXNyinKOchy5QrlWuTty7+Xp8m7yifK75TvkHymgFPQVAhQyFQ4qXFKYVqQq2iqyFAsVTyjeV4KV9JUCldYpHVbqU5pVVlH2UE5V3q98UXlahabiqJKgUqZyVmVKlaJqr8pVLVM9p/qMLkt3oifRK+g99Bk1JTVPNaFarVq/2ry6jnqIep56q/ojDYIGQyNWo0yjW2NGU1XTVzNXs1nzvhZei6EVr7VPq1drTltHO0x7m3aH9qSOnI6XTo5Os85DXbKug26abp3ubT2MHkMvUe+A3k19WN9CP16/Sv+GAWxgacA1OGAwsBS91Hopb2nd0mFDkqGTYYZhs+GoEc3IxyjPqMPohbGmcYTxbuNe408mFiZJJvUmD0xlTFeY5pl2mf5qpm/GMqsyu21ONnc332jeaf5ymcEyzrKDy+5aUCx8LbZZdFt8tLSy5Fu2WE5ZaVpFW1VbDTOoDH9GMeOKNdra2Xqj9WnrdzaWNgKbEza/2BraJto22U4u11nOWV6/fMxO3Y5pV2s3Yk+3j7Y/ZD/ioObAdKhzeOKo4ch2bHCccNJzSnA65vTC2cSZ79zmPOdi47Le5bwr4urhWuja7ybjFuJW6fbYXd09zr3ZfcbDwmOdx3lPtKe3527PYS9lL5ZXo9fMCqsV61f0eJO8g7wrvZ/46Pvwfbp8Yd8Vvnt8H67UWslb2eEH/Lz89vg98tfxT/P/PgAT4B9QFfA00DQwN7A3iBIUFdQU9CbYObgk+EGIbogwpDtUMjQytDF0Lsw1rDRsZJXxqvWrrocrhHPDOyOwEaERDRGzq91W7109HmkRWRA5tEZnTdaaq2sV1iatPRMlGcWMOhmNjg6Lbor+wPRj1jFnY7xiqmNmWC6sfaznbEd2GXuKY8cp5UzE2sWWxk7G2cXtiZuKd4gvj5/munAruS8TPBNqEuYS/RKPJC4khSW1JuOSo5NP8WR4ibyeFJWUrJSBVIPUgtSRNJu0vWkzfG9+QzqUvia9U0AV/Uz1CXWFW4WjGfYZVRlvM0MzT2ZJZ/Gy+rL1s3dkT+S453y9DrWOta47Vy13c+7oeqf1tRugDTEbujdqbMzfOL7JY9PRzYTNiZt/yDPJK817vSVsS1e+cv6m/LGtHlubCyQK+AXD22y31WxHbedu799hvmP/jk+F7MJrRSZF5UUfilnF174y/ariq4WdsTv7SyxLDu7C7OLtGtrtsPtoqXRpTunYHt897WX0ssKy13uj9l4tX1Zes4+wT7hvpMKnonO/5v5d+z9UxlfeqXKuaq1Wqt5RPXeAfWDwoOPBlhrlmqKa94e4h+7WetS212nXlR/GHM44/LQ+tL73a8bXjQ0KDUUNH4/wjowcDTza02jV2Nik1FTSDDcLm6eORR67+Y3rN50thi21rbTWouPguPD4s2+jvx064X2i+yTjZMt3Wt9Vt1HaCtuh9uz2mY74jpHO8M6BUytOdXfZdrV9b/T9kdNqp6vOyJ4pOUs4m3924VzOudnzqeenL8RdGOuO6n5wcdXF2z0BPf2XvC9duex++WKvU++5K3ZXTl+1uXrqGuNax3XL6+19Fn1tP1j80NZv2d9+w+pG503rm10DywfODjoMXrjleuvyba/b1++svDMwFDJ0dzhyeOQu++7kvaR7L+9n3J9/sOkh+mHhI6lH5Y+VHtf9qPdj64jlyJlR19G+J0FPHoyxxp7/lP7Th/H8p+Sn5ROqE42TZpOnp9ynbj5b/Wz8eerz+emCn6V/rn6h++K7Xxx/6ZtZNTP+kv9y4dfiV/Kvjrxe9rp71n/28ZvkN/NzhW/l3x59x3jX+z7s/cR85gfsh4qPeh+7Pnl/eriQvLDwG/eE8/s3BCkeAAAACXBIWXMAAA9hAAAPYQGoP6dpAAAAIXRFWHRDcmVhdGlvbiBUaW1lADIwMjA6MDY6MjAgMTM6MDA6MDaJt/OvAAD1HklEQVR4XuydCWAbxdXHZ1aHY+cOhHIWypFAYlsSNwTKTbkKpZJzcYezlHKlQGJLpalsJ0ChHy20UO4GctgSpaVQyn003CDJTgKEo6WUM5CQy44t7c73nnagJPjQsbvald7v+9Sd92wcabU785/ZN+9xIQQjCIIg7IO2mk/t7mVPDv2O+Ey6CIIgiBKhyCNBEARhA555hru5wqLVQ9hp0kUQBEGUEFpZJgiCsBHaGn6mwthd0DMv5yPFROkmCIIgSgStLBMEQdiE11/nHs5YGNtwnJBZzQ/M/oAgCIIoGSSWCYIgbIJ/F3Y6iORdpMlcnM2QTYIgCKJEkFgmCIKwAdlVZcGapKnD2ZSVK/kwaREEQRAlgMQyQRCEDfDvws7knH1Pmlk4Y8O28LLJ0iQIgiBKAIllgiCIErN8OfeCMN50VVkC/rNlkyAIgigBJJYJgiBKzO7bsBkgineU5iaA/8DeVXwPaRIEQRAWQ2KZIAiihLzzDq/iCmuUZp94FNroRxAEUSpILBMEQZSQnbdk53DGdpBm33B2Om4AlBZBEARhIVSUhCAIokS8/z4f8t1R7G0Qy9tLV7+ojP3YNVL8WZoEQRCERdDKMkEQRInYYSQ7NxehjEBnTRv9CIIgSgCtLBMEQZSA//6XV283nL0LYnkb6RoQ6KnVjSrbsXqM+FC6CIIgCAuglWWCIIgSsO1wdn6uQhmB33VVKewMaRIEQRAWQSvLBEEQFvPxx7xm65rsqvLW0pUT0Fu/6xrNdtM06rgJgiCsglaWCYIgLOY7Newn+QplBP6bXdKr2SHSJAiCICyAxDJBEISFfPopHwqi9wpp5g1t9CMIgrAWEssEQRAWMnYIuxDE8nekWQjBNWv4KNkmCIIgTIbEMkEQhEWsXMmHFbOqjMB/Xz1csGnSJAiCIEyGxDJBEIRFbOFhF4HYHSvNgoG/QaEYBEEQFkHZMAiCICzgiy/48DFu9i8QultIV1GkGQt4RoqkNAmCIAiToJVlgiAIE3jnHV614VO+Vc9KvmvmC743COWoUUIZcTM2QzYJgiAIE6GVZYIgiD54/30+ZGwNG+VW2CiFs1EcX4zhxrpRTLdHZtv9vOB3h8DRNKDnXvWfL9l2O+4oNkoXQRAEYQIklgmCqAgyq/mBIHp3huYIfJVa7BoB9N6d8D8rQbyvB3M9tPUj2PCzDV/ZAn+u6kd8ab1sfQZ+tlZj67fbjnVTkROCIIj+IbFMEERF0Ps5H+fxsL+BCN5NuggARgANDrrIZqxLvv4nvr8hxLMCHG0Q2VKQ60cQ4mnB/lu9hfgIfpcgCKKsILFMEETFsO4jvsWwoezPIJgPli7CAGAUeaxrIzt16HfEZ9JFEARRNtAGP4IgKobh24ov3l3JjgJxt0C6iCKA86hqgkV+9X/sGBLKBEGUK7SyTBBExaEonKur2S+hGeHQD+peIh9g5PhYY2y6a6R4WroIgiDKEhLLBEFULNqX/HTO2W2glr3SReQADBtPdPWyU4ZuJT6VLoIgiLKFwjAIgqhYlFHiTxpjPxCMrZIuYgAw7AJec+KPsx+QUCYIolKglWWCICqe3i/4eI+bPcQZ20W6iM2AkeITmFic4hopnpQugiCIioBWlgmCqHi8W4i3NnSzA0AQLpEu4htg2EV3LwuQUCYIohIhsUwQBAEM21qs/M+X7EgQzIukq+KBc/F12EXNWPGJdBMEQVQUFIZBEATxDShThg6MDBR2QRAEAZBYJgiC6APtS34G5+yPlZgpA4aFJ7vT7BRaTSYIgqAwDIIgiD5RRol7spkyBFstXWXPN8IujiahTBAEoUMrywRBEAPQ+wXf3eNmfyv3TBkwEnwqwy6ekC6CIAgCoJVlgiCIAfBuId6UmTKel66yQwj2VHcv85NQJgiC+DYklgmCIAZBZso4AgTzYukqC+DzaPBqjj/OjqKwC4IgiL6hMAyCIIgckZkymjljjdLlWKDn/0xT2amuMeIx6SIIgiD6gMQyQRBEnmhr+FkgmG+Fl0e6HAX0+s9szLDp1VuIj6SLIAiC6AcKwyAIgsgTZaS4S2PsGBCdX0qXI4D3q4ddPMaOIKFMEASRG7SyTBAEUSAyU8YSztgY6bIt0NNj2MVprjHiUekiCIIgcoBWlgmCIArkP6vZv+BQrVv2RQj23sYMC5BQJgiCyB8SywRBEAXyvbHsAO4Ascw426qLsXXSIgiCIPKAxDJBEESBQAd6mGzaGhD0w0a72VRpEgRBEHlAYpkgCKJwDpdH2wOC+RzZJAiCIPKAxDJBEEQBfPopHwqHfXXL/oBY3jf9Ja+XJkEQBJEjJJYJgiAKYEsvOwgEqFeajsDNaXWZIAgiX0gsEwRBFIDCnRGvvBmnvP8+HyLbBEEQRA6QWCYIgigEA8WyYCyjCXa1prFp0P63dBsOZ2zMDiPZj6VJEARB5ACJZYIgiDz58ks+Eg576VZxYA5kVWUHK6PEr5TRYtF/vmR7gHCeDaJ5rfwVQ6GNfgRBEPlBYpkgCCJPhjP2fRCdLmkWDAjiu1epzO8eI16ULrbjjmIjCOd5XRvZbvDzW3DVWf7IGDg7tGcl31VaBEEQxCCQWCYIgsgThReXMk4ItlrT2BQ+Upy1xRaiz2IhQ78jPoOf/ySjMT8I5keku2hA5HOvl50tTYIgCGIQSCwTBEHkT8HxyiB8n+lhzK+MFm3SNSCe0WIZiOZjVY0dC//tMukuljOeeYa7ZZsgCIIYABLLBEEQebD+Y74lHOp0K3dA6KY1wZrij7EjhowS/5HunHGNFo88m2R+TWM/gb/1mXQXBGdsm4N87HhpEgRBEAPAhYBulyAIgsgJdQ0PuRhrl2ZOQC/7tpphp7i3EK9IV1GsWsVHjHax2dC8FIRvQang4D39jY8UP5QmQRAE0Q+0skwQBJEH0GnmFYIhBLv9s40sYJRQRsaMEWtB6M7uZWwPEL2L4FXIqsex3av4drJNEARB9AOJZYIgiPzIaXMfqNcvVMZ+zEeJc7/zHbFBug2laqT4N4jmaarGJsG/93VGjVzAbB5VCjtLmgRBEEQ/kFgmCILIke4v+LYgMneXZr8IwZ7YqDKfa6T4s3SZinu0eME1mh2Yb1ET+Cwz5szhNA4QBEEMAHWSBEEQOVLlGjgEA4Rqr8bYFb+6kR1dPUZ8KN2WoGlC5FvUhHP2vfDPikuDRxAEUe7QBj+CIIgcEV/y20Fg9pmjGHrSNzKMTfeMFEnpKikbPuVb1Qxhc6B5LoZc6N5vA+97MR8ppkqTIAiC2AxaWSYIgsidPldhQXDe8kkX29suQhnZrKjJP6S7L34k0+ERBEEQfUBimSAIIgd61vCdMGxBmllAhK5UBTsRRek224gu6bYVntFiKby/Y/orasIZq6qpYadJkyAIgtgMEssEQRA54NksZRyu1nanmc81SjwoXbZmoKImIJip/DVBEEQ/kFgmCILIARCU2RAMEJobNcYuc41mx9ZsKT7O/tAhHHKIyCijxS2rVbYbfI55+FnQD59tYmY1PyD7SwRBEMQm0AY/giCIHBBr+H/hsDoj2HTPKNGpe50NhpZ4GZsLzSkwC7iLjxK0wkwQBLEZtLJMEAQxCL2f83FwiP/nS7ZPuQhl5JtFTcD87hdf8OH6TwiCIIivoJVlgiCIQXjmGe7GEAZpliWKwvm//sWqdtxRZEMzCIIgCB0SywRBEARBEATRDxSGQRAEQRAEQRD9QGKZIAiCIAiCIPqBxDJBEARBEARB9AOJZYIgCIIgCILoBxLLBEEQBEEQBNEPJJYJgiAIgiAIoh9ILBMEQRAEQRBEP5BYJgiCIAiCIIh+ILFMEARBEARBEP1AYpkgCIIgCIIg+oHEMkEQBEEQBEH0A4llgiAIgiAIgugHEssEQRAOZMbO9wyRTYIgCMJESCwTBEGYzKwJdw1vrG/bR5qGsN2IofdGfLGLFGUO9eMEQRAmQp0sQRCEiUT88ZPcVSOWK4pynHQZA2fDmMJ/1+SrfWF2fZtPegmCIAiDIbFMEARhArMmLN42HIjHQdQ+wBnbnnGuyR8ZxNd/b1+3y/VKxB+be8H2t9VIH0EQBGEQJJYJgiAMBMMiIv74hZ4q9xsgkn8s3YwJYbBYZt/8ex4Q47PGbjmms7E+frT0EQRBEAZAYpkgCMIgwoG22kZf7T8ZZzeDOUL3SoxeWe5LfHO2s8vF/hEOxOZfGbh3K+klCIIgioDEMkEQRJFgZoqIP9bCmet1ztgB0r0JHNStbBrDAOKbM35qFat+Ixxon6EoCrwlgiAIolBILBMEQRRB2B8/YruRwzpBvDaC6dG9fSCMjlneJAyjL8ZwptzR5Gt/sinQNk76CIIgiDwhsUwQBFEAV+yxaMtwIH4X5+wxMHfVvQNifhhG3xyqMFcq4o+Hp9TFvNJHEARB5AiJZYIgiDwJB9pPHTLEs5wzdiaYuYU5cIM3+OUXAz0E3mV0nJsnIoHYQdJHEARB5ACJZYIgiBy5qn7xLiA2H+NMmQ/mWN2bI9aHYfTFBFDZz0T8sT9cvvM9o6SPIAiCGAASywRBEINwgXKbB0TyLK/L3Qli80jpzg9esjCMzVEY5xcMHTnsjbCvfbL0EQRBEP1AYpkgCGIAInWxfcf6xrwCancumNW6twC0koZh9MXWXFEWRwLxv0UmLthR+giCIIjNILFMEATRB5eMXzAiEoj9jrn5C2AWX07a8DzLhq1UH8+8Vcvgs14+RYm5pI8gCIKQkFgmCILYjIg/ftLwmqploHAvAtOYftLoMAxjNwwOhT94/Tgff6nRF9tL+giCIAiAxDJBEIRk1oTF24YD8TgI2wc4Y9tLtzEYHYbBDN8wiOzlUvhLGJ8tbYIgiIqHxDJBEITEU+V+DUTyj6VpKMK+YRib44I3W9gmRoIgiDKExDJBEMT/GCqPxsM1Y8Wt0XmbCYIgiD4hsUwQBGEFmrEry8KcMAyCIAhiM0gsEwRBWIHhYRi0skwQBGEFJJYJgiCswOAwDM65kE2CIAjCREgsEwRBWIHh5a5pZZkgCMIKSCwTBEFYgXOyYRAEQRDfgMQyQRCEFWhGZ8OgDX4EQRBWQGKZIAjCAgzPs0xhGARBEJZAYpkgCMIKKAyDIAjCkZBYJgiCsAIKwyAIgnAkJJYJgiAsQOGKsaneKM8yQRCEJZBYJgiCsAKjy10zCsMgCIKwAhLLBEEQFiAMLndNYRgEQRDWQGKZIAhHM2Pne4bIZvEIxmXLeAzf4OeMMIwmf+wnM3eMVUuTIAjCcZBYJgjCsTT528/dbuTQK6VpbwwOwxAOCcNQOGuoGcOfjewe2066CIIgHAWJZYIgHMfhyhx3xB+7UeHKH0GFeqTb3lRqGIbguLFxb1bNX47UxfbVnQRBEM6BxDJBEI6i0bdw9CRf7UMgFi+WLmdQoWEY32Bb5ubPRHzxU6RNEAThCEgsEwThGGb5Y+NdivdFaB6tezAcQRibks0sjM6G4ZwNft/8fobAqDM/4o+1KMocGn8IgnAE1FkRBOEIGuvjR3s4R6E8Tvc4C8OzYTg3dRwHod/YVD/xgVkT7houfQRBELaFxDJBELYnEohf7HKxh6A5Svf8Dy42Wbm0L5UahsH7Wfnn/IeeqhHPN/oW7iw9BEEQtoTEMkEQtmVKXcwb8cdvh+aN8HJnnU5FU40Vt84JwxiIWpfifanJFztE2gRBELaDxDJBELakaXxs7G4u/jjj7Gzp6hOBa8tOgCvGilvNKWEYg34/WyoKfyzii50nbYIgCFtBYpkgCNsR9i2q5zX8Zc7ZwdLlfBSDV4K547JhDIQHzs+tmA4Q0wJKH0EQhC0gsUwQhK1o8rX/iHPPEs7YTtI1CM7IhiHUig3DyP374fziSfW1j8ysi42RHoIgiJJDYpkgCFugKAqP+OONcIwzzoZJd/lgdBiGcGw2jIHh7IgaN39pVn3bHtJDEARRUkgsEwRRcmbuGKtu9LXfC0KpBcy8+iXOHZINQ8kYKm4Fc0oYRkEr/7t6XK4Xwv74sdImCIIoGSSWCYIoKZHdY9vVjOHPcsamS1dZIlSDV5bLIxvGQIyEidCDkUDscmkTBEGUBBLLBEGUjEhdbF9WzV+G5t66J38ckw1DMToMw+CKgGYhivp+XDAruB4E892XjL+pSvoIgiAshcQyQRAlIeyPTWdu/jQ0t9U9ZU7G2DCMClhZ/gb8jBE12zwZ9i36jnQQBEFYBollgiAsRVHmKBF/rIVzfi+Y1bq3cJxSwU8YvbJsfPlsczAupvxApnhebgwsCkibIAjCEkgsEwRhGRfVxYY1+WrvZ5w3gsl1b4VgsFhWuEPCMAwELpjvupjnuYi/PShdBEEQpkNimSAIS2icsHin0W6+BJon6R5jEE7Js5xJGytuHROGYfj3M5RxpT3ib/u+tAmCIEyFxDJBEJagVLkuhEO9blUeLu4xVjQ6JQzDHDjTlC1kmyAIwlRILBMEYQk8m9nAeLiR2TDgj8mW8ShGryw7JQzDnGwlmmLO9UQQBLE5JJYJgrAIXtn9TZryLBuJwkksEwRhDSSWCYKwBGHSyrJwSAU/4XIZK26dE4ZhyvcjBIllgiCsgcQyQRCWYFYYhlMQrl6DV5YrLxvGJnBB4xdBEJZAnQ1BEJZg1soyd0g2DNZboSvLwpzvh9PKMkEQFkFimSAISwBRW9H9jeFhGEplxywLilkmCMIiSCwTBGEVpogbYVK2BaMR7o3GiluHhGGY9f1QzDJBEFZBYpkgCKuoaHEjNroNFbeisvMsw2RBofGLIAhLoM6GIAhLMC1mWZiTbcFoNLexYtkpqeO4SdlKFFpZJgjCIkgsEwRhEZWdZ1ls2GCwWK7sbBgUs0wQhFWQWCYIwhLMSh0nHJINQ/V4jBW3DgnDMO37EZQ6jiAIa6DOhiAISzArDMMpqF6vwSvLlR2zzGllmSAIiyCxTBCEVZjS33CHZMPIrF5tsFh2RhiGWd8PZcMgCMIqSCwTBGEJlV7Br9fgleVKz4ZBK8sEQVgFiWWCIKzCFHEjTMq2YDQbhg41eGXZKTHLJn0/orI3jBIEYR3U2RAEYRUVvRK4ctkyY8Wtplb0yjJlwyAIwipILBMEYRHmZC/gDsmG8TTIW9k0Bq44QixzYVY2DBLLBEFYA4llgiCsoqLFjaZdbay4VShmWTYJgiBMhcQyQRBWYYq4EZojsmEYLmyF6owwDMFN+n4ozzJBEBZBnQ1BEFZRySuBxgtbh4RhmAXFLBMEYRUklgmCsAhzshdwY7NhcHk0GuNXV5WMI8QynFBTVpY5xSwTBGERJJYJgrAEUEy0smwgQq3slWVQ4TR+EQRhCdTZEARhCWYVJRHOyIZhvLBVnCGWzfp+qIIfQRBWQWKZIAirqOT+xnhhm3FGGIZZUDYMgiCsgsQyQRBWYYq44WZlWzAWw4WtcMjKMsfoYhOglWWCIKyCxDJBEFZRyeLGeGHrELFsGpzKXRMEYQ2mFVciCMKeRCYu2FFzewJcUcZzJrYSjA+FjqAHjhs4Z/9RVfbmWiFevakztF7+J4YQCcSXwmGibhkH9GAXNyeCv5NmUcB73ACHGt0ylNXRRHCMbBvCVbULd/N6vCukaSyCPRFNBo+UVlGE/fGFcF1NlaZxCHY7vMdzpWU4M3eMVVeP1vZggu8KunxLwdlwuF/SgokvNcb/rYneFfOS0/8rf50giDKGxDJBVACRuti+zMVOYZyfBOaOundA0vB6BV6Le1j3omsTp36W9RYBCNHlcNhDt4zDIWL5CxDLW8q2IVxVv3gXr8v9jjSNxQlimbG74JzOkG1DwImk8FZN54wdB+a+8PJmf9A/H8AQ+pQQ2uIXOpc/+qR2dUb6CYIoI+gxFkGUMU2B+AnhQPx55uYvgVC+GFy5CGXEA68D4XVjFat+H0TkrSgksj8pHHNiljVHzPiNj1l2uRwSs2zO9wN/1bDrCSeTcJ/EmbfqPRDKreA6CF6DCWVkB5gInK4oykMH+mrfDfvil12w/W1mTLYIgighJJYJogxp9C3cGQTuP+AGfxAG/wOku1CGwOs8EBJvgKCIHK7McevuvKncmGVhvFiu6u2t8Jjl4stdh32LvhMOxObDZPJFuE9+DK6C/yb899/lCrthy7Fj3oBJKv4tgiDKBBLLBFFmRAKxKS7Fm4Dm0brHMKpBEPxqUv3E52bXxb4rfTkjzMqz7IRsGNyEDX4OWVk26/sptoJfo6/9SK54kpzxU8GES9sYUDTDwBqH+/AOWmUmiPKAxDJBlBERf7wRhuuF0Byhe0yA8/3dbv5CuC7ml55cqeT+xnhh2+sMsWwWoog8y5FA/AKXovwdmlvrHjPgM8aOHfPUlYF7t5IOgiAcCollgigTMESCcdYCTcNWyQZgW+7mT8z2x+qkPSjwpkxZWYa/W6Exyz2OEMvmfT+FpY6DCeWlcPgDvAoNJ8qHfatY9dNN42NjpU0QhAMhsUwQZUCTL34WiJJfSdMqxrg5fyQ88b5tpD0YlRuzbMbKsruyV5YLmXxF/O3T4D+8QZpWsQevYQ/N2PkejP0nCMKBkFgmCIczu77NpyjsZmlazbbMM2TxFCWWi3Axpb/RTMq2YDDGryxvdDtCLAubZMNoqotNYFy5DZqgs62FM77PdiOH3ShNgiAcBollgnAwKFLdLtcd0KzWPdbDOTt4nI//VJoDQSvLRuLuruyV5TxilhVljsLd/E5oDtU9JeG8xvq40ZtuCYKwABLLBOFgxtWxs+Gwl26VlGjTxPlbyHZ/mCKWFSdkwzBjZdntjJVlLkz7fnIevxrra2dwxvaTZslwudjNRaReJAiiRJBYJgiHcoFymweUYqM0S80I7q2+TLb7o3JXlk3Isyw2eCp6ZRnI6XqaUhfzcs7C0iw1ux5QV3uabBME4RBILBOEQ9nCN+aHcCi2qp5hcMbPzQr4/jGlvwHFaP+VZRPyLAvvOkeIZfhyzPl+coxZ3k0RP4KDbe4TRWGXyCZBEA6BxDJBOBTOhN1WqLYa6xt1jGz3hRNWls3a/GW4sNWqKnxlOceYZa7wM2TTLvgaA4sCsk0QhAMgsUwQDgRXcDnjR0jTNgjBj5XNvjBFLCuaA7JhmBCGoa4a4gixzLlZ38/g5a5n7hirhndwuDRtg0t4jpdNgiAcAIllgnAgW/jG7AmH4bplHzjn35fNvnDCyrI5mBCGkRnySUWvLIMCH/R6qhrDDoCDHfMbHyaPBEE4ABLLBOFAQHtNlE27MW6AuGVT+hvNtJVLQzH8Pfa8XeUIsSyYOdkw4K8OKpZdjNfKpt2w6/1LEEQfkFgmCEfCd5INu+EZs/uI7WT7a3IsWlK+mBCGsZqNruiVZcYHL3cthNhZNu0FZ9+5qC42TFoEQdgcEssE4UQEGyFbtkPxiG+/t4nmhWBwpth/ZdmEMIx2NtkRYpmbsKouGfya4nykbNmO0Wlm2/dGEMSmkFgmCCfCmX0LG3DlW+9t6IYNld7XGC5sNU1DEWr/iYJ5DCqWuRBVsmk71Kq0bd8bQRCbQmKZIBwIF2ydbNqOdEb91nvbcqTLtJVlwcRAuZ3tgRBmrQLbenW50RfD6pLmZKPIJc8y57a9T/hGj23fG0EQm0JimSCcCOcfy5bdEBu451vvradLMU0sK4xfG/bHT5dmwVyw/W01cDCnT+TcaWJ5v3Cg/QeynTeKovCIP36pS+HPg2lOQRCe03f1mTzajfQLby9bLdsEQdgcEssE4UCEJt6QTbvx35s6Q+tl+2uGDuGmiWUQTcM4Z/eAYL6n0E1TVwbu3Wrs2DFPQdOsR+POEst4TpnyYNgXO1N6cqZp4vwtGuvbH4C/8RswvbrXFAa9pgTT3pJNu/Huk9rVGdkmCMLmkFgmCAfStW7DK3BQdctWvCiPm8AzGdP7GhDMp49289fCdTG/dOVEY11s1ypWvQSa++oeM3BkGIaHK/zOSCD2C2kPSpM/frDirUnAd3GidJnJ4GJZU1+VTXshGN6/BEE4BBLLBOFAbnjvjC+ZELYbcDWhPSabm5D2mriyvCnjuJu/GPHFLpL2gET8bfu73NlQgV11j1k4LgzjKzj8/5yIP3774cqcfjeVKsocBX4nrHD2JJg76F6TySFmuSU19U04fKBb9kEw9rhsEgThAEgsE4QBlCSPMOcLZcsu9LD0xvtlexO8vZaJZaSKKfx3kUD8/kbfwtHS9y2a/LETGXc9Ac2xusdETMizLDFbLOtwdvYk38S/9BXmclVdbOum+tpH4XeiYFqWpUXkFrMMc0rWJpt2obtr7fq/yrapNPraj5xdF/uuNAmCKBASywRRBFitLhyI3zKulu8nXZaxcWN6ARy6dKv0gCj5c8uy076Q5iZkPJaK5a842aV4E5H6+IHS/pqIP36hwjkKe9zUZz68HLJh8ONGu/nTKI6lg+EmQK+bp0AoHyFdlsFzybMMCFXciQfdsgX3Z58MWYCi8EPdbv5KJBA7SLoIgigAEssEUSBX7LFoy7G+MY/CoH2+pohtpdsyrntj6uegAW6RZqnRVCZaZftbcNVbqr5mR5BUz4A4bsRQAT1LQ2wuKK2b4WcWCnjHhmFszl5eF18yu3bRRDyPnCkPg28r/UeWk9P319IZWg6HB3Sr5GiCqfNk23Q449gvwffDn4CJzQzdSxBEvpBYJogCCAfaaodUeV6C5qFoKzw7KFnOxo2ZuXAA0VxqxN1zk6FOaXwL1W2lMP0WblANLU2+if9orG9fwDifJf3W4fQwjG/C2c5uj6dDnsdSjiE5/9taRoTh0KtbpUMw9qfmxOSl0rSAryfxXpjY3BEJxK6v+NLzBFEAJJYJIk8igfYfcuZ6HkWDdMEgaP3KMiJXly+XZqn4ROvtvlK2+8SdKalYlvAjOWdTpWEtZRGGsQl2GDtyvqbk6vK1ulUyVvZsTF8h2xbBt5ENCb98nI8/fPnO94ySDoIgcoDEMkHkiCy00AgtfKQ7XPfqcFGalWUkmgjNB8GMcZmlIKNpYmp/scpfwd1ahfc1JoVhmLdi7QTymoCtTK36lRDsOWlajaqq7FR9cmspffVLRw8dMezFWf7YeGkTBDEIJJYJIgdm7hirbvS134uP88Hs674pmVhGPlyz4acgnDCzg5UIjYkLWlKhZ6TdLyAUKv3Rb7c8Gg3Gv5Y8vKBE5PW5b9HOTadVMRma7+ge6xBCzGztCD4qTUu4ZPxNWGBnC93aDM7Gezh/obE+frT0EAQxACSWCWIQZk1YvG3NGP40Z2y6dH0bXlqxfOd7Z2xcrYofwbCMVeisQBOC/awlEbpD2gOiprWVcMCct5XI4g1r1p8n24YSTQb/Twj1AGiu0D2VgWDshV41k3eGh2s6Q5+oPZmj4A+8J11mA7cJa2xOhm6UtmWMcI/BrCXQbfXLaJeLPRTxxy+VNkEQ/UBimSAGIFIX29dT5cbiH4NVd9ssNtB6sMz02q5PjgUhMF+6zEGw9Uxok5uTQcwokRP4+HnlylV7QfP38LJTGi/zgPMkNHFWNBGcamaqsObk5NdXZ8RecFLvlq5yJgMn9urnU0u/f03HlHelLy9al0/5txBpTCf4su4xjV7BtHOaE0HchGs5mtubywQeN7/+JhKI3TGlLmZmaXKCcDRc4LyXIIhvEfHFT4Hp5G3QrNY9A9PDuoddmzh1gzRLStgXO5Mr/DfQNHYjjxAv9mbSp1+zdNrb0pM3Tb724xRFwRXpr/P1lh2Cva5xdVpLYrKlK77hQHwqZwzTCY7UPWXF2xpjp7UkgpiFpmhQHI5zsRbG+WVgGh0m9KYQ6ik4kZG25UT87UHGlZg0c+Gf0IcFoQ/7TNoEQUhoZZkgNkMv3RtrgbsDV2hzEsqIOzOk5KvLX9GcCt2tdYlxIG5ROPXo3sKBKfV/BNPObulYNqkYoYy0pBoehvdWD82/6J6yQoNz/usVqjjAaqGMNCeCi3qYCOCkRrrKhT+uzog9jRLKyOLOUG80GboCRO2+cIU/K93Fsgb+1uy1XR/7SymUs4jNM2EMykFVrPrl2fVtPmkTBCGhlWWC+AazJtw13OMdfh/j/IfSlTtCPSSanGzUoGsYGHPt8brOh9v9VPaNdHc5oMLrCSa0u5d0LG9/Urs6o7uNI+KLnQfn+np4X98qo+xAPhaaOAMmKo9Ju2QcrsxxT/LVXg3N2fBy8ubKlTBTOzeaDJo+sdKr3PGLoXkCvHKeJEvehPd5V2a9uHXuOyEQzKUn7I+3cp79/vNlA9zzZ0STDXFpE0TFQ2KZICSNvoU7uxQvDsq1uic/4E6ahit70rQdmPruqvq2Whfj3+eM+eH9jofB9DtwrOEim1lgA4jW95kQb2qMvcS62TMtb4VwY56pXFW7cDePxzsf3pPlJcMN5O89rPtMuz3CDgfaD+NMwSck2+keJyEe7s2ws3FTnnRYwiXjF4wYVlN1pMLEYWDWwzC5Kxy3hBfG9GKqvnXweh/umxVw3yzJMPHEQAV5SgWI/7vhvZ8hzXyBjyd+2ZKaHNU0DdoEUdmQWCYIoLE+fqjLxdqhiYNigYiZ0UToBmkQeZBdCa2fGGGcN4Lp1r2OoAdkxayWjoYb7SoqmibO30Lx1mCM+Em6x/Z0wTm9As7pH+x0TvEafZrNUZ0iHiOB+D/gUFRqOMFE2+crV591y3/P7ZIugqhISCwTFU9TIH6+wtjvoOnRPYUBt9L1zcngz6VJFECTL3aAonBcCd1F99iaNzKqOm1ux+SUtG1NxB+/kHH2a2jmG2JgJa9pWvrUltTUSk0zaBgglnG1u6CnZJuRYGrmpGjHlA+kTRAVB23wIyqWC5TbPDCg3Aw3AW6CK0ooI7xEJa/LiZZU6IXVGeGHqUepKhLmyh9Xrly1t1OEMhJNBn8vGG5mY8t0j61QYbbZujK16gASyoZhVH8UYC73yziRlTZBVBy0skxUJDPrYmNqXLwdFO7h0lU0cCc905wIHipNokgi9bGTmYv/EZpFhMYYD/SZ4eZkCCs5Og6MD/d6vA9DE+Nw7YPQpkeTDQulRRTJjJ3vGbLdyGEYOjFQUZJ86YHv6Xz4nu6RNkFUDLSyTFQcTXWxCTVu/pKRQhmBUYlWlg2kZenkB+Bwv27ZB875FWFf7ChpOgbM9gBC+QVo2ksoA4IrrY11Mdu9L6ey5cihmDbOSKGMVDGu3B3xx66bosQqvXw9UWGQWCYqiqZA/ATFzc0SDCSWDQJzXTf62v8ATVPKRBfJSK7wh5p88bOkbXtAKE8B7YQp7bbQPfYCVN1OLjd/ZnbtoonSRRRBlZnZTzj/+Tgff3D2rrFyLHxDEH1CYpmoGCL++JVwwWNquBG6x3CG4mNu2SYKBGPJm+on3gsC6nzpsiMeRWF3RgLxKKbkkz5bAkJ5FigcDHEYontsy7Zuj+eZSH18b2kTBYATTfi+fyFNszjWPZy/QP0dUSlQzDJR9mD83rYjht3KOTtdukwD7qaXPk+tOvgW7dy0dBF5IGMtMVe1U9KcYXqte9/OsLOxIpx02QJZmORmaNpxdX4g1mqCndCSDD4nbSIPcFGAcXaNNM1mFUiIyc3J4BPSJoiyhMQyUdaEJ963DfMO+TO3suCFEPOiyVAhlbMqmovqYsNGu/gDMNAfIV2OATd3alrvya2paaulq6RkK1FWjVgMzWN1j+PoUoUItiZDj0ibyIGmQHw/hTGcZBSd3ScPsLLnzGgi+FvdJIjyg8QyUbbg41zhYiiUt5cuq9BUJo5qTYSelDYxCJfvfM+ooSOHPQTNA3WPI3mjh4njr02E/iXtkhDZPbYdq+Z/g6Zf9ziWXo2xaS2JoO02edqRC7a/rWbs2DFJaJYqNOKPKzLiZ3Z7wkIQRkBimShL5IYmzNVbo3usBe6q/6zr6qm78a3pa6XLNlwZiH3Po4k9FK7sBOYYwcUQmFCs14T4QnD+rpphy60sMXxl4N6tqlg1VhtzurjDL/5TpooTo52hl6XHUsK+RfVM8TxUggmiWcC8Uzu7FOnKsuFbI6t3Fcy1EwyUI+C79cIX3AUCfhVLa+/Me/PN/2ja1Vj+2haEA7GbOOM/lWZJwCcsPRvToevemPq5dBFEWUBimSgrcHNLk692DjSb4AWaoaTcFU0EZ8h2ycA0T7vU8iMUF5sG5pE5Cql3oGf4O7zua0kEX5I+w5nlX7C9h1dhlobddU9Z0KVp2iktqQZMfWcZjfXxo2XJdrM2sJYKmMexi5uTQYy/NhXMxuHyuKdwwY5inO8FroHCGdbA6zl4cw/39mTaSykQw/74EZwzvI9K3eehYP4309InNaemdkgXQTgeEstE2YAxr6PcbD5n/EfSVXI0xn4IYhMfiVvOlLqYd1cXO1vhfCaYhZePFux16CmubUlNbgMRaFiHgXl1FTd/DEZ3XOEuNzQ4bzOjyeD/SdtUQCydA2IJU+25dU/5ARdeY3MiOFeahoHZTJpq234kXPwKuBYLrVKXhvfXzjLiuubOEIZCWMaVgXuHeln1UlvdRwKfVGmnWT1hJAizILFMlAWNExbv5KpyY1q4et1jGz5I96ydOG/5WeukbQmNvvYjXVy5iXE2XrqKBnqKF1RV/YkRJZ5n+2N1bs4fhebWuqc8gXP2u7dT4rLFWkiVLkPJCr36tmbGeaN0lTdCtEaTIXxqZAiNgUUBhXluLkIkbw5Oku7U0l2zWpad9oX0mQpMlH4NEyWcENsNPBeRlo6GuUZOsgmiFJBYJhxPky92CGiGGDRtVRb5K1AwNSeCF0vTVDBd2IG+ia2c8Z+DacYj2R74PFfA5/mdtPOmsb5tH5fL9Xdo2rJAhgn8ZeXKVdNv+e+5WH7YMC4Zf1PViOqt7wKhjOE1FYNg4ubW1LKLi4kXxkkGTCivhBskCqYZmSM+VJk43exNvo2+2F4uhWOYlG0r6oHEWNS9Wsy4/v1Qt3QRhOMgsUw4mogvdh5TOAo3r+6xJRrLiAPM3vRlabowIW5Z0rHsZ09qV2PaqJyRE5sHoTlc91QMLwstfWJzauqn0i6aiD9+G0yHzpFmhSHuWZFiZxeyYq9v3Bt6D0woJ0uXWeB7uyiaCN6im8aiV7msfR4Ev3VpMQvnVdYtfhR9M/ShtAnCUVAFP8KR4ApqxB+7EYTyrWDaWSgjinCzm/TKWuaAaaNAKD8MTWvy6nJ+wYG+iXfl85nC/vixIJRxRbnShDKyL+NuQ4viCC5s+STFGvgZ43zZTbx5gavx240c+oAFQhnB1d4/hP2xK3TTWGbX1Z7hEKGM7M2q+SuYB1raBOEoSCwTjmNmXWzMpPraR0CwWRLaYAQwOO+Dg5s0DQUfKY/dcjRWvTtI91gDfKZTm+on5l4pjLOr4X+rdYMgikMwntdkAe+T4TVb/wkuxB9IlyVwzq8J+2JnStMQLhm/YISisFZpOoVtQHA8HQ60nyptgnAMJJYJRzGrvm2PGjd/EYSX46q8KZzNxUFOmobR6GufBSPyD6VpLZzPbArEfyytAeHZ/y85pmy0qzAyQohfCiZekXaJEHmNX02+tsssWlHeHM4V/vtwXcywPOIjqr1YIdSJm2OHcKbMjwTi15j5pI0gjIYuVsIx4GN8j8v1AjRLVaGqODj7zoiaKkMfyTbVxSaAAv2lNEsBh07kD00T5w+6WQ/EVSnF8keaph2vquw4aH+pu4gC+BLO4fHNydCc51PLDsRsB+ArScU2EL45X09NvkW7w39RypXYau7if7pAua3ozYTZCo0OeqrWD1c2+Wr/YsbiAUGYAYllwhFE/PGfw9CIG8NG6h7Hcll44n3byHbRKC7+WziUOmZ7K8Vb8yvZ7hcQNyXpbwRjC7oyoq4l1fBwa0fw0bQQ+4PzLfljIndW4LnDc4gGbu6MJoPNKkvvD+ZS9FmJELlPvhTuuQkOVbpVIjirG+sb/TNpFc4QjkWXSlKZ1GBOGFFT9fxV9YsLzwFPEBZBYpmwNbghJxKI3Q0DzXVg2jY9Uh4M5Z6qX8h2UWBmCTgvdglHOWd2Xey7st03At6ttXyuCdHQnAiecn1naJX0sXnJ0Fuq6MW8ulnRR+TEY6rWuz+eO2l/TWtiamJt18d7g3qdB6Z1YS48t8mXve4TfhUWEZFG3lxVu3A3+CyGxj+XmIlel/ulxkDscGkThC0hsUzYlqvqYlsPr9nmKRhgTNkYVzI4nzGosMwBrtjqUazX7WLny3bfcOv6G8HEAz2se2JLMoT5t79Fa2ra6iWppcdD05IKe45GiN/CuToOz5n0fIsb37qoJ5oMzdY0cTCYK3SvucDMK6fJF+f8ctm0A1t5WHXBG9y8nmyscjksGnyTLVyMPxLxxy+UNkHYDhLLhC3BylpeN38ZRkOjKmvZCa/bza+S7YLAjCBwbk6Qpj3g/DTMOCCtvshJ3BTJl0KwM5oToZOvTZz6mfT1STaMIBG8TDDtbDBLEndrc9JME+eDCL4k13zaLanQCytXrgqAwsawB5OT+A8ehnFl4N6tOLconWKOKEIUtDJ8ZSD2PTiUayYJD/QON4f9sd8bEddNEEZDYpmwHWFf+2QX8/wTmjvonrLk7FkTFm8r23lTrYgj4WC3/NI7NNYtqJPtvjBbLD+aFj11zcngn6SdE82JhjtBeOFj+gHFdYXxuaqyo6Op0B+lnTNYqTCaCP1MZdlr9H3dawJi8DCMKlGFQtle4ovz/VDESytnqvSqnGUtJDnnPxnrG/PoFXssquAc4oQdIbFM2AZclYz4Y3O4omDO4HLYwDIQVR6vq/DNPpwfKlu2giuegd6XWf0NltH9SUuq4Zh5yen/1V35AeLun6y3Z19opnSP8XDGHVMuVWXpo1s7gk9LsyCw1HMP68Zzag48hw1+nB8mW3aCe7WqvO5ffJIEh/IKR+ufQ4dUeV4KB9pqpU0QJYfEMmELcNNLU31bOwxuuPnNisf1pYfz8wrd7MM5myibdmOg92XW9/oWlhTWNK0oMRpdNv19JrSoNCsaRWMfyWZRrF3ZvV42TSCH1HGCD/Sko2RwRcnrfdW42XlwKHhjoOPgbGfOXM9HAu2lyR9PEJtBYpkoOZGJC3asYtVLYOwLSlelMMYjhhRUAlkwvrNs2gwx0PuyfX8DcpuKlgBio1uTTRuTQ1ESznaVLVshRO7va4oSc8EHqcTNb8Ohy3gg4o83DrIXgiBMh8QyUVIigdhBzFv1MjR9uqeyUDi/QDbzAkYOWybzFwPnwbb/gMe5A0Si+Wz02n/SIMTAK8u6yETBZT/gjY+SzUHZrY4dA4dy3r8xEAqcrJYmX/v8mTvGqFQ+UTJILBMlIxxonwHDxhPQzHuzSxlRH/G3YVGHfLHb5r4snPH+NyBZn2c5fxwkls2MgRYbNtj+PMDFNOD1NHrb1ViExJ7XHGdDZGtQuMLPlc1K5pSaMfzpYjZFE0QxkFgmLOdwZY47Eoj/hjPlDjBtKfoshSuFDIbr5NFWCDHA+7Iwz3KhgPykMAxA9XjsP2kY5Hr640fn48ZPu36fOcVyy6wZmA+cYGxfT5X7lUhdzLxNowTRDySWCUtp9C0cPclX+xA0L9U9BIz6oQIeMX4qj/aCD/i+HLCyrFEYBqB6vbY/D2KQ6ym74VOwz6VpN1bK44B4RXUDHNy6RQDbMjd/OuyPTZc2QVgCiWXCMmb5Y+Nd3PsCNI/WPY7ACtEwYsjo/FaPQCi8KZu2AtRL/+9L2L+/AalMK8tA1Vr7nwcuckkdJ75VntsOwP2b0/vinFkhCrHse1FpAi2mmnN+b8Qfa1GUOaRhCEugC42whMb6+NEezl8ENTVeupzAJ5qqfp8JsVDapgGd/zTZzAku2CuyaSs0Ifp/X9wBK8sKbfBDMkM+cUAYxuBFSeCXXpcNe6GJQd/XLP+C7eFgdgXTd1Wtd+rK1KqjQcJj1UWnAL0Jb2yqn/jArAl32XITJ1FekFgmTCcSiF3ucrGHoZnzDvBSI5h4JS169mnpmLykh2/EmOIO/SfmACrymAu2vy3nQiwqTz8mm3Yivb67t98VqsEem9sClcQy0vN2lQPCMAZfWRaaeFw27cTG7i8ZVigdEBfzYo5hM++ZnoyqBltT01bfop2bxqqLGhPnoF//sQPg/IeeqhHPN/oW2jSVJlEukFgmTGNKXcwLQvkO6NGuBxPTODkDweZ3r2KHfFUN7trEqRs0LT0FmrhhyCxqxo4dhSWXc2JeanoSDit0yx4Iwf5+41vT10qzL2zf33CFwjCQ1Wy07cUyLi3KZr98tG4DZttZrVs2QYiHrn8/NGhfojB+omyaAkxer57bMXmTipUtidAdcAccDs1PdI8jqHUp3pca6+O2rGpKlAcklglTwF3c49yYFo7PkC4nkIEhZGY0GTx988GsJTX1TRhcrpKmSfCcq1Xh5iXgdmnaAs61Ad8PKBv7ryxrKq0sA4u1kP0nDWLwoiR3vnfGRsHEAmnaArhz75TNfslu+OXMNPEHfdlLb6fEr6W5CdGO4PPpnsxe+DvS5QS2dLnYo02B+PnSJghDIbFMGE64Lub3smqMXT1I9ziCVaqmHRtNhG6Q9rdoTS292cwBRDB+lGzmRKZ33S1w+EK3Sk6qJTXlb7LdH/bvb7hCYhn0nDzaGsFzKHcN9DKGT7bSulVyknM7p/xdtvulejQ/EA4552LOE01T1Z8NNCGat3zKRx+tWX8o9Hd3S5cT8EAHc0skEL8Z05NKH0EYAollwlAi/vYgd/N/wij2XelyAkt71cy+ramGAeMbNe3q7CCDTd1jLHDOdson9m7e8rPWCSGi0iwpqhCzsqm6Bsb2K8sglSkMwyFiGS6mnK6naxOhf4G0vlWaJUUI1pjDfQKfTBwmWyYg5rd2TB50gzCuyjcngmfBLP4yMDO61xFcOKm+9pGZdbEx0iaIoiGxTBgC1u6PBGK/YFxpB3Oo7nUEf16dEQdc0zHlXWkPCA4ygomYNA2HK568Bsm3OxjuYMdy4SUDRv4FrcnQI9IcCNuLZYwlka1KxikThpzHr7VdvU1w+FC3SgP0G23NyeCgq8pZBP++bBlNRs2wZtnOiWgy+H8g8rHktl2eYg0OZ0fUuPlLs+rb9pAegigKEstE0VwZuHdoo6+9DXqoOWDaXxDpCBgA5rSkGoI3dYZyqqb1FarIDjaDrw4VANyQ+Pg1Z/BRag8TU6G5SvdYzop1XT0/ke2BcUCeZaFQzDLgjDCMPMqn48ZTTROnQLNUK6T/6s6wnO4TDCHgnO0pTWMRor21M/SOtHIGRP4Tqta7L9zDndLlBHb1uFwvNgXiJ0ibIAqGxDJRFJH6xTtUsernYNQKSZcTWAud/skwAPwyp0eimzE3GYIBQ2Aif+MRfB/Zyhl8zKwygZW+Nuoey1ipaemTBsmA8T8ckGcZpDKFYTglDCPP8uktqdAzcMAwKqtZLbT0j67vDOU0oT2wbvwEOJjydA56u4LDUVpT097r4d0HQIdp2pM1ExgBF8lfIv74ldImiIIgsUwUTKQ+fiBzuTEEIKB7HMHbWkYcEE0G/yLtgoBBx5xMFJxNwJV6aeVMayL0JCgcFMxmprf7Jp+JjDgas4RIOxfs398o5m3wE9ycpxEm4JTV9bwnX9FE8BYhBAonq76LNTAfP745NTXnPO2CefaSTaN5d27n5GdluyAwjWZrqmEyvMkImE65ThS4Uq4J++P3zNj5HrM2TRJlDolloiAi/vYzmIs9Cc2tdY8TEP9Qtd79WjpDy6WjYN5R2V/hkNuKan64PKy6VrbzoiUR/JumqphR4zPdYxKCvaVmxKTmzhDmes4H+4foZDJOEQBm4pDV9RzKXfdBczJ0ndAEprTs1T2m8YHQ0t9vSYWwxH/OKFzgyrLhCCb+WsiTtM3BvxFNBps1IU4G04w+0BQ4Z6dvO3LY0+GJ920jXQSRMySWibyYosRckUDsesYVTClUpXsdgBC/XpFix2O1KukpisWdoV74m6ZU0eOaKHhTClYc7M0IH4yMuWy4yxcYb9ntPbx7r0LiHgHbi2XFRWEYgDMmDCKXctd905wK3Q3f9CRovq17jAVulAe03q5APivKX8O5KZvSQONiFVXDaEmG/ppW1f2haco5NAPogPZj3iEvN/piZq3eE2UKiWUiZ2bvGhs5zscfhC7nculyAt2CaadFk6ErDC+0IJg5ccsKK2pl6ZrO0CfRZPBYTWTjmAsRtd8CBv9XNMEOgb97Lj6Kle58qegwDAfhjHPAC1tZ/opoR/DVrlUwsWTiarjA89rk2y+CvQcnL9icCJ3csuy0QrNHjJdHI9G09HrDc8TP65j8Bj6tg89txuTcFOCi2d6l8GcjgRhWZSWInCCxTOTEVbULd3MP5/g48VjdY38EY/8RQj2oOdFwr3QZiqpkBs1VWhh8F9koipZkKLYiJXaHMzEVXphDOt/JQg+8/qxq2lEw+O/bkgw+p7sLxvYryyLjHLEM17c5cbfCKavruRUlGQis1BlNhH6lpbt2EkL8Elzv6z/JC5hLihdxUr6kY+n4lkTwfunPG0zBCYftdctQ3sK87LJtKPi0bkWHOAHOwTwwrYoFL5YauH4WRgLxqKLMIR1EDApdJMSghH2xo7weL65KOCZnpRDsuV7WvU9zcvLr0mU4q1LrlsLBBGEhdpCNosHVdBADi+F1lNDS28FINg1G9pvhR0/D6wN4YcwhiuJVMMy9B69H4Nxdr2nayZl14jvRRPDHgxVryQPb9zcZN4VhwJTGIROGwctd5wquAjcnQ5hK8nsYnoFpJeHvPw73y3/hx5sLQIx1xvL3MaaJn/Wqmd2iydABOCl/Uru6qNR0jXULtoKDGZvQcsojXyjZfiYZms2Ehun5unSv7cGJSbjRNzF+UV1smO4iiL7hmGyWIPoDZt4XwwHLxTqnfKgQt6xQ2SXZuGKTCQfiH+BjPWkag2CfRpNBB22czI2IP74OhiczBqUkiHpDMrJEJi7YkXmr/i1NQ4Ge9ufNiSDeS4YA114crr0fS9NIPoTzacg1fcH2t9WMHTum0LCdgRHsCbhPjpSWaVyg3OYZOnH08Gqtp2pdhm/43dtvr8dqnvLHhhL2t+3Jues1aRoH9IkgZnPLh14k+BkYd/0Zrk0nVXHtUHsyJ7Uun2LKvU84H1pZJvpkSl3MGwnE/gjNG+HlJKHcioOCFUIZgQHhI9k0Ds7GluWjQQfkWU57aGUZcEooiiXX0y3auWnMkdy87JSP9eIm5ghlRBPclBLNgrM1smk+QsvAF+OU1eWvqHdVuV9u8scPljZBbAKJZeJbNI2Pjd3NxR+Hsehc6XIOnF8U9semS8t0hDl5jZVZdeNGynY5Yf/+ptflmJhls4Br2hkThjyLkjgB+ECmiGXAksWDiD9+IVc8GLK3u+5xFGMVzh5v8rc7b9wjTIfEMrEJYd+iel7DX+acOXWGPYJzfl8kELujkOIe+cKFOeVzVaGYNWiWEtuvLAsXiWW4ph1xDkDU2/56yhfBmVmTZK88mkKjb+FoDAuCbwT3Qzi58IdX4cofI/7YjVh2XPoIgsQy8T+afO0/4tyzBEagnaTLwfAZVaL6tXBdzC8dpgCDmykbQzxcmC70S4Dt+xt3L4VhgOBxhFjmBRYlsTOcKSaJWj5KNgwHQxdcijcFX4YZ8fOlgfOLJ/lqH8ZJgPQQFQ6JZSKbrijij4fhiCsD5bMrmLPx3M1fxE2KMiWT4cAfNaUz5cJj6kpQibC/uHF3V/zKMuCQc1B4URLbIsxZAYYbz/ANw7JA1S+gZ8VKroZl8LERR8Ek4KVZ9W2OyQJFmAeJ5QoHd6s3+doXQm8aBbMcrwesMngjfMY/N02cv4XuMga5Cc+sHd8klkuAcLtJLDskZlmU48oyZy7ZNJpx8mgIkd1j243zscfgHc8Bs5zDFXbzuFwvhP1xx9QXIMyBxHIFM8u/YPuxY8c8C81KqGR0kuKtSRi527lpj91wNcWU+DyNl2VOR9v3Nxs2CgrDcMjKMjegKIndgAlAWjaNZpcZO99jSF/VFIifwKp5Er6Bw6Sr3BkJV9qDkUDMSZVrCYMhsVyhQIe3n4dXvQzNSqqRv4PC2VP46BAfIUpf4bi8e8qW4YBStmT3usXYXtyoXi+tLDtkgx8TxhUlsQsm3vfe7UYO3Vu2C+KS8TdVRQLx38BJ/yuYW+reigHGC349jB1343mQPqKCILFcgYT98dPhi8cKbtvonooCO70543z8cXyUKH0FIRQ+STYNR/DyEssyZtz2YjmzejWJZe6QMAxefivLXJiSilJH8O/LVt40BdrGjajZ5gVoXgqvsjvvucPPgPPwZNi36DvSQVQIJJYrCIyxjQTi18AQcw+YTk7vYwSHsmqeavLHTpR23sB5NK16GO9V18mmKeDqyOzaRRMbA7HD8RzgKxxoP6yxLrarOSmTrnbEAFs1tIfCMByysgwXlCXXFO7raJyweKfZ9W2+cKCtNlK/eAes6id/bCig/1fLpuHABLygvi67uCKyVQUNqZJZBhzIFc8rjYFFdD4qCCp3XSFcMn7BiBE1VfdB8wTdQ0gEE+J3a7s/ufLGty7qkb5BuTIQ+14V4+9J03DWdvWMxGph0iwaXNltql90sGDKj2FAPgRctfDqTxT3wjl5HY5Pg25qb05OxnZRYNjLOB83JSc1YFi5axRBY31jTFrVFzOjidAN0igaE8tdvwrncx/ZLgpTy10b+D6/Ca6igjg8EaT4ITA6+uEc4xOozYU5xhb/CzqPl+F3nma93Q+0LDvtC/1HhYN7KhTOcB+JGWisW3w3+mboQ2kPyKwJdw33eEfcDJ/8NOkiNmWDJsSZLclQTNpEGUMryxUArhaCUMZHaCSUvw3uE7oYHzHiICl9g1IleINsmkH6d2+fasjKMhZmifjjlzb62t9j3PUMCOVLwI25pwdaPfbCOdkfXrM4d70WCcQ7w4H2GVgCXf48b0az1Y7oa1az0RSG4ZjUccatLONkDiYfUyP+2AsKc70Ff/k6cJ8A/8D2cOzr38GV5XHQeZyqMH674q35CP7bWJMvdoD+4wIR6ZWyZQYKG8LPkO0BafTF9vJUjXidhPKADFU4b4PvfY5ZqUkJ+0BiucwJ++NHuNwcy49O0D1EPwTwUSM+cpR2v8iOcYZumcInmqYV9cgH32MkEDutilW/DQPeb+ANF1NoppYz5Y5xbr407IsdL315sXriaEcMJou1UMWHYcCF54xzIIwRy43+2DHj6vky+GMLs5PEwsAJZhBuu+dhcvnwLH9svPTnRVrJfCCb5sDZDJnysk9kv3G5Cz4HmLvqXmIAcLHlF031be1WVIwlSgeJ5TImW6efs0egWY6lk42Hs2EYzw3n7U/4CFJ6v8Ws2vZD4HcLGgxzpKgBs2l8bGyTr/2v8IH+BKaRmzh34wr/G5yf2/IdGIZu2OCkvqbCV5eFMz4/zOBkqyCyT10CsTtcnP/d4Pv5WA/nqUKKIV2bOBVDVooO5xiAXWbXTegzdln2Gw/Cib0ezHLM824eMFGqYtX/nF0XMyvvPlFiSCyXIRh3GQ7Eb4EBAOv0U337fOHsNHwEiY8ipWcTXC5xhWyaghDsP7KZN7iipdRknySYF3LD2TlVovrZq+piOVcFG60OdcTKssQZG9zM2nAieNmHYaCoAXHzIvwJs54Q6cWQ6tvuKyDV2L/k0RQUzq+Sza/Bzb3QbyShWdCTIyKL3+3mr8AE7CBpE2UEieUy44o9Fm051jfmURhFzpcuojB2xUeR+Ejym6tDuCMeBlhzqzlx8bZs5QVmt/Bw/k9ofk/3mAhne3rd/J+zJizeVnoGZIO62kliubJDMXh5xyzjHg4QNRhmgJtczYXzaSOqt3lo5o6xaukZHMHekC1z4Hz/ryrSYeabSCAe5Ux5DMyc7mViQLaCE/wE7vGQNlEmkFguIzCt0ZAqD64qHqp7HAEOzJiWyI54oeO7Hh9N4iQEHW6X0goHk4UfXy4bOYMrZW6PBwc8K4sF7OKpcj86e9fYSGn3i3v0aArDcAhcOGaykPc1FZ543zaKm+N9UlSO9bzg7IiaMbwt50JIXOR9/+cL52weZvQ50DcR8+2H4WVWme0iEXdqGTFRMIbjmlPw4h6PSCB2vSHFrwhbQGK5TIgE2n/Imet56Jh3li4nsEpo4sRoIoiVpX4Cr66s134cP2SIJxkOxGfDMHOc9JmGqqp5rSzhY163m7dDsxRFZia6h/O7BovNHKauc87KsnPEojlwh8QsowzNAwxP494hbfAfFbPZtVBO2M3H5sj2gGiML5VNM6mvYvwNzswrrFQkX8BFGIwmQme3dIaWr+v6GNNd/l7/kVPgl4/z8Ycv3/meUdJBOBgSyw4nu3vZH2+E1gNg9rspzYYkVK13n+ZU6CE0QDDfkhYCy0fbdZV5OxhkcVXZbDa+J5S8xPLwmq2b4LCvbpWEkxt9i8+S7T7hvcOd09c4JwzBJMozZnls/RiM1S1ZPCkI09lN9W2DilOupV+RTbOxa9nmR9M9mfqWRPB+aTPMgQ9jxE9hJovZiuy6qNIXRw8dMezFQrOjEPaBxLKDwTi4Rl/7vdALt4DpnO9SsNs/XLP+wNbUtE2KesxLht5amVp1ABMCRWllru4JkVzcGcq5KMZVtQt3g0H4Wxt2rIYz5dpG38LR0vwWPdoG56wsV3w2jPILw7iqfvEucJHipLKUKIrLdetgFTKbU1M/FYz9W5qVRA90gDNbUkuPnbd8ykfStwnRRGi+0NKYy7qgfR0lgbPxHs5faKyPHy09hAMhsexQcGNVzRj+NCiQ6dLlBDYKwc6NJoPn3vneGRulbxNu0c5NR5OhJk0TR8CAUXBWCKciOM9rVcnr9kbwoFslZQsX91wq299iyHCvk8RyZYdhOGWykEeeZa/ivhoOdijxP3FS/YRTZLtfuBBYRKpyEKwTRPC+WOFS064e8PqDyURHZp3Ayo1/1j2OYLTLxR7CAlHSJhwGiWUHEqmL7eupcqOoKuWj9/wQ7D2VpQ9sTgZvl54BaUmFnulas97HhFgoXRUB19hzsjko2UwUnE2TZunh/KL+0mTxTMZJfU1lrywLx+RZzkksR+oX7wC/aZ9FBa4M+iRIY+Ip2Sx3BFxvv/1w7fp9UQRL36DMfSe0piXVEIT/Gs+lWWX0jcYN1+FvMLd3MdVQidJAYtlhRHzxU5ib4w5mJ6X5eUgVvXu3JqYmpJ0TN7x3xpfRZGi6YBqWXF2je8sabWNvOudB0uN1nwoHO+XRHjNiyDZ9Fjzo1TzOWVmGC062KhPumJjlnMYvobgwztVOWQn2iPjbBqwUKFReCWL5Y7jVjoU+/pL+njQOBFY5jSaD16oqOwru2U+l2wHwGePc/IkrA/duJR2EAyCx7BCwRGnEH2uBb2w+mLnn7CwtKnRikZbU0hNbU9NWS1/eNCca7lV7Mn4hcl91dSid170x9XPZHhTBRZ/CtKQo7CTZ2gQ+xEEry7yywzAcU+4av6kc4Iz/WDZtg+DKgO+ptTP0DhxMLU5SSgQTD2zcmK6Hvv0f0lUwrR3Bp9lGsRf8zSXS5QQOqmLVL+t5+wknQGLZAWDp5ab6iQ8wzhvBdMoK3UpV046BmX/zYDFoudC6fMq/3+4Qh0Evi5t00rq3zBDi77I1KBfVxYaBCLBjGM7h8rgJXs3tmJVlEIuVvbLsnM8/6PjVNHH+FtBj+qVpG7jgR8hmvwgh/iqb5cQGponzmxOhk/NZGBiM6JuhDz9PrT4Mmv+nexzBjm6Xa0nE3x6UNmFjSCzbnEbfwp09VSOeB6H8Q+myPdkE8mpmr9ZUw+PSZQiLtZAK4rtVVVVMv+Sc3dA5ogmW8+A4gmt7wMGjW7Zim6bxsbGy/TVpB4lloMLFsjNilqGfGfSaEt5qXLmz3zjHWe1gWTHglx6UjbJAMPFKb7o3EE2F/ihdhpLdHJ4IXiY0bQqY63Sv7RnKuNIeCcR+MViueqK0kFi2MY318UNdihcrF5lfltU4fo8J5KMdUz6QtuG0dkx+pYd1B6BpSqdbEgT7dG7nspyrVEHHupts2g6lin/rvXFVdUxfAyNWRYdhOKWCH3xPg4oLF+PjZNNuePeZMG7AsvSfd6x6Fg+65WhUJkTr56nVk65ZOs30RY7mVENbWlX3g6a5ZcONAy/lOY2+tkUXbH9bjfQRNoPEsk1pCsTPd7nYo9C0snxxMXThRjxMHI8J5KXPNK5NnLoB/q3zNSEwRnal7nUugotYfuEqvN+cxqUGPsu33ptHczlp1cSUlVWhgQx1AmW0wU8IsYVs2g6v2zXge8OVUvgAMWk6Erjg/60JdhimA81+HouY1zH5jXTP2v0EE23SZXs445PHjh3zz2z2FsJ2kFi2GViSNRKI3wxfzC1g2vExe1+sEEzdDzfiSdsyWpKhv4rejT7oloveKFJKhKrllSIPlKdtN3kK3sd785q6smx0RpDKDsMwKBsIPlbecuwYLGNvCrmEYcCvDJUN2yGYa9D3pjG+QDYdBwjVe9V1wt+SDJZkY/a85Weta06EpsAbuQxMp+xzCTCX++UmXwwLrxA2gsSyjZhZFxsztn7MI9C8UPc4gj+v7erZpzkxeam0Lad52Skft6QmHwvNS+CVdwqiUoOrL3OXTn1emrli25KvnPENsvk1GWHqynJtOBCbj5sepV0slV6UxF/s6tblO98zqtHXdj986b+WLsOBvz34NcVZt2zZDq4N/t7mdjT8Ew7v6pZj+JIJbToI1dMwH7L0lYxoMvh/mqri5r8PdY/t2RrmmU9F/O1nSJuwASSWbUJTXWxCjZu/BJ17n9kEbEgGVN5VmBj+xremr5W+kpHNuZkI/lYwFSs75Zzc3ibcie9ftnNCCM22sYxcFV/I5te4tV4zxTIK9FNHw/2D95F05Q3GC0YCsd9Bc7zuqVA4q2Mud0c40I55vPOm0Rfba+iIYa/Bd/Ij6TKLwccvwVbJlu1IM3XQdJp6vyByKuRkB+DNPpPJCF802WCrYlItHZOXCC29FzSxRoETqGJcuTvij103RYnZKUd4xUJi2QY0BeInKG6O5U131T02R7BPMRE8JoTPV+SZDa5wr+36eF94kzeA6YTH6RneLe6U7dzR+ArZsh0bNmz41nvr8Xqt6GsmwH30ciErMnAP7jd27JgEKMWLwDRV2BuF4KbGQI/iTJkfDsTbs+nXciTij1/oUvgSOIM7S5eZDPo9aZpts+ao3T2fvSfbA9KbYXfDwe5hBGkYF5reTokj5naG/iN9tqI5NfXTJamlR0HzWnjZatzqF85/Ps7HH5y9a2yk9BAlgsRyiYHB5Ur4Ev4CzRG6x95gYRCR3hjIJoK3KbjBMJoIzVQ17Qdg2vrRG5zPhzFHqDRzZl3vJ7jT236PmAV7DysvSutr3FraKgGKqZjuhvvqtpk7xgaN687uEfDH5sA9iI+77Zo5oWTAlxZSvDUdYX8cw5z6BXPBw+8shP/gZjD7LHluOGJwsayoGzvhYEdh9FauG6Gv6Qx9Av1EXJr2Q7C3VE0cgGk9Mb2n9NqSJ7WrM9FE8CqmCsxt7JSqsMe6h/MXrqpdaNsMSJUAieUSMWPne4bAgP4n6O6vAdMJ3wMMOOKGzztWHYExwtJnazDPs9bb5YM3fr902Q6NixtlMy/kQIsCz15w8YRsbYrmsfYa5+ycmtH8pVn+WL8hFbPq2/YY6xuDOcx/AaadyobbjW05Zw/BpOIPVwbu/damtNn+WJ3HO+IV+J2p0mUNfPB+U/ZVtkshBn1S3/dJP2iaik/K7Mgfe3j3Xq2p0GvSdgTRjtCfe9O9TgrZ28Pr8b4IE9JBi9kQ5kBiuQSEJ963zbYjhz0Nnf1p0mV31jGNTcHVWivT/xhBy7LTvmhOBIOCaWeDabdE9cnWROhJ2S4E200CVNH3e1KFZSvL/4OzOg/nr4QD8U1EnF46Pn6px+XCAX5v3UsMAodJxQVVrDoR8bftL30s7Iud6eb8RfhpKeK8c7qmhMg+ubMVmqblVZ0Pc8vbrNz/Skzbiek7MY2n9DkKzPm8cuWqAzBrh3TZnTEwIX0kEohfLG3CQkgsW0ykPr438w55GXp5TJruBJZjgvdoKtgubUfSnGi4U82IPQVWF7QJIOCvl82CULXexXCwTSgGnNv/vtvBHpPmJrg9JcuzPBz+4YW4Kpp9mjNxwY5NvomPg8z6DfzMtun3bMxujLueCwdizZFA7A6u8LvAV6pCCjldUxkm7oEDXJ624f15ncvzniQLoc2TzVLz996MqMe0ndJ2LLf899wuzNoBV8dPwTS9PoAB4BOwG0Ew3zqlLubVXYQVkFi2EBhcpjAXewZ6+O2ly9YIwRatzoj9MMG7dDma1s7QO8+nlh4EH+xXYGZ0b8l49/nU8kWyXRCtqWmrhRD2qWIoxK/7jVnUtNL2NZxfsN3IYa8wb1UKDEwjRRSOmzPeBOdxhrRLRU7X1Lxk6C3oy+xUOvqG/AoQ6cztnPJ3OLyqWyUBJ+aXtKQajsc4at1VHkSTwd/DF3IINE2rPGsw5+3m5o9esccipxQtczwkli1Af+wba4HBBdPpOKGcZS+8LmlOBqfd1Blar7vKg+wGj2ToaqZCxyhYTrvRzUBjYi6+F2kWTFpluNpU8tR9wPvdq/svP64KpVQry98Ey8aXbFc5Z8LQECaYKM2Hg23zbVtAzteUxtO/hEPJN58Jxv7z4Zr1BU1wMfOQJkRUmlaTzKTT+2B6TrtlQDKKlkTwpY0b03tCEyvn2h64+A+pGuJ5JexbVC9dhImQWDYZLJTQ6JsYZ5w3gmkHwTAYH8KQchh2itIuS6IdwefXdvcEhGB/ki4r+dcXqdWG/LtypzxeWyUFRvGfXv9+qN+QEF7qleVSI9gdKztX3yotQ8DH4KqqHgpNR2y4NYF/y+OgtCamJmB2gZk6SgpMcH5253tnFFw4aW7H5ActDiXT4F3fsLbr4/3nLp26TPrKluvemPr5ipQ4DprN8LJ96lEQFDtx7lnS5Gs3O6d5xUNi2UQaJyzeabSbL7EgOb8xCPZED+veE4Wk9JQ1WEylORk8Q2jaFDAHLRBgGBqLGLlRsrVj6R/g8Dfdsh7BxM3NqdBD0uwT1ZNBYVOy91hCNDhBV0WTwXPM2ByLG7+YmsH9DyndUzH8ZW1XDz42z5kevhEnlSWrNArXwe3Fxvniqi5MTK+Sptl8CBPxo3Fjd65p7soBDCWLJoIROM8ngmnbojZfw9kwRVHiEX+8EUvMSy9hMBxmurJJGEmTL3YIXLcxaDohpgj0jrhmRQcL2z1Ppllky/u63Ljaiyt1ZpJoSS3du5CYxYFo9C0c7VK8uFt+ou6xCvHUigw7ZnFnCEN3BgTDkZrqJ17NOI+AWQmd+gamitMwTZW0TQOfYI12sQVwbn8oXeUKrnTOaUlNjhYSDtAUaBunMNcSaFrbLwvx4odrNxxWzKryN4kE4jjxPF63jAdObKw7I86/vjNkf7FoItCv7gz9Ko7jAd1jb0DOLepeLWYM9JSPKAwSyyYQ8cXOYwrHsrlO2K36pSbEGeWws7lYdDFX+3OQcRgXaMp3p2raUZj/WZqGgikJuXcIFouxpLgG9BwvZHrW/mDe8rPySskX8cdPgnOMExNHFOIpkI9UTZxoZf5ZLIs7zsd/Dc1LdU/ZsQaU8qktiWBRTyiyGYlcDO9Bq+LXU6rWexhuyJV20TT5Fu2uKB7MEezRPYaxTjDtUsweJO2KB7PobDdi2O+gzzpHuuzOq6xb/KiQYldE/5BYNpDDlTnuSfUTr2ecOyUPYkrNiBBmiZA2AYTrYn7u5vdBc4LuMQbBxAPNidDJ0jSFpvGxsUo1+ytcg1/nwjUFIR5c+fnqqZh6SXryQg72uOK6u+4pK5Jp0fPDecnp/5W2pUQC8QvggJP1ciq0slxj6skticmGlHnHTVFc8TwMze10j2k8vWHN+pP7qmpZLBF/7Dq4z38uzaLByW9azZx2TceUd6WL+AZhf/wczrP31RDdY2s+hokl3C9B26RKdToUs2wQM+tiYybV1z7iFKEMHePdXavEASSUv01zZyi5cuUqrO70e3gZNZvcqGnpmbJtGi1vhVau7f4EQ0n+D15mzITT8Gdnt3Qs+1GhQhlpSU19c21XD8ba2q5gRDEIwf66OiMOLpVQRqKJ4C2CaSdA0ynlfAcEJ5lwrRxglFBGmlNTO0TvRrzH+8wLbgAaXAy/XpERPzBDKCNru3vxCZgRmzsz8F5/9Xxq6fdJKPdPczJ4uxDqJLggS5ZFKQ+2AXH3dDjQfqq0iSKhlWUDwLK5HpcLB30n1G7HjRqX4oCqm8RANPnaj1O4cifj7DvSVRBwm82BzhbTV1lGpD5+IHMxzGqyl+4pEsGeFFy9pDkx2bBNUrghpcnXFoGu6Go0da9TETe0pJZdYXQ8eqE01cUmKG6OIQvf0z2Oo6j45FzA0KvG+toZnLNWMMfq3qJJwru9uCUZNL3iXsQXb4C7pk2a+QPCTxPi1JZU6AXpIQYBF8Zq3BzDyEyLGTeYa1tSS2fbpV9yKiSWiyTsjx8LHS3mTy5Z/tY8eJ+pLBTtCJYysb3jCPsWfYcrnjugWWjnuHxt18d7lmJHOYrR2b724xXBLgXBj8U48hWkacHEQ1xov4kmJz8rfYbTFIifAG8My8464T7anAyMQhe1JIKGpoYzgmxYTg1/AJoH6h7H8KXQxKmDZVkxilkT7hru8Y74Cdwj+GSw0NCMV2E0vf7tlGi3cqN0JBDHgiv4JCEv4L3enelZe3G+ew4IfZLVVF/bCNcLLoC4dK+t+dvarp5TMAOUtIk8IbFcBJFA7HI4hddC0wE3i/iH1tt9Ssuy076QjooDheOsuvtGFbLRJrsCWt+Og+l1YOZTWAZXxw6JJkL/lHbJmOVfsL1HeH8kFI4pt/bmjH0XjpuL5zSuNgkuXoGe4enejZm/YO5R+TNTkZkKMI7Z0Fhxk/lS1bQGszZtGoG+QWnonYzzadJld5b1pntPvmbptLelbRkogmb5Jh6qMP4jLtihcL/jtdhf/44ZB16CMfRpNZOJlSoPsczkg097ct0wuwp6pQuiqWC7tPNidu2iiW63u2lJx7LTjSis5GQa6+NHuxQWh+tkmHTZlQwT2jnRZAOWficKgMRyETT6Y8e4GL8bbpSiHtFbwNK1XR/vXUm5Mvsi+31xfo9g2szmRAOuYuZNdmMa99wH3zlWehoUuLt+15wI2jKOHUXUd4YO3QrUcrajV7i6buXStZ+YkQ84Vy4Zv2DE8BrvPY7ITY6PsFXxw5bO0HLpsS042Wusb7+ac/YLMO2btk+IeLp33Vl2We28ZPxNVcO8W++iuLQtNcF1QcSVdaI388G8N9/8j10ebYcD7TM4U/Dp18AI9kSa9ZxZSEz9zB1j1TVjssW1roSXF/PTN6caCg8BcTj4NMJdNeK3cDOdKV22BMagf3OVnVIp9RPMgsRyDjRNnL9Ffyuy2Uf03IOC+RjpsiuvpYU4ZV4y9Ja0K45IIP4POBytW+Lx3nT6wkJWr6bUxbzj3Bw31+BO9IHCGlasXLkqUMxGuErECXHMgoklooudjBsqpcsRRHzxU+CMoqiq0j22AYu3RFo6GuaWazlls4n4Y5gFp7882736+V3660IEftgXO4orHDc876p7siLspeZE0NysOzYl4m/bn3EXLrjsontsy+INa9ZfMNAm03AgfovoEhGn9WVWQ2J5AOTmj19wLvaJJkL9xqvKR/QzQTC3gGnn3MobmCYuj6ZCf5R2xRAOtNVy5sK8pN9cVdsIPX7LClVcm0tRjc1prI8fqrjYPTKcYXMyTKgHR5OTX5Q2kScwQB8PAzQOSKN0j224b23Xx2c79UlNU33bJMWVDXcxakNbsaxWhZjemgw9Im2iAK6qi23tdXOs5LiV7vma5SIjTsEsP9LOmSsD927lZUOu54z3nVVBZZMqacUym8u8ns+GUQQn8nZOzbhBMO3iwfJly2JWX4AK/JCrbAqtPvePLVdt7ACuJjf5Jj7MszcF31e6+wRXQqLJ4K+FUA8A8WXnlduhTOG3RgLx+/HzSV9FwJlyWfawKUPAEx3n5okmf/xg6cuZ1o7g011r1vtgvrlIur4GfC0klIsDN3f1pnvx3itJLGhfwKByf0uq4TRHhzQpCt77RhezKJR0RlUPI6FcPNd0hj6BSccZ0PxqBQyO4qauVWLvfIUyLgBhXuEqVv1Gv0IZEC6G/WpF0Dhh8U7jfPxpHDPAtK9QFuz1tBB75VZYxo2ZkkDmsO2Ziz0F2sApNSIsh1aW+0BWeMISlzvqHsy3Jna+NhH6lzT7BWbiQ6vYkN/CqZ0hXXblI6GJM0GQmJVn1Dbg6gh0+u9Dc6Bk8gL+744uVVxVSIlXGFhOhx4HE9aPgD/17IoUO7xSS4cbTTgQvwo683nSLDX4CLt1RUr80mnfr74qxpphaLwKzM0njqUkydTMidGOKR9ImyiCbLESxk/ThDYDJnZYeCUvMOUgd/FboD/LZQFBhbFxt1zGRicT8bdPY1z5AzTtnK0HxjBx/QqVNeX6pBT61tnQEWDaxP8hxMLVKjvvps7QeukhAFpZ3oxs9SsXw8wFXwtlxKsJTGA/KNcmTt0QTYTOhituKpimJKM3iG25wh+JBGLX4yYW6StLvKL6QjgMVnWJw/+dU+PmbxSSyL05GfyT2pPxQUfzIFPVU0koFw9WxAz7Y7+3kVBGsM8Mj/Pxh6/YY9GWusv+4N6KcT72GAjlWWDaSSgjfuZyv5yNAyWKBsWS1i3q8hXKuOEXxr+o4uaJHIUy4qpijqlYmze44TgciM0HobwATPsKZcE+VYU4LpoMXZFnSOHe8vg/OJ822s1fwvoR0kMAtLIsuWD722rGbjnmFhhGTpOuTYAp23XNiRDuAs4ZfGzjqnJj2WS75zhNahlxihN29edLNm3WyGG4qrx5HN8giMfVDPsJVTgsDZfvfM+ooSOH4U77o3SPLflAY6zB7iVlZYzyYmiaXdq5WDYyoc2IJhswbz1hIY2+9iNdioIb+AoprLUus07sMPedUFlUjPyKSCB2kGB8Pswsd5IueyLYI0Kkz2xOTf1UenIGJkf/gcMOuvUt1jGNnV1oisFyg1aWgca62K5jx455oT+hjHDGc1pZ/iaty6f8e0lqKea0bYaXnVca/YqbvxrxxS7CWDXpKwu2HTEMV4nzFMoIP9Ll5p0RfzyM2S+kk7AAvB9BKGNFMTsLZWQH6ECfgWsEn1zYDryXMRc8COWnwLS7UEaGMK7cF/HH5pRbP2RXMEQNV05BKGM4XqEVaIe7hvNzZNvx4BMtvAZhDHja5kK5F5TyzJaOhuMKEcr4tAkO/QllZDgoxDYQ1L+5QLnNLnscSkbFryxH6mMnMxe/C5qDPWJZ25JaOrrQvJoRf9v3ZaqZgS5OO/C3HtZ99rWJUz+TtmPBAbfJ194JzYm6p2CWa4JdYEX52kqnyRc7BL62ODQdtQFVMHHv5ytXn2+XNIHZinRVIzBFXIPucRztK1euOpPSLpoD9o2NvsVncaZgkaUxurco3l+SWrqr04uUXFW/eBevAuM05/YOCRLsLcHU6c3Jya9LT97IqqlY/TEX/pnuyUyZt3zKR9KuOCp2ZTk7ewzErwGhjANzLrFII66s3WO8bOcNlgruygg/TE3uly67ckKVqO7AMt7Sdiyz6tt+AIdihTIyQeHZFcTbZtbFjBhYiD7A3fcwhuMKl+MytWDGgLFjx7yEVQilq2RgmkSPd8Qr0HSqUEYa4Hw+G9k95oQVcUeBhZWafO1PyiImRvVnO07yTQzKtiMJ+2Jnel3uhAOE8u09vHuvYoQywkUf8cr9c5DH634d06VKu+KoyJXlbCERxYPpvvL84sXp0URovjQKJruJkLHr4ZVP2WSrwZ21v+tazWZd/34Iy7o6DjjP3yhCYhifFVMBkPg2mM+8qX7iNTBIYZEXp7NWY+yslkSwJJPisD82nXOOedSH6h7H86GqiZNaU6HXpE0UCG7kHl69zWzOGW7yNHxTNygJRxYpwVzDiuK5BSa8k6XLrnwJZ/kC0CC4/6BoIoHYQyABj5NmrmTgi25q6Wi4rtKKB1WcWMZ8ugrP5sXdVvfkDpwpw0oXY3oexc1xI0u97rEtSzNCTJ+bDGE4g2PopwiJgdAGQCOQ4QK40/wE3VMWZFM4LelYNtuqx9J6VUmcgPOLpKuc6GJCOz2abMCngEQBhAPth3Gh/AF6w4KfjuaCpqoHtXRMXiJN24NhX1zhf4JBoq/CUrYBOpQlvLf3lOiy6bhZ3RAigTjGORewnyfLnzPrxFnltqlzIComDOPrzS6cPQFm3kJZks9jiwHBzBMfrlm/H9wGN4Fp5xlLrZvzVyL++KVO2nTDhetSPOiWGdAGwGKJTFywIwhlTNNYTkIZ4bhKPsk38YnwxPu2kT7TiNQv3mE3N3+2TIUyUsO40o73Gm38yx8QRTdzpjxhtlBG4PtxRJES3LAW8cda4HJ6wuZCWYWJ96+eTy071FChDH0vHAoVysjJ7uH81bBvkd0X+wyjIlaWDdzs0r0ytWrkLdq5aWkbggy0x2o7dik/2x+Pit6NZzYvO+VjaduSHIuQGIi4IZoIzZQGkQN6Tl3XAzCA447scuZjTbApZm0ObayPH+1yMUxP6Zicz8UAo9WCj9asP/vO987YKF3EIEQCsT/CUH+uNM3G9kVKrqpduJvH47mvkAxXFvMBE+qpuN9J2oYR8bcHYQKKhdeKpQvuSgwNKTo81e6U/cry7NpFEw3c7FK95cTRRmwY24SWRPBv6Z6MH0aCJ6XLrhzNvUNSTf7YidK2JTkWITEOoVEeyjzAuFrGXU9VgFBGtsGnWdmnWgavimLKOhDKWHiiIoQyAidw+nYjhj4l014ROaCyDFaeswqXV7BLZNt24CZir8ebsL1QFiKuar0+M4QyIrhhn78G7so/RfyxP5R7cbOyFstYotLt9rxo5OMn4cqtkl++YEqWlo6lR8G/MBtMQ1euDWaswvlf8ObAQi7SZxuwCAnn7CfStIIEdGgvyjYxCJFAPMo5x82R1k1mSo8HBpTrG+vbz5a2QYjD4X9ceruC4Hx/uUGbyIHWxNQEiC/L+ii4v2fM3jVmq2p3TRPnbwF9z/0wNtwGpp03v3YxTZwfTYZCralpq6XPcLjghoWUZuH8ghE12/xThneUJWUpljGGNBKI/S5bopKzYdJtCApXjL3IvgHmcI4mQvNUVZ0Epr03jsHNMXbsmNfC/rY9pccWFF6EpDA0oVm5auNoMOsFHMLwqsy4U25wuVzOy/7JYL8INkK2iBwQjFvZTw13D7Ms7GNQwv74EYq3JgXNk3WPbUmlVXXvaCqE2WxMI/uEi7O9pGkkezNv1WvhQDumbC07yq6zneVfsP1ubv40jCRmbXYx/fFNa8fkV9Z29eyFhQ6ky67szrnrhYg/fqUUQiUFOwHOGW7ss4o1ad6DmRyIHGiYONEtmxUJB8Uim4YA/UNlTjoQzir6WsqXj9aux9LxX+iW+cCV+TOsZSDNkpBdNPPHroMx4VEw7ZyvG7Pn/HZt18f7zeuY/Ib0mcZs3yKs1DhKtwxnC86Uh2GC8ks7aAIjKasPg/XtPbzqdRhBDpAuM6jFDWSybRo3vjV9bXMidJpgGpbgXqt7bYkXBq5rmuprHyt1AYFG32LMqWx4THn/iPnXJk7dIA1iELZfW/KQgXflsSQYLW4x5YZsWo8QL6qahuXIV+oOyyGxnAfZDZFCYKVaS4AL87sH+mpD0rQcTM06zs1fglsEc7fbWees1Bg7MZoMXXLjWxf1SJ9pYJiiIlw3StMsFOiZrm7yTXwYw1+kz/GUhVjGFcWIP97oUpRHwDQ7o4SnSlQ/3jQ+ZknmCix+oWYErjLjJkX7wtnhrJp3NPljJesgYUZ7uWxagdAyjEIw8sAzdF0JBY64eklq6e4lfVpjdNiEECXqv8Xjq1V2VGuq4fG0EAcLxv4jf2AlJJbzpFdTb4EDaDOrEFb2x1mkFrhQcXMcL/2617Y8Jno3+nCDv7RNBTfgbTdyaBwGymOky2T4DxRvzWuR+rhpoatW4nixfPnO94xqqm/7C1wALWBas3LFWZ1SzZ+4Yo9FluxCx8IXn6dWT4LBcR6YFnZ2eTMGppTtkUDsjovqYobGig8GFiGBA650WQIIhGcxV7Y0iRxQPENKIXA0+LJ+Gk2EfoUFQlpTy84AwXyz/JmlcKPDJjDoyGLg3D2wtuuTE27qDK1He14y9FZG9OAeC9MfH2+G4zc2Gp0dZTCu6ZjyLnyDWE7eEjDjBIwFB0nTdHABS2oBvL/tXB03DTfSVS2ppcdYlYYVQ2KGV2/TBt9KvhX7imVHuFP/GdGrFjsaR4vlxsCiwNARw16DQeOH0mUdIJirhrgfxhzO0mMqmNs5mgzNVplAQfiR7rUrfMZoN389UhfbVzpMx/wiJJsCwsfyVeWmQNs4TKYvTcfBN3qsFsu9MKk5JZoM/l7a2U20zYnQRXLiaSnC+LAJS8WWEOxPz6eWNWz+uHhecvp/N25Mfx+aL+seS3DsyvLMHWPVIB5ubapffLp0WYewdKMfXvOWFCnBTWVKDU+VRAvkxzu4gR/6pGuxL5I+U8HY4Un1tXdC71OqlK+YUu4PEX/8T3bMoJUrjhXLTb74WS7mWQLDxc7SZTk4c/ZUjfgrxgFJl+m0JkJPal0CHy9Z8uimCHZjbv5PuEHCU5SYqatA2Rhyzk6RphV8siLD/izblgETgtu39I15rtG3sGTXfDFwd4+VAmeDKsRJzYlgnynGcOIJQnoWNOFgEYaHTVi5wU/c1Nqx9Kz+yndf98bUz1dnxBHwe49Ll9k4Uixj3v+aMRwnFecxrvxM91rHig7xNyvDZuACPemq+sW7SNNwcOyFicdvOFP+Dqbp1TKLASeb6Z61e+IGfumyhEbfxF/DF4F7n0oLvIexY8e80FgX21V6HIXjxHL25vDHb1OUbMW7at1bUg7dbuSwP1m587PlrdDKllTDiUwT2NnauZKVB26Q6Dgfe3J2Xcy0kqJWFyERTNyxuDPUK01LCNfF/Jyzg2Hw2c+leF+PBGJT5I8cA3e5rRI4qzRNHNWaDOEehn4BIX0NHPDasWSFx/ANecKy1HHN0UToZ4OthGFoBoZogBgzojLYwAjnieWIL3ae2+NBoYwhY8hekfr4gbJtCYu1EJZPNjU12Wa4vIrrYtk2lNn+WN12I4bh+bT0qWIBrIUe5tTmZPCMecvPWid9lhD2xy6BfsdOJcjrXW7+aqQ+Zvc0ft/CUWIZV9RAmD4Pt8U50mUXGhrra6+VbUvQQA1EU6GbhJbeD0ybx87y77vdPBUOxKdKh2GUoAiJqmaYlYNNFu5m31yFGgmeRThpvDJwr50T7G9Cj8tlhcD5SDD1kJZU6AVpD0g0EbxFCIGrLqYXAhIwasmmMXDTV5YFCN+fwzmKSHtQMETj7ZSA+1xg8QfzcFDqOCzQEQ7EFjOF3wrmJo+hhbLJfW0JaZXdAQcLJ/t8Bu4tkkbRZDfxBeIXuzl/Ga6DOum2J9msMb2BaCqIJektBcaHkzjnN0jTToxkLh6H7/CaUqcXzAfHiOWwL3a8S/G+Cs2A7rEXINhm4sqBNC2jOTW1Y+XKVfvATYk7ne3MKBjZF4b98XsuGb/AsIICVhchAfXw0NzOkKW7//WNpHy6NP8HTBqrWPUrYd+ieumxNTydNrtjfLuHiYOaE5OXSjsnmpOhBTD9DELT3Kc0hodhGLxSvSkqXOvnNSeC10s7Z3D1siU1+Xz4vGbGhTtikG0KxPdzD+dYXnmydG0CfIPBWRMWbytNS7imM/QJHKwLI+NsWM2IoYYUKcEy502+9oegienP7FwFVIPrv3VJx7KDW1PT3pM+y8BVdzhg5h+7ajzsu66c5Kt9zCml620vljHeFWYgUa7wB8EcrXttisJ/F/G34UYXS7nlv+d2RZOhn2iaho82LEs8XwgwOJw+oroq0eSLFZ0LuwRFSLAHtHxj35AhbnyS0t/AsAdXPC9F/HEMJ7A1XDF1ZTkhtPTB1yZC/5J2XkQTDQ8KpuFOcRMfkxotbk1LHdcrNG16czJ4u7TzJvvkC+PChbgSTDPiwm0tljEsD+7JK+ELeg7M7+nePvG4q1yWZwqAr8fSfgw66p8Vuzk5Emj/IfR1ndA8VvfYlg+hLzkSrv+m/mL8zQRzG7s5x6wglmakKpBD4Tt9ram+DTPq2Bpbi2VMBTPOxzDu0Cklcr2Mu9pLVZyjJdXwAFMzARiZnpEue8LZzqBzn8UqP8U8hrG+CAl7d17HMqwGZRn6+eGDCeEhcE5vDgfi8UbfQttOKLmimCRwxLOZdeKw5tTUT6WjIJoTDU9pevrBVbrHWAxPHSfMWVkGgRtuTjVgxbeiaU6GrhNMfJ2NxEBsK5b11c+JD8MXjjHxgwpEzvj5mANXmpYwt3Pys3CwMnxvh7H1owrKwY8ZFCKB+M0gV/4CpiX1DYrgL1pvlw/7EmlbCk7SFG/NfGgONEGzG9spLtdTMLm0dOErX2wrliP+tv2VGv4adCVHSpdT2EpUs8WlSvEV7ZjywdspcQQTDOMMLZ/V5gFMftnVB/pqny00u4PFRUhQRNxqVbqfrzigfuKP4LCDbg0MKKcfuxRvwupNQ7nCecYUgaOqvGXuO6E10iyKlkTwJbh3zHlEbXRRkuxXbgJcGPt0SvDPZctIbJlnGavIcsWThJP4A+nKha1G1GzdZ5iGWeDKP7N4dRnmdnlvNMONzWPHjsHsEbhgYOcFs27ccN+Saji5ZdlpJXu621g/cTYc7L7y3heYDOA3MClqsyodb77YUixHfLGLGHfh6mhOIsFucMYnbekbjUVSSgLGDEaTwWamskMEY/+WblsCvd8BKPDC/nheOUetLkICbOzpyVhWLvYrFJ73BiBMAv8MzNIbbVebXzVrZdkZCKNXlmG2KFuViNvqoh4DgU+AIv5Yi0tR/gHm1ro3d6CftnyjX2YDmw//cLa4jBXAuLhPkz9+sDQHRIax/Jy7+YtgTtC9tmWpYOq+uOE+OwkpERjayDn/pTSdSoOnasRLWK5c2rbBVp0t7uyHDmcBxv6C6dW9zgQ6hpmNgdjh0iwJ0Y7g8+q6bE7mxbrHtozgnN0DgnlhrrumrS5CAoNKO+aSlZYlzK5v88FHLCQG3g1npqWpvvbR8MT7bJN71KU4v+paMXBh7PUKo7JtxGIpOJRdbYvrKTJxwY74hIxx3ghmQWNqVkgasI8jH7JPYzhbIE1LgOnNoKvLuOGxyVf7CLy368C0NDylAH7ftUrsm++mYqPB1ViYO2L4RTksSOyhuPhLEX/7NGnbAtuI5Vn+2PgqVv0SdDi2OkFFoCiM31PqGFLsEKOJ4FShibOsXEUoBBDMU2tGDkvBoHGIdPVJCYqQME1Yv7HPrbiKW23i7AjuHZJs9MeOkZ7Swit7ZRkwtL81PAbaYey0004lv55gQA8yb1UCvojiNyzn/xSpaETG8n7txIGKlGD+XU+VuwOaVj41LIQvcEM9jK0/vf79ULf0lQx31QicWJhW/MVycHMiVxZE/LEbp9TFbLFwaguxHPHFGzycY1ySlZu1TAc60O0VxWuLPIfNqdDdGlf3AsH8unTZEjhn34UZ8hP4SLO/uG+ri5AAyVzz9hoF7miGk/HtdHH5s5WL84cjgdj1pe50VJVXdhgGx8vbSCwrSmJLaoYOLdn19FXJavgKsACLMQsinIesTiPX3BlKCsas7NtcHpf7Etn+muxTZTyfLn4/mFvoXrsinmLdwpfdUG8D8Ak2dCyWp621BM4vHufmT5UqacI3KWlni2IIB3F4FxgmYMug7mKBi/hMu6zstSQmr1ihigOYEL8Gs2SxVTngwkeaW/pGL7mqduFu0pelBEVIcFnZ8lVl7q3BdHFGVaiEy5BfDp3OEjNLzw4K1ypaLINWNlQsGx4D7TC8GzaU5HrapGS1sXg8Xtf5sm0Z3OJ0mFyws775xLXRF9urSlS/Bk27C74M3HSRFSl2VPTN0IfSV1Jw0gaDJRbJKue+4EBWzV8P++NHSLsklEwsYyzllvVjnoDvGDMalHWn7+L893hRS7OkYJnmaDJ0hSrEcXDjF5Vqy2wwjs/ryW7++7pio9VFSIA1qzVr4/owtzjcEGZMCPb2utzQ6cSMWLHOH17ZK8swSTU4DMNY8e00XFVVll9PfZSsNhbOz7P6CdCHaza0w8G6/RicDXNx77nZTXyB2CyXwl8A33j5U3si2HtMqAfjxvlsyXCbUD2GYfaL8gm/6J+toLf7h75xvTQbe0silhvr44dyz5AEfPicdsaWAd+rGZPd/GEbWpOhR4RI+6ATwDzWdmYoXCe3YQ5hrGQHbYtzMYr5N3WGLI313tXHT4LDjrplOCM45/fBIHWH1aWy4d+taLEsjBa3hlcEdBaK223Z9TRQyWqD2Xo3t7A0jdyd752xUTBhaaYfwdnPmny1uFg2F8ySpFnNFcHYgrXdPYFocjJm5rAN+JQQJsxY9KdScMGkqqWxvv0BI8un54qlnW22prs/fqXLxR6DD+2IEocGcsWVgZitEoVjEYeWjobjoDuYCWav7rUnoDJ+PGSIZwU0LY1rz6QzlpcRh5vSgo0+fIblpbK1Cg/D4MaGTQisX1nBeNPWZFfJlqwexl8HYWKJiOVMsXyjX1pVcRJgWQ55uHC3h8OhumVTBFuPG+ObE8FTbnxr+lrptQ1exYVFb+yeLcRwoNc7ceiIYa81BhYFpMsSLBPLODNv8rXH4S7BL7gSB82qKn0WbSuyZWkToRtUlt4fOoe3pNuuWJpZRDD2zNylU5dJ0xKkeLVqELG2VHalh2EYvCEPBEdFi2Xm6jX1etqkZDVnBRVOKpB9UaDLtiVc0zHlXejwLK1OanNe7c307okb46VtK7KFpzj/sTQrD7gfXcyzpMkXP0t6TMcSsYwCwD08m+3iZN1TsUyO1MX2lW1b0ZqYmujh3Zgt43bpIhizfFWZK+6LZNMqsqWyI4H4/WanOaz4MAxh+IY8yxY77Eivy2Xa9YTpKfMpWW008MVavrqsWbzRz6bAaRC/XpERk65ZOu1t6bMfLoZFzyp7ssxYtaKwO2FCextu/Jc+0zC9s40EYqdxxYOpaTbJalChcOa2b4WdaxOnbogmg+fCsD4VzC91b4Ui2KdvZwSmMbKMmXWxMXCJWJo/+huc7FK8qVwrbBVGpWfDMHxwq+jBkivmiGUsWV3FqlPwL+RTstpoGq6qi+VdCbAY3ulgD8Hhfd2qSD4WmjgGN8DjRnjpsx3hQPthcLB3CIuVcHbOdiOGLTE7zNU0sXzJ+JuqIv4YzFT5n8A0c0OE0zg24m/bX7ZtSTQRWsx6e/yCiSXSVYGIO6zuMKtd7Gw4lPJe2UHh7EmY4P4CM3JIn3FoFR6GYXR5aoMrAjoNnskYej0VW7LaYLweF7M0jVw2y4NgmIasEnlI6xK+5lToMWnbFi6UsGwSX8HZnlWMv9rkaz9OegzHFLGM5T+H12z9HOP8AukivoFgLkz3Ymuiy6a//3xq2aFMiF+BaZtUORahsnSvpYNGVpxybk3s8MCAAOFzxvnYY0YXSBAVXu7a8PLURotvp6EYVxESx6xJvtpn4B4suGS10XDOz7c6jVyvKu7Eg25VBD1wY17Wkmr4YctboZXSZ1si9fG94b4/XJrEpoxRFOXBSCAeNWOxx/BOIRxo/wHzVr2GOXKli9gMztkJs+rb9pCmbXlSuzoTTYauZkLFm/MD3VsBCPEwThakZQnjatmJoKR2kqYN4Id5qtzJsC92vHQYQGWvLJuQF7myV5YNKp/eFIj/GEtWQ/NA3WMbttnNxUKybQnXdIY+EYJZGn5WQt7IqOp+0WTw/3Cju/TZGxf7uWwRfYOaNjzOxx/GVLO6yxgME8u4czjsj/+SM+VhMG1errLkKG6X61slP+1KNDn5WVXr9YGIjEtXWSMYt36ji8v6DT05MJYrHGbqxpTK5qIis+D8D+PzIle0WHZpxT2pyIYKBuI3w5eC/ZqlmXZyhvOLZcsyOFPLf6OfYLf3sO595nZMTkmP7cFCbnAoVQYMTCuIqVudwtFDhnheNzKrjCGdd9PE+Vs01dc+xDm7GkyjBwSzWAN3zGy4aSwtOPEVIBxOuWT8ghHStD2tqWmro8lQiGkC4+i6dG8ZIth7rR1LMWbRMmb7Y3VwRdh1wwYIsmyp7OekXQSiosWyCXmRndLXmkOR2VVqqrceBwc7hD71C1ww+zXWt1n6lBYXR+BgacpMC1mtCdGAG9lxQ7v0OQLuGYJ7WkpRwEWF3uvMrlXCLwRbJH1OYAfoIJ8xKjVq0Z0txtAo3prX4K4+RrqcwDtpVT0gmgjNg+kSBoSv090WwtmwETVVpSk7XATRVOiPcO72hqZjZuR5cqumXW1Zcn7EzTmmi7P7KuHu8lg4FZ46DmcdsmkUdr9mzEVRi7qeuEg7QiwpLsXy1WUQRWW3ugyf6blMRvhbkqGYdDmGbIlnzs6UppUI+P+zQCvNv/79UHdrR8N08DSB39Ixsgiq4LzdHA7E5hdbsbYosRwJxC9gLvZPaJpVmtcExONdGbHfvI7Jb6DVkgw+J5iG5YV70LYUIc6QLUeB525t18f7wfv/LZjOiPXKjZ6NPWnc4GIZMrfxqbpla4x4mlDhYRiGrwRXtFhWi4xZVjWPI56QYeXAsG+RpRVv13X3zIfrtSRPXU1ABaE85+0OcdjcztB/pM9RNPnaJsFhF92yEMEuR6EsLb2IWTLYCq0fgWm7qob9AffQqVWs+sWmQBs+TSqIgjrvC7a/rSbsj98DTZx9OqfcIoi7Jallx17fGVolPVmaEw1PaUKgYLF2tsT5/rP8sfHSchQ3vnVRTzQZugRO2Ilg2n4XcS4IJtqve2Pq59K0BBf3ljpdXG4IA8SyqOwwDIBWlo1ELe5JxcbeXqeEk3lhXmBpGjks7yw4u0+aTuZ9TVUPaU4Gf5lNjedUBLM8/z6Mhzfj5kdpbkI00fCgYOok+KX3pMsJ1CrM9Up2Q28B5C2WG+tiu44dO+Z5ztnp0uUEejUmzkFxhxkepG8T8NGM0NOkWYqb88my6UhaEsG/id6NPmjaPj/lYHDV2o19ero4e8dMfg2nleWi4QZX8DN+pdpRcF5ckZvOt992ilgG+PkXKLdZGq+qqs7e6CcYi6lab6ClY7Kj6wVg8gS42HEl1zKwxsLnqdWXSbNPmhOTl2rprn3hl5+ULicwAjrNWMQfuw7zqktfTuTV2Ub88ZNc7mzZahRHTuEz+OqPaEmE7pB2v7R2LIvC4e+6ZQ0wejq+vnvzslM+bkktPQZumqvATOtex5GKdgSfl21LGFfPT4CDqVWHjAIGnqLjOyu+3DXjxopbjGKsZIq8nuTCiVNyCm87tn6UpWnkZKYIS/tEg9ggBDu3ORFswI3p0udYmnwTMaWhlUVyvuSqOu0W7dxBx/KWZad9sbJj1THQu90kXU4As3j+fJJv4hMyw0hO5NR54woYKPG58E/8GcxRutcRJDIZsU80EcK46kHBjV29GTEDml/oHkvwY0J82XYseO6iyeC1qqpibNU7utc5aHpIkdXYMV1cn3AmKAyjSOAcUhiGkRgz+XLM6rLgiuX9hWCa01aXE2kh9mpOBm+XtvMR7FjZsgahXRrtmJJzXQUU1aCxfiYzZTmooA3/PvcOeS3ib/u+dAzIoGIZNxaM8/HHoWOaBaZjOmd8BNPDug/ON6A/m5SdMcxOYB1u7w9ky/G0dkx+Jd2zdk+Y2WOZc6ewdk1GWBqfN7t20US4mxxUiYlTGEaRCEGp44xEKTLPssQxYhkungOyFdwsZF3Xp+1wcMKeFNxo/n9ruz4+YF4y9JbuKhM4P1q2LEA8FU024H60vMFMWZpgR0LTSXuYtmHc9UTEH/95NuPIAAzY2TbVt03iiuc1aNo1B2xfwE0jrm5NNUwuNI9icyK4CP4G5pq0Bs4svBnMZ97ys9bBzP4MpmWzPNh+x6xgYv5NnSFLd3673W4npIv7JkWLCsENETfOhRtclEQ46voxniJjliWOEcsIXEGWri7/7u2Le2GW96I07cpnQrDjo4ngZbjxXPrKApktaU/dMh01I1hRxdIwu5jak9kXmk5KLeuGnvS6Rl97bKDaF/123qC0L1VcrqeguZ3ucQCY6kYVwWgi9Ktiy1cKoWFwe1F/I2c4//5gsxonEk0F78MNFnASX5IueyL4DlhYR1qmc/nO94yC7/w0aToC+A4NyElb6XmWDV5ZppjlihPLcAVNuTJw71bSNBUMD2yqb8enyj+ULjvyaG9G+JqTQUv3GlmFwjwYr2zVE6RFc5OhTtkumNblU/7dw7ongYhyVMVf6Ex/PKKm6pVwoK1WujbhW1/CrAl3DY8E4m3wX/4GzFJUiykIGMz/LUR6UrQjhHHVRdOcnPw6HP6qW6Yz9sr6wvP/2ZnW1LT3Pk+tOhhunFYwbZnIHAagExVvzdJIoN2SQWHoyKEYF19UgnSrgY6keFFR4THL0EcZLW6tGkRtiaYZIJaFAbH41lJVJarPk23TCPvj5zBvVQdcsXYNFeuFG+qKltTSYzF0UvrKDhibUCxbgZZJp+fKdtHgU/2WjskNcH9hhjFrFh2NYRxnrhfDgfZv1T7YpLNtqotN8FSNwFXABt3jDOCbeKZnY3qf5tTUDukyBFB2hl08g+EW7ADZLDuyGwCSoSaViaPA/FD32o6t4Xb4ayQQu2P2rrGR0mc42XRxgv9Ums7BAFEBHX9Fi2XoqAwVtyaIb2dhSBiGIbH4CFaBtSZWk7MLzEojN2vC4m2hD3wI7tXbwOz3kXSJWSGEekA0Gfy11dVWLYezvWTLbJ6Yu3SqoSXO9QImoas1ITA9rpNKiw/lTJkfCcRvvmT8TV/XEfm6847426cpLo5CeQ/d4wxgwLj189Sqo8woJtGSCOL5SOiWuUDnFJDNsqU1EXpS6+3CtIN/0T12hM9wDecdYX/8COkwlF3r2fHQAe4sTVMRTNwLB6MykxggKio8DMPgsAn4Y5Utlo24nozIHy7Ye4KpB8KxzwIOJrDdWN9ow1OOhv2x6Z4qdyeclOOky3bAeH/36gxmu8g++a0AuEXxymLQ1LqFgjUsVJY+GL47p1VPvHB4zTbPROoX74CGMqUu5o34YzcyriyAjmNY9lecQRrunJ82J4IX5JIPsGA0YUn5Y8F42YtlBPMytqQaTobzihtVNupeewEK5LsgbB7DmWWx9eQ3R+GWbdBJ8242C0u7w8VVdNJ4wQ1YgRMVng0DtzgaS0WHYRiRtxu+k6Kua3yqubEnvR8WaIDjH8FlUZ/GL5aNosEY6HAgHofziRmBxuhe27EGzvU0GO/PsnozdqmQJc7H6paJCLb+wzUbTF3Aak1MTfSy7n2EYM9JlyOADns/5nK/jotnyjg3+wP0OobdeBbxuaqyo6PJ4O+lbRoi04NB6qY/6gFx5qgV/WLIPp5JhW4STN0HzKW613agsLmwilUnI4HYQbqrODDMCf6sKSvWfXB/9M3Qh1jaHZPGCyGKypfKNWHAY7RKL3dtcFES/RqtWLgwIrtKMZNAcdvbGXH0V0815XEhti3gwEZfrOhH9JH62MnQx3XChWTf4lhCvNjDREDPUlU5cK6Ml02TEf+4870zTJ/kXZs49bO3VXEkiHPTVrFN4r1eLt5TetjGi/HRhnQ6gaWq1rtfa0fwaWmbClang/ODVQvNZksrMzLYAVyN6Vol9oXO8BbpsiO7Qrf1DJbHnLHzPUOkryC4K5u/2xKBo6nq72QzGzPenAxhWW1MC9RnuffBEIoBG6EqvIIfF1SUxGAMuJ4KmgSqMOBfFk2EzlvcGdqkCIPK0l/fd2bjKiKNHKYkCwdi85mL3w+mJdk1CkCFV/OSjmUHX5sI/Ut3VQ4wF7Rk07/g4mHZNB28X6LJ4DlCiCuly86A9BM3rMiI7PWn4K5FfLQBztNxOV7+kl3pFRlxGmZYkLYlwCD3hGyaiqJU7yKbFcP174e6o8nQTzRNOxlMKysn5gPW5v/5diOHvd5Y34ar4XmD6eI4syhdnGCvt3RMXiKtr4kmgr8VmsB4xAJKwCrFi+VKL0rCubHi1uANg46DG/KkIt/reo0qxAkw4PcZn4yPm+GQU8XY4uFTmsbH8n5MH/bHj3Up3qXQH31rx7+N+EDTxBHQZ0VkWfLKg4vvypapCE21tKR5uC7mh67wDGnaFdAi2kkwIZ751YT4684WnPM1kUYhYGhGCYPxcjd/Nhxox9RblqFx/oJsmorm5tvLZsXRkmp4gHULH9y6mNvbruzhcrmej/hjczDWX/pyomb4sLOYRXsCYNbe7+pWcyr0mMbU/UFo5VXlCv5m8WK5wlPHwQkwVtxWep5lYUTquLzCMN5Jq+oBrcnQI9LuE6FpVq0uD+HVLOc0ctm0sP74bTBlw5XEbXWv/RBMPKD1dgVaUqFnpKsigdvbCj2wam7ndEsqHirKHAWuvytBw2HihIm615b8k6mZQDTR8KC0s2zSebekpr754Zr1+9n8sfhwzpQ7cEPCFXss2lL6TCWTEa/KpqnAl1GxYhnBGNsVKXYU9JYRMO26muBmnP9iHNzwYd+ieukbEOwkuMKsShe38qN1GwaM7WtJTF6xYe36/aH5qO4ZHEPEcqWHYcAJkE2jqGixLAx4UgEnMLfrWrAncbPsvI7Jb0hPvzzfufx+eG//laa5cH7B4cqcQc9DYyB2uKdqRCd84HOky450w+snzYnQybgRXHdVNFvLo2nAxOSNYgu45cLsuth3m3y1T8D1dw2YeS00WYgGA928Jamlh0U7pnwgfV/zrZUODPTGx+IwO54C5hrdaz+gk/vxkCGejkZ/7BjpMg2Z9NyKc2H+zlebs1gLqdFksJkJ9WAw7Ryn5ueK52WYKTcONljN9tVi6IM1ITZC3JbLZo0b3jvjS+gUjoff/610DQgIPSPyZFZ0uWthfHlqY1eqnYYRYRi5TQJ/j5tkcbOstAckGzZg0YITXFDbH1g3od/NeRdsf1sNZrtyMf4YmDvqXhsiWGcmnd4nmgjaeaHOakzfwwTXj+mryljgw+3mWP76UN1jSz4TTDsOtO/s/sJ++u1sm1MNbb1qBnfbvqZ7bMk2Ls4fxhRf2ClInynADGyFbJqGEKKiNvgNRDQ5+cXMOhEAgWHnHdBV0Nu0TKqf+Nwsf6zfnctwk1mVLi6TZr05Z73ATgE6h0uYJs4Hc8D0i5rQDAjDqOyYZc4NF7dGi2+nUfT1NMjG1Wx6UhBwP803PanoZpalkeOK0mf/0lTfNmns2DFJuPAw25VdJ1a4ieqmD9eu39foohhlwGh5NA0YX03LfTyzLjYmHIgtxgIfYI7Svbbk6XRPJtCcaPiHtPtkwBvomo4p767t+hhrfOPqk+lL9QWCA8aF0Cm8ZkQqnf7ggplfUpNz0yrHOZG574TWNCeD04QmzoKrz76bTznf38N5IuKPX4ohF9Kbpcm3aHc4YOVCK/jzvOT0vB//RlOhP2patrpiv4V9NE01IAyj0mOWDRe3lS2WjYhZ7n/j6iqViWMKTU/a8lZoJQyYVk30D2oMLPo6Tz9m7YkE4tcoLhfG/O6me20J9DfZTVQ/syJ1mQMxNMd/X3DGTak62ehrP7LazVPw97F6n11RYbIwZ0VKHDlv+ZSPpK9fBp1t3vjWRT3Z1SdVBMEsYBe9ZezuUvgL+Fg8W1LYaLj5pUxh5KuWTeIbNKdCd/dmerGSkSWx4wVSDV/gbxp9tU9eGYh9T/oYV9zWpYsTrOCNRbiZBlMyQrPP1R1vxlO8WK7wCn6o7mTDKOy6WmgJnBcf1tNPLP4bakbshxVHpV0Y4n/pG83GxTzZ1WVcMNpu5DBMdYqpuewb9oSFkrqFf/NNVMQmmK8HuDA0NlyfqMWudynKP6Czs/MerI9UlR3ZnAz+EkM/pW9Acu5sox2hP7PengDMli3JDFEgHpAlLeN8/OlvChYjgM9tfsyyILHcH9csnfb2iozApxy/BtP0IjGFAh3EIVWMpyK+2Hmzd42NhJn16fJHZpNsSQaLqo6EKRnXdvUcCM2HdM//2NC7wYiY5coWy4KKkhhL8U8qviWWBXsks04c0NoZKrpMPJZkFkx8K4WjSUzD1WRcMIJ2re6yJWk4ybNbOpYehRu6pY/oCwF6xmxUtkme8GLAlHAwUXsVuqXLwbTzRP7RHtYdyLdWR14fKLps+vufp1YdAs1r4WXXsAzkIBAsybAvdqa0iwZEj3kltb/C+JjGskJPaB66QmgCN3WaHxZTOMOZwm91D89uahiuu8xF01hOG/UG48a3pq9dkRInyUnJ13w4dGjxK8sVHrPMOBUlMRQDrieX2CQM4/9WdIgTMPxL2kUDX5BlaeTghavJ5gusQhHsPY2xg6OJ0DxNu9q2Cx62gZuvsTRX8brGQSnhMnBGm1pSS4/FaoLSlzN5izPc6BBNBK/SNO0EMPuNcbQBI7jC74r4YzFDKuMJYUEqM2HnCYhtwFzBMDP0QfPvuse2WLX7/POP1603rMyunpEkdAUIcMxn3gOvzOaVygqCV7hYxsABY6nwyXXxYT1yZblXE9p5MK5dlusj2VxZmVqNFfJoBZWx+9Z29wRaEkEUVERumK8HRHG53x2SEg75AD7sYdFksLXQiVrBJ6ol1fBwWvRgtoKiHv2aDudBxVvTEQ60/0B6CkIwXiWbZmJoR21nFEUpSjjgzBCuwePhi7kMTBR0FQvcgzmli8uXllTwLvjrR0Lz37qnaCpcLBtclASnHxWMMGDyxdNspaaJo1uSDbdJl6Hg4hII8pwz1JQhawXTToOJyKn41Er6CiJbotsftyqszQ6YPq4pTBS8idAhKeFwgHwQi9xEE6GiKmsW1Xnjzvu3O8Rh0GyGl50fq2zLmfJ3zDc5c8dYQXHBvIiLKmdENil72XNl4N6hjb72JbP9sTrpKghMpo5lZ0VGYIGNQYsFlCkZrmVMG4yxg+lh3ZOkWSyVLZYFFSUxluJjljFu1uxKcb18Iwrxisv2IJh4Rc2IvZoTDfdKV8E01rftoyje1+EOuqWQEt8OpfjQt0EQTMlb1zgoJVwvfMKZLR2TTzKiyE3RKx3ZR7aJYEQIdjSYdo4j5Yzzi2vG8Fe/mWYnZzi3IPY0r9KrjqVKG3IWjPIHuDl/yYjS5c2doSQIun3gzr9duioGwdgDfVUbMpJC4rv6pNJjlo0Xt5Utlg1JHWc++v0jFkuzEshWQvs8tXqSERslI4H4xS6X659wse8EZjWvZhfqPyl71smjefD8CqE5JCUc8i+WERgff4NRFQoNeyzYnAw+0ZsRARgQn5AuuzLBxTwvRgKxWXmlmBMWlJ7k7EvZLFuy51zhl0qzGmand8B3cXexRWVgQNoQTQbP1YRoANPOKQ4NhVuYnqpYjHhs7miM38Br9N9zFg66nlTNso1+peZjVdN+gJXQ8i3ksjmYTSgciLdD80Z4fR0Pyzm/EFOUSbOMETlVjCwGLkROusZBKeFwAen+DWvW7xntDL0sXYZgaGeLZaFbOpYeDe82Aqad42/hxuNzd6vnTzVOWIyz1cHh5otlmI2XfT38cbXsRDhsVvqZnzF27JiXZAGPomhJhmKY4hCaRcUnOYRkNDn5Wdm2PdDJVna56+wpMJSKXll20vXUmgphJdzndats+ZvWJXytqYbHpV0wmIbMPZy/At9xSLq+yVbbjhh2qmyXLYJx0xMoCM63lc1+cVBKuB6miZ81J4LBG947w/CFR8M/OO40jCaDzZomjgDT1ruAOWcHu6rcyRw3DXxXHk3E/Juj1AgXmymbm1OrcM8rYX9surQLBlMcrkiJQ7E6D5hlu2lSY+Im2XQGlV7uGtfWjaWixTITzqoICZOlcl1d3ogipSXVcCJWLpS+gsEc9dydzRfdb/VBGLsvK3aTuN2BD2d6WCv8G7vK5rf4Rkq4F8G0c0o45G2VpQ+IpkKmjYmmzRJw08TGjWk/dBEPS5ddGQk33j0YsI6B69K3CVfVxXBV2fSYZSG0sk4x1BSI78cZ73+zGGfDOOf3RfyxPxT7mA1j6bE6D5xV3Kn7vu4tK77YuIotkG1nQKnjjO5v7bzKYz7cWRUhP0+tisOh3Pr45UJL74cipdjY0IvqYsMigfi9mKMezMH6/wmz6xYfK9tlijB1L4pkt74mHZulhLMiE1jhCLEw3bN2r9bE1IT0mIKpne11b0z9vCU1+QSYUl8FpvlFPYoAA9Zr3LwDA9il62u8Lm2cbJqKIpT/ymZZAhdbf6vKm8L5BduNGLbkqvrFm4Vr5A9mc1C1Xqw8GZOu8kCI265/P+S07CkVLZYFrSwbjaOup2wMr2C3SNP5CHHLypWr9mlOTe2QnoIJB9pqR7s5luk+RfcMjsIVDAsoXzRuhVge2lS7cJMYZMekhGOsWwh2bjQZmj5v+Vmmb4Y0fWVCpve6Fg5Y+c/uK3zbuRTlUZjd/uabK5saUyx5BLExnTYqn63tkLHhJ+tWDnC2p9flfi3ibw9KT8G0pqatbk4EG/DGAtOIss2lJpNRmRNzt1a0WMZ0PLJpFBUulp0VhoH08O4/4kG3HMsqJrQQiJSf3PLfc4vO4AR9/BmcubBYSX57Vjg7AuNppVV+cPVd2TIVTXFls4M5KCUc8kZGiP2ak0HLMmBZ9hivJRV6QV/hEw9Il13BAehSDGj/6kZUOMs/1Vz+fIkr8bJddiheF2bAyHdwG8m40o6Tlyl1saKrA+GNlVbVfaCJs2bnIsRf5naG/iMtJ1HRYhm+N8P6W4wnlM2KRTgkddw3wTRyMGl3cBo58SxTM/5osgFDSooCax5EArE7oI+/G8yCsiFxV3bTWVmipXvelk1TAcETcFBKOIz9vxtTxc5NhjqlyxIs7XBxha81NfnH8Gmx6lrx5XPNZSLWOscAd7ic9pY+M1khj2XH5TvfM4pzXmg+5ezkZZyLPYNxVLqrcOZ1TH5jbdfH+0Hz/+BVVIxdqdCEYzcKVbRYFnATyGbRNED3JJuVi0Nj4DUhfiubTiIDvWVkRYodbkRe91n+2Pia0fwl+BKLy7PP2ZTI7rHtpFVWyEIaRW+YHAzoln7qhJRwcP2th/85vTkRPAtTxUqvZVi+OvFV1TVVEweCacljhiLwws2IAe6mryyDalsum2VHzYihGP5Q3AZJzvd3u3miKRA/QXoK5sa3LuqJJoKXCU38EEzTOyOD6TC74pgZyE0kFZ06Dk6AYQJ3JVtW8WIZToAjrydMIwf9PWZ7cATwXv/NVHYIZrnCjdPSXTDhQHyqh/NX4AssqoKrxMuGsItku/wQrOh48BzAwiR2f1LVoYn0PtFECENESkLJThB2GJl1Yi9oYtJxQrPkprCcC5TbPCB0L5ZmsYyBC/avkUD8msOVOUWvKjWnQg+J3o0+aD6me+yPcOiq8nns1soOwdAxrL8dO3Gi3Qc383FwKkKuCadkslnctWZ9INoRLDpHdLawhT/2B5jkLATTuOxSnJ+PmTSkVV5wZmmogS0R4pYP16zfryU19U3pKQkl7XDnvhNaE00EMUbmJ/CquNr530RThLPjaPthbN2YydA5Gvl4B1fUrpzkq33KiMdvzctO+bgltfQYGHivANPuoUH46dfLlqMYusNoEsv6tWsIW/d+YtjfciwODcPADW1M4fOkaVc2CKadDePzVCMKPGBmI8xwBML2AukyktGj3Pws2S4r4DvAYjaVyhqhaVNwI+md751Rcn1oi9UJuCFvwVyN0CzpzKGEaGIdK8+bgjOzNmAcxKr562Ff7ChpF4wspPNrpjLMAW3JpopCAYW0wKgNj1biGbqOxLIwTiyvSw8nseywGPgrA/cODQfid8kNbUN1rw0R7PW0EHs1JxrulJ6iwIxGmNkIrv49pctw4Ga4ZIoSK7swL8GEoSWbHcRrvWpmr+ZUQ5u0S45tHuVhrsbVGbEPXB0li0kpIW/hKrtslw3hQPthZnaQwFZc4Y9E/LE5RnSU0Y7gq3AN7om7baXLjqBIunScmz93ZSD2Pd1lf3o3KhUdr5yFG9ffent7KQzDQWJ5du2iiVWs+mW4ec+ULjsC2kz8eoUqDpiXDL0lfQWDE3qc2GNGIzBH6l7T2GVcvfiRbJcNc1NTcfFmlW5VBHgN/nZt18eTrumYYqs9bbbqcG/qDK2PJoOn4+MfMMshH26uYDnJsgO0QW5FSIpDYZz/Ylw9fxRTEUlfweA1iLtthRCYHH+t7rUl+1Yx/nqkPpZ77uoS4qqqopVlfaJjCCPGVtPKskNilsP++DlujwdXCCfoHhsi2KeqEMdFk6ErFneGDAlH203/vJfAy5prtQyLlGSrIgqxRJrlzmqmiiBcg5fgJnzpsw22XJ3Axz9aRuwLzWW6p8wRmuOyGwzGrPq2PeBwnG5ZAGcjjKxo15wMLcC84NBR2XkiM4q5+P2RQOx3l4y/ydYlSRW3m8SygaKhKzOk4sWysHnMMm46Cwdi8zlnt4FZUB5hSxDsESHSvtZk6BHpMYTmzlASDob+zUE4sMkXO0C2ywbBednpg83JZofp7QlEO0J/li7bYdtHeS2doeUrV67aF86iZRVaSoXaW35i2ePKFiGxbkAXrFm2DKM1Ne29JR3LDoYm/u2iUyaZB79oRM02hpQHNwvu6iWxbGB/66IwDOxcbHtNhX2L6rF8M2f8VOmyI73Qcc5s6Wg4rjk19VPpMxbV+H55ILhSfkVKNE08LZvlCOhkdu3nqVWHRJdNt3WFZ1t3uFhKM5oMnsuENh1M02t/lwTB3mtdPqWsylw3jY9h3sbTdMsSOqDD/6tsG8qT2tWZaCIYEUzDjYQf6l5bsle2PLgv3iBtW6H0ukgsGzh5rFG9Fb+yDH2nLePgI77YeVzx4BOp/Mo3W4lgbwmhHhBNhG7IPuo3CT3lnHhKmqYDN8XJTtrLkQvzOpcl4OC0egC58DlceyfA+HrVLdq5aemzLY5YnYgmGxZqTMUqenjRlBWCiX/IZtnAq9mFcCg6fjh3RKuZHT7SnGh4Suvt8sH3Zedy7SPhjm7DXKaY01T67IGLxDJgmMDt0TaQWLZZGMasCXcND/vjC5nCbwXTwv4vTwS7vYd379WcnPy69JiKqj+ZswqXV2TjpMsGzNYEg5tjagHkghDsubToCbSkGh6WLtvjmEd5LYnJKz5csx6r/v1e95QHnPGyEsu4yQ7LZ0rTfAR7a0WKxaRlKlh+tDkROhn+Tfx8hsVHGw7nF2w3ctgLV9Uu3E16Sg5XMiSWDexv+dChFR+GAdjmmgrXxfyeqhGvcc6mSpcd+RI6zKn4tNbKcsGtidCTcCi6qEmuwPgz4/Kd7xklzbKAa8wxonIQNHg1v90hDpuXnP5f3eUMHNXhYmLqaCL4U00IfNRcDqnWumGG/7hslwVDRguM0cMwDIvQ5hpRgjUfYLD5vWAqbkBdqntsid/r8b4W8bdPk3ZJ4YpCYtnAPMtDtG5aWbaJWI744xdyN8fy1baZnG6OYGIJ6+3xRxOhxdJlKZqmtcimFQwfOmLYebJdFqisF8Wy7UMVBuETVdN+gGGNVo/ZRuDI1YmWZCjWw0QAmk5P2P2ElTN8s1EUhcP/XSZNK/jXko7l98m2pTQnJi/tWoUZW8RNYJoaAlIEw0GlYhGTW41Iq1cUGRLL+BhJtoqmV/OQWC6xWJ69a2wk3Ftt8K3eDKa9wp7+h8qE+NXzqWWHlnID1dzOKX+Hg2WFtwRnP7tAuc0jTcfTmpq2GkaZZ6XpPAR7ojcjAq2pBscuDjr2Ud61idC/VmTEwfAt3ACmXcXKgGj2jn/Nm8a6NkwVhynjLEFj7BrcgCdNy8FUddFE6Gdw9WGu4y90ry05r2YMf7HJt6hkG4445ySWjQzDGJKhMIwSiuVGX2wv93CO4s+WG2olHzChHh5Nhq4uZT+JZPeUqMKy1WWYSW6/pW/UFGmWB9yacEODgckai7R0LD36ms7QJ9LnSBzd4WLydBArM+FWPAlMO4uVvkiz3u6yEssgiCxL2wOzo/+u7/rYFpX2osngX1i38MG7smzXdwHUK9zzSjjQXppUVopKYjk7hhuDV3PTyjJjLnyaJduWEfHFLnIpHAtF2DZVIxMirmq9vmhysm1WI1uWLvsLHCwLXeOsvIqUaF0iDoeSTnry5EOYIx0B42MzblKUPsdSFqsT0UTDg0zNYFjGP3WPI3gcN4zJtuNpDCwKQO90uDRNB0bI6+xU5Sf6ZujDltSyI0HFN4Fpzw6Ns2EwgMyPBGJ3XLD9bZYWSdA0e6b5shQDY5bTJJazHMqutuy6wk1jkUD8fqbw34Fp1yJAXUwT50eToVD20b2NyAomobVK0woC4UD7YbLteOa+Pflz6EM6pGlzxMMbN6b9LalQ2dSQKJtHedGOKR8sSS09DGbU88B0wCxGKBjzJg3HozC3dbN4wT7tWiWwKpatwMEAZtGtTKgHw3t8T7ptCJ8xduyYl5vqYtaV3+UUsyxgpiKbRePRekgsAzvttJMl11WkLrbv0JHDMNWancvLp9Kqunc0FfqjtG3Hig7ehgfdMh+45WbKpqOZ5V+wfZOv/RH4QHtKl11Jw9h3VUtq8gnXvTH1c+krC8oq7i1bQCIZmi2YhrGzn+leu8J/4B7OO8O+GBa7cDR4I3PGrYwPu8HI0tZGE01OfnFtdw8+6SjJ5sMcmai4+ctw/Z0pbVOhmGUcuI1bWeZqVVn13YVSM3SoqdcVhnlE/PFLmZs/B6Zdi10IJsRv13Z9vN+8jslvSJ8twSwIQhNzpWkFx5Vyr4YRhP3x0z28qhOaR+se2/K+polDosngtWbXPSgFZdnhNica/pHuyYZl2L1M5A5c4f+IBOI3Xxm4d6j0OQ64kX+GB90ynVXp3rV/kG3bcuNb09dGE8FThWBngGnX6pND4fq7KxKI3W369cc1Wlk2UCynh/TSyjLg3bDBtOtqZl1sTGN9+wPwrf0GTK/utR0rNcZOjCZDl9gpLG0gPu9cfR/cC1ZVreWK4rEyQ5NhQJ+8FYb9cM7uAdPWeaOxWJeq9QZaUiFMoViWlO3qxLzlUz5akRJHgliZA6adc/rhoHdhFatONtW3TdJdzgGrVsHBwpyW4sZ5y89yTOnz5mTwT2pG7AmdySvSZUP4GXD9vTrbH6uTDuPRaGUZMDAMw0ViGXBVVZlyXTX5YgfUuPnrIFROlC478pjo3ehrSQT/Jm1HgKWN4eK9RppWcFrT+JiFuf+LJ1IfOxn6ZFxNtnPYD9ILSvmy1tTkH9stRt5oyvpRHj7yAbHyS1VlR4L5ke61LbsqLtezEX/sOtuVKh4At3f4DDhYNetdq2pp3FzjKFo7Q+98nlqNE6Fr4WXXePrd3Zy/FPbHz5G2oVAYRnZWbJzAVVUKwwAUt9vQ60qGXfwcDrgxaUfdaztkXOjSY5qXnfKx9DmKtV0f3wWHD3XLdKp5NbtQtm1No2/h6HAgNp+5+P1gbqV7bcu7TGWTosng/5Vj2MXmVESH29oRfLqHdWNYxqO6x7YooCp+vt3IYa811rftI322ZYoSc4EIsqwOvxDsZqfOXnE1JZoIXiU0cQyYdh3gqjlnt0UC8XsvqosNkz6DoDAMwDCxrApaWUa4q9ew6+qKPRZt2eRr+xt8S9eBadeCFu+oqooC5Vonp+PKhowI9mtpmg6MUxfafREq7I8f61K8nZzx0qT3zI/2zDqxV7Qj+Kq0y56KWZ24NnHqZzATPxZuUPum9vofE1wu1/MRf2zOlLqYXWPl2Lg6/mM4WLXpZYPoFhg76GiaU6HHtC7Myczs/Oj0lNFu/lq4LuaXdvHQyjJiWH+bqSKxjCi9LkOuq0ggdlDVEE8CLlTcHG5LhGB/Sves3bO1Y7KNQ7pyZ+XnqzBrh1Ub8bfadsQwW4pQDGWMBOK3cs4eAnM73WtbNsLrJ9FEcPLcd0JrdFdlUFGP8r5O7cUE5l78QPfaFjcIjF+My2YsWFQvffaCCwuTvotbW94KrZSGo8HP0ZJqOBFjvcC066accdzNX4BO/AJpFwfFLMMlbNzKMqcwjCyqu7j83YoyRwGhPAvO6FPw5Wwv3XZjLdPYqc3J4BlO2q8xGLf899wuwRhW4LUEEKOXlaKIzUA0+WKHeKpGpKCJ+37sPgF+U2jp/UAo3yLtiqIiO9xoIvRPrbcrAFP1B6XLzvi44nk54o83Hq7MsY3gyG5G5Hx/aZrNRtHbY9kjOyvAGC+M9cqo6n5g2jXdEz62/EPYH194yfgFI3RXgVA2DBwKDRsMXRSGkYUrha8s46avJl/t3+CvYCoze16fQryIWQaiqaCd01AWTKZn7e/hsEq3TGfC7LrFx8p2ScGiUBF/7EbQ7k+CadeUhF8jmLh3dUbs05ya6pCiKMZTsasTWD2vpWPySXAZYNLyXt1rW6pgmG2ZVD/xuaZA2zjpKync5bKylOidTt3IMhhzOyanVq5ctTc0bVtIgHM2dURN1Wthf1vBCfE1CsNADOtvVYEJBQieyRR0XeGKnlLDk9C0hXjqAw2EcuuSjmUHt6am2bjAUXHgSrkQ4rfSNB2Fl74ENmZaGTt2TAI61ovBtLsG2yCYdnZzInTaTZ2h9dJXkVT0o7zs6l4idAPLiIPB/JfutTGc768wVyISiF+Mjw+l13Kuql+8C4zUMNGwhDTr7cEsEmULPo6MJoLnM6GFwLTrBsZdOXc9H/HFLpJ2XihU7hoxTOByt6ei++6vUfKrDJkNu/DHw4rCnwBzW91rOz4EgXJkNBlqwkJb0le2aCKNYnmtbpkMZ0cYuhcjDy4Zf1NVxB+bC9fec2DaYtFrEJZl0un9mhMNd0q7oqEOF4h2hl7esGb9noIxTNdid2rgdWNTfe1jkYkLSpLayOtyXQoHi8SPmB9dNv19aZQ10WRDnKkZH3zmZ6XLblQxhf8uHIi3512qnVaWEQPDMDK0sgzwPMqoY5GHJl/t3+FbiIJp18nbX7TeLh8IlKekXfZghiPMdCRN0+EubvnqcmNgUWBEzTavwgU7C0z7LxwIdvvKlav2nbt06jLpqXhILEtueO+ML5sTwSBMc7Eanf0rIXF2OPNWdZqVF7c/sKoV/ONnSdNsVDXDrCyNWnKiHVM+WJFih8tiOrZcVQKVFnIP569F6uMYPpIb3KYxodZiWH+rCnttVCoVXMltEtYYiB1exapxI5VdSwZ349jTkmo4GUMEpa9i6OXd/weHLt0yGc6mRHaPWZJ1AvcZRQKxX7iY5yUwa3WvrVnHhDY9mgyei088pY8ASCxvRjQVukll6QOg+bbusTXD9by4sYdmTVhsySPFajc/Hw6WlOYWjC3Ggh7SrBi+KqajqeqhYNp1VX0X5mJLIv74pbntMBcklrPzDGPgmkZ9N6KqA15XmAs+7I//0sU45tjfWvfajqWCqfvi2FMJxR36AlO7CiZulabZeEU1w0UxU5lV37bHgb6Jz8Pdigsfds3b/U2SGlP3jiYbFkqb+AbU4fZBa2JqIt2zdi8mhEMuGn6cp8rdGfbHpkuHKWDOZxjtC4pZLQBNTadbZbsiaemYvGTDmvV+GETapMtueEH+/abJ1x7HylPS1zeCwjAAw8Syy0Mry4ii9P9I+6q62Nbj6vmjnLOrwbTro+/fd60S+zYnJi+VdsWS6VEx4xHm8TUdzvh5xhde0pFx8T/3uFyvw79j++Jikt9/uGb9AS2JySukTWwGieV+wF260WRouhDsXDC7da+tGcM5vw/jSc2qgz/OJabBwZpNMUL8meKlvgoPCk2R1+EG3Ws7TlYU7+tNgTimwesPEsuCwjCMRu0nZrnR136k180ToIoOly678YWmaSdHE8GfXv9+yAnji+nMWz7lIyEElsG2gtGj3MaHEzbWxXZt8tU+A9cdVoG0dcVAyRpNiAa8Du987wxLJipOhcTyIDQng7dnhLBzLtxNgBE0pNTwpZH62MnSZQjZR+1cwSIaViBUnmmRbQLA6zAtxF7QTOgeewHX3U7QmTyHKyp9hmVwCsPA5SzZKh4Kw9BRN31igWEXkUA86lKUf4Bp07AL8RTrFr6WVMMD0kFIeLr3Gjikdctc4Ga8BK8XaRYF9nmYKcjlzqYjPEj32p6Xe5gItCRDMWkTA0Adbg7MTYY6e1j3PoKxu6XL7mzFXPz+cCA2f9DH4znSWNd2JBywTLMVPIyhMLJNSOYlQ2+t7foY4+lxM4wdYxs9MAJd11Tf9hd9I+j/gDdLYjk7PhuDi1aWs/BvFLvBfRu7+bIp4cLwsuPYloEbIbIixY6Kvhn6UPqIb6BnPhLzpWk2u4yrFz+S7YLBrFRN9e2PYaYgMC3Zz1Mk0B2LG1ZkxMHXJkL2T5lrE0gs58i1iVM3NCeCZ8FFdjpcao5Izs0ZP9WleDFjRtGJ9zm3MN2OUJtli9iMG9+6qCeaCF4mBDsersNPpdtecP7DajdPYPJ96YHvlGKWAcP6W81NqeOyyJSE4UD7DzxV7gSclEOyfrsh2HvQrx0cTQabcQOv9BJ9IDMgWXOOiixSAtfdDOatSsFge4R02Z1V0HucFE2EZi7uDNm9GJutILGcJ3CRzddEGoP2nVL2cTvO2UORQPzWWRPuGi59eREOtNVCZ/ADaZqLYE9Ek5NflBbRD83J4N+FSPvgfD0iXbYCRMt3FYU/E/HHr9RDeCgMAzBO4Gpu6rsBLsQQLPTAmfIwmFvpXnshGFuwtrsnQP1abmAGJDhni6VpNgduMqnPEdw8CtfdX+G6uwPM/HLOl47nMxkRiCYaHpQ2kQfU4RZAS2rqmx+uWb8fE+IW6bI7OEif56kakcIyr7ord6BDwFhlS1ayVI3RqnKONKemftrS0XAcjMZXgGnHVQIMy7imydf2Ny64XdN2WYlh95BLwBSYYFxRbpaFHuw3lgm2XmjirOZE8JQb35puTYW6MkFmQtJ0y1y4kt9T03AgPtXr5kvxCZp02R0snT5vSWrpIXM7Q/+RPiJPSCwXCO4cjSZDP4EZMGaIcEpH+D1F4U9GArHrZ+4Yq5a+AcEZNHQnp0jTbP7Z2hF8WraJHMiWbE8Gfy2EiqsjNk37w48DmXiaNCoZw/pblakklnW2lEe78WpvpnfP5lTIKftcbEU2E5IQf5amqcCNdPKVgdj3pNkvV+yxaMtIIN4Gv48pZbfQvbbnM8G040CrzK6E0ulmQmK5SJoTwUW9amZPaL6me2wPfOf88pox/LXG+rZBc0DCDPqncKjSLXNRhaAMGAXSnJz8+uqM2AsmbzQ42xfDBC53uajvtie4ivfrFRkx6Zql05xQ2Mq2yIxI0KWZjqtKsEtlu0+a/LEThwzxdEKzQfc4gqfTPZlAc6IBM8MQRUIdrgFc0zHl3bVdH0+CTvK3YFpxcxvBHi6X63lMs4TFRqRvEy7Y/rYaOPxEt0zn1dZkyJbxt07hps7QetyEKp92rNG9hI0wTCwrglaWbcjHQhPHRJOhK2jzVPHIjEgYi24BfMblO98zShpfg76wP36PwvlfwHRKKJkqBJuzIiWOxNzV0kcUCYllg8hmKUiGLoHLNAjmat1re3DTVXicm788u77tW2nhtthy9Bl40C1z0TSNVpUNAp92qD0ZPzSf1z2ETTCsv9UodZzdeEjrEr7mVOgxaRNGYFVmJM6GDR0x7DxpZWmsjx89dOSwDs7Z6dLlBD5WmTi6ORn8JWVdMRYSywYT7Qj9mfX2BARjL0iXE/C5Xa6XI/544+HKnGzWAizZCbPpAR9NGYZgnXM7p+DMnTCI1uVT/o0bOqCJgw11mjahz4ItBaDQBj+70AP912UtqYYftrwVWil9hEFkM4gIhrmzTef/2TsP+CiK9o8/s3eXXHoIvYiKSIcQey/Yu5JQ7BWwYK80/fuGZnvV97WA2DuQYMX22nsPoSlFlA4B0vvd7fyfZ29QxJTbu929udx8P647zyQkl7vdmd88+8zzcAbXXqnN8VAZ7ClDCx53uYxMQ3sEvxoTfNAAdUOnF+V9LGyFhSixbAOUWH17cenRFLuGZqyEZSTg6nra4dmDvrpjyLz+E4YMPB37+gS/ZC84SE2njWrCVFgEbejIL8qdgm8t5QBdH+xVRJe7rBG5Lq7G7ujziz8QODh/Ue5DavyyD6cyJOGN2aPDkKwZ7agKH2NXBrtiAip2M2la8dJT7i26oET0KSxGDbg2MUsf46PYNRxESXRuD/bGBAd5XK6fGGMPC9teOKxYVcznC0thA9OK8z7TG2tzOHBVXjfKHGPRmKsrz3J04fAkVXWdsXhksehR2ITIkPRl0LIXvKtuxtM+QSsmWI8X47G4YJuu63c5kmovXlFi2WamFY94x8cbcjiHL0RXLJCEM/Feom0z+gwVW2U/05ZduGNqUd452KQNm7VGp8Jx+kA3S0SuplLHRYsynfMRKE7GUFVX0aewGZUpqQk4f4ucIPlFeY4sJOIdJZYdYOai8zasWsyPxSY9TlKrv7/4/avFy18SbYUD5BflzvL7fAcBB0qDpHCYsoHtLBG5AV2ljnMacnj4/XzotEV5BaJL4RCUKYkD/0GY8Y4Px+9bpy0eeRY5QUSfwmbUgOsQ5D2l+NGArlPZ6C3B3vgGVw33qETpzkMJ/zdWVh+E0/8jaKpYSwdJqamxZMzVXLryLDuHkYqLHB6qAlr0YJwp7zLA7+DnR1AhKhUn7yxKLDvM9OIRHzb6eQ5KFEd2+MoK3uUbqms3qwIaUcKoQFmUdy0uWc5CM5Zi6mOadoEUS0SuTtGVCidYqwcCR6tUXNFn2uIRb+JpcdCKP3DOXFBTUb1f/pK870WXwkGUWI4C9yzJ27JyMT8JL/+70IzPAZjz+yk3tbAUUSK/aMRbUMeH4kis0g05QE2gzBqRq6tsGHaD4qQgoDfmTFs88ivRpYgiQU8qny7MeKIB7/drpxbl5v57zcXlok/hMGrAjRLBsIy8f4m0XhuDvXECh63bt5fNEZYiyuT/mrdx2uKlJ+AHMwFNX7BXYQfudu2sCcNQnmU7qeEcxqA4GTG9+NxYKTAVF6wshgKcP1YIMx5YFQDfofnFeRQyp4giSixHGUrrVV/vo2pr7wZ72j6cwYOzNoxRGRkkgtIO4eJtpg5wJE5Ga0S3wmJSA1XWhGGo1HF2UeTjfP+pi3KfFLZCIsjJxAHiw7vM+SuVtQ0HiLLfiiijxLIE3PfL6O3TikechiLldjTbumev1N9Q+ZhoKyRjWlHud5V1DTnYVFlKbKAukGiNyNVUGIbFoAaDhyprNx86c1FePHkuw2KUVuCianfCdJSvFy99GU+/B602SR2uhsflL8o77+EV51WKPkWUUQOuJFA8Vv6i3HvxRCWK1wZ72yL84ZnLL60ShqNMyi449I6hL/cQpqIZaIDOL8q9gIN+IZpqsLYQl8+nwjDko4RzOA2v+RvVPorWmTKk8LA+Q9j3HbOzLhddjmJkUNL5TGG2NX7xc35wfnHeE8JWSIISy5IxrTjvm1o/3w8Hb9r529aoDOi+/4q242gae8zDEn+dMrRw8vV9H0kU3YpmmFo04sWAn++v8ptahzctwRKRy7lKHWcRHzT6efbURblxEwYXLpMHvtR18tDC58AFXwKD/bDrRk27OyoaorJ+y3McYIMw2wT49zxrVIVclKdy4EuIEssS8sCSvNLpi0ecjXfPjWg2BntjH1wAPBqtDTMTs+cfjyeKDU/BgT4/Pbnr0kk5hVSKXNEC05fkrd5eXHY4fnjkyVEFdSKkQfdYFIahqbE7MhpxfL11WvHSUyg7kehTNAGFW0wZWngLS/D+yhhchF07r+E+EwYPOFO0HYWeAOCLuE+YsQ2HavzfRVOLci9VVSHlRQ24kiLCMh6CAByO5m/B3pimhtfxB0XbcVxMo5r/u9IbL/63puQUvjVxcEFv0adogln6GF/+orwJoqDO5mCvIhw0v9+SMVcD5VmOgJWcBw4NFna4Sy0AW2BydsEJHbOzilEekzBND/b+BdPYLaLpOLWlfA4Kza3CjFUW69x3YH5R3gvCVkiKEsuSk78490d/Fd8fm/ODPbEJB/7EtBV524TpKJNz5g3CwZ6EXlOc7nKzpSia82/LeTFF9CmagArq6LU8G5tvB3sUZknQ3ZaIXJUNIzzoUXeZn7JdjPxZdCmaYOKAuXtNziksRDH8AZr9g73/hAE7fMrQeYcI01EeWJtXh/PKA8KMPTiftbGi+uBpxaN/FT0KiVFiOQaYsTqvIr8odyQ2r8Kj3uiMLer9DYH7RTsKuMir3JK4oPjlyQmQ9CtOEKODXYqmoAXPtOIRZ1KSfDRj8VqMKr7kemtELlfZMExSgUL5XHrU/ciSvGrRp9iNm/csSJo8tPD/XInu5XihDhfdraBFzbvsb6yahacdQStmqKRrMX9R3lVUSVX0KSRHDbgxBArmWdzPD8XmymBPbMA5f2bm8lGbhOkodwyY2w0H/fOE2SL4fT3weGVKTsHHhjda0SRGiFBx3iNc9x2M5vJgryIUmN9rTRiG8iyHDuffNgDPQaH8quhRNMGk7PlnJ2exZXhlUWXZpGBvCDB29u1D5u4jLEehzEooPB8WZizwU2PAv5+6FmMPJZZjjKlL8hbRY0QO/EXRJTs+5mu8R7Qdx5PgIg9oQtAKFXYsA1fRlJzCByf0LsgQnYrdmFo8evG2baUH0uNE0aVoBY9O+5IiR3cpsRwCATymfrV42ZH3FuW15by8EXHHkHn9caz7QNO019DcO9hrCpfH5aLN6FFCj4UKuDhl8/9U1m4+/J7Fo9rCHqS4Q4nlGIQeI04tyruQg055LmXfPetGxTqWktgL2zHuGPBMGjB2pTDN4sbjBncqWzE5Z/5l0UqRJDtUiZEeJwLX89AsDfYqmsPPrYlZVmEYrbJe1/lx+UW5U4y8vIp/QOPjlKEF96HQLUbzhGBveDBgl04a+EJ7YTrCMO1uN71+Bprs1RbLIMBzcZy8XuXxjl3UgBvDTC0a8bTfZzwKXxbskRIcR9nEPtnw3qS+BR1FnyO4E9Iuw1Nm0AoTBp1xMH5qUvagbyYOmXeg6FXsRv6iEYUQ8A9FFfe56FI0RULAkjFXhWE0Dwf+ut5YmzOtOO8z0aXYBU3T2OSc+Rd4EtNX4NhM8cZWVOJL1jzJtKfGESZnv9r5sOxBH4rXL+29wAG+gcaGnPzFeeS1V8QwSizHODOWjl62bVvpQXhXSr66ZsdryeynKYMLDhIdtkJeBxxIbxCmFRzkcrm+nTK0cI7Toj9WyF88av3KYhiG1+IUNJU3rwk8usuSiZ2r1HFNUYfHVVOL8s6ZtuzCWNv05QiTh87bb1L2/C8ZaJSqrGuw1zLGX9brOa9o2wZVEGSa5ye8AajaraxQ2MX924tLj85fdl4brsgbPyix3AYIPgrPHcM5Px/NqJSSDpE9wM0+n5JTGG5oRMgcnj0wFwfTvYRpFRowuAJF/4op2QXjoxFaIjtz9bwAXotT9UDgGA7wh+hWCPzcGrGsipLsBoclHAIH0SZo0aPYBQqRmDK04HHGXN+jeViw12IYdO6WnnqBsGxhytDCG8AFn2Kze7BHSrbrun56/qK8WylHvehTxDhqwG1DTF2U97IOgQOwuSjYIyWUpu3xyTmFz1CaomCXHdiaLL8daOy/fbLZT1OGzjtK9Cl2YdrikV/VVlTnYHNusEdBsIA1YRhMlbveCa7J+CMbK6sPmlo0cqnoU+wCFRbREpIp5IKcFLYu8BmDmyjMQ5iWQTnwUey/jIKcCltZETZiC5zDFz7ekDOteMQ7okvRRlBiuY0xrWjkyo0V1ZRe7rFgj5zgaHpJchb7amL2K71El2VMyi6gx3O0aLCbbGCuT2k3ubAVu/DvNReX5xfljo6RjaiO4E+0KgxDxSwj2wH0s/KL8q5V+Wpbwk9V7rKCbdvpPyF7/mmibQmTcub1SYSkb/GSP1d0yQhVgpz69eKlw2YuOm9DsEvRllBiuQ1CEweKlGt0zkegWRHslZIcl5bw46Ts+acK2xI0B0uwcoDvZy4e+YswFU1AG1F9nO+Pb1bcV01z6z5LRC6L9w1+HD6GOj40v2jEW6JH0QyU4tF4vxwCL0zLxt8pQwrO0cD1AzZlznu/JaDrJ6nMK20bJZbbMNMW5RVQMn5sUpyarLTTNO2tKUML7rYiPZvw8lrq2WiFh8RZ0QIzF+WtWBmggjr832jiGiNO0T3WjLla3KaO8+HlM2Ha4qUn5P+aFwv5deWA6Y4V7kCxfPSUIYURPdmj/SA4J8wAFytEMz3YKyEcPmr085zpxSM+FD2KNooSy20cSsa/0s+PlFykaMDYnZOyB74Taa5Oj+a6CU+OeN3wzdywvbiUBnNFCMxdkteYX5R3c4DzU/HNo0fDcUeAW+NZ5vHoWeawRgc4Eq+hmbp+Fz32VoTItOLlC/G0Kmg5gCt87zJlG+ozhL2Pc8IdaMp6nQfwgrxr5WJ+0j1L8raIPkUbRonlOGCnSNE5PxtNiQtHsJNYQvKPE7ML9hcdpqDcmzi02robe1cY8EfVbmfzTF+U9x7nvmwUP++JrrjB7bEmZpnFX+q4lyrrGnKmFeV+J2yFCWhxgYv7/wrTCXInDphrOhvRpJzCgynFKF7gx4kuGdkULHiT9y/K/iP6FG0cJZbjiGmL8t70+42wjK+DPfKBCmAvl8a+nDy08ArRFTJM84zHk+15PgW1emPdHNFWmGRq8eit0xaPOBWA34xmY7A3DtB1S8ZcncdN6rhKDvqF+UW5Fzy84rxK0acIg3I/f4ZOQct23FqCy1See0rHiRc1FTXaI9gjJe/qtXyoKngTfyixHGfMWJK37qvipUcD5zPRlPVRppcxmEMFQEJNcn9ljznJeHKsghQHeEEVPogMXdd5flHevzkPHIpv6ArR3aYJcGvSajGt7XuWOfAfAn6+/9SiES+KLkUEPLIkr5pzeEqYtsOAXT4x+5V2wmwWGrsn5xS8QOk40UwI9kqHDy/I26cVjzht2oq8baJPEUcosRyH0I7d/EV5EzjolIWiJNgrIQyu6J6R+mUoj/M6dMi6FE8RxTubgPsDAcc2zLR1pi4a+XMDq9sf39anRVebxWWRWG7jqeN0WsxvLy47fPqSvNWiT2EBeqP/ETw5EzrAINWlecYJq0kmDi7o3bFj1jcorB0LnwuDtbiuPzp/Ue69tMAXfYo4Q4nlOGZq0Yj3fQ1+Csugikiysr8r0f3j5Jz5Jwn7H9DOaZQONwrTAfgHKl2ctdxbdEFNflHe5fjejkbTqUfFjsPc1oRhoJhsq2P3ZiMNFy7m1X4A65m+fNQfeO28LkwHYNeOGlzQpLd4Ss78M1xuRmnhhgR75INzeLPWz/ebVpz3jehSxClKLMc5M5eP2rSymB+Pg8LdaMq6WaE9A+2dyUML/6+p9HJ9hhgbF/cJWvYT4CpdnF2gYJ4bwAUcB/6V6GpTWBWGobXNbBhv67U8W6Xhshnm6PjVbV8NzhNtAyMtXE5hPl7Fb6CZGeyVjkbgcOP0xSPOfmBJnsSb4hVOocSyAmhH79RFuf8XAH4impuDvdKhoTy4a1L2wLd2j4PjTKNNYk7x68zFI98XbYUNkPfr6+JlxwDn/0KzTe02d3G/JSJXp7uh7VAPOr92WvGIM1U8qP3ggvRLPP0UtOyHaezmnSWwb+3/aoc+2YxKQU+mL1GfhPyGo87h+YtyH1JhF4qdKLGs+JPpRXkfN0DdUGx+EOyREXaqiyX8ODHnVQofgUlD5h2OIy6V93aKh9UAaj8irv4u4IFhaK4P9rYBdLc1Y27bCcNY7g8EDskvzntE3VfOwUF30rs86I4h806iQiVer+dHtMkpIyvz/VV8//zFufQ6FYo/UWJZ8TfuLbqgZFrx0lNwNJ2EppylOxn0coHnq8nZBZdoLpeTXuVSXEy8INoKB8hfNPLzgN6YjeKwTRR/0d3WeJapio9oxi6cz9q2rfTAGYtHFouekLl5z4Kknd5KhXlW+dk8PDn2FNHF2CPgAvJo7xnskY56PK7KL8odOWN1XkWwS6H4CyWW2wgUB0ZZIyZnvzpkUnbBoZOHztvvtpyCvalffEvIUAL7/EW503E2O5YDbBDdspHENEZ5Qyle2RE48Dm0EU2YCpNMGPTqQNr9LsyQmV58bln+orw8bFJqwFqjM0bRLMuGIe0j7FAoBa7n4Wd61awNY0x/nlOGzjskuR0rmpQ993TRpTAJFarCi+gxYToB7SlJDDalYyX380NRKM8StkLxDxjn6slXLHKlNsfTPjvrJA34SfgxHold/fBoajBqwONXnF6/AM4+rKzb/N7DK8ZTX0hQ+WnNk/QMMHaG6IpX/BDw98pfPKrthAQ4zOScwkLGjUewt09bPOLxcB67TxpcMEBzs5exmR3sAQgE4KTpi3MtCx2aMrTwSZSilwvTWgJwoBWPePG9vBbV8n+EaSkc9MunFo2wLI0fbcyl/QZBi3+OH9gF4dxH1/d9JDE9qcudOBbdhqabflZ+Ud7Rwa8qzEJlpbVkthabScGe+IMDf7HcD1dRDmrRFTbkmOozRD8QmHYMDmw5DNi+eG6P92kafpkyu9Tgb1yP8/Aq7P+2kfGP7i3K+934xwrpUWI5xpjSr6A7T4Lr8UakvMIdgr2mKMUb9lmcsB4KdcKix52Thsy/GQXEdDQ9wd64Y25+US6lNVOEwe2DXtk3wZOAizbxNIvDR+BruDx/2Xk0WZuCCtV0T0+5B0XTtWiyWBLLgUDgoOmLR1K6rIiYklN4HZ5syfVtk1iehD/47pWL+YxwSgTTkzIGrmfxcxksugx0gENUCezwocJP+J6arpbaBqjB6/w6K67z24fM3cfjcl2DczLND12DvSHzI0qwZ7dvL30mnKcsCudQYRgxwvjBBalThhZMgyS2Gm/KW7ErHKFMZKG+uAlc7tU44d5zx4BnaNXbIuQBzF+Uez9OTOTBjsuVML4FqghJBCS4PTfh6a/xhsFxkJC4OJyy5k+vubg+f1He9Xg9nolmTGVPsKwoCecxE4aBYmCtHggcg2PIVLNCmZ6gBcW269vdhTKBb8ItoqkIA86M4krx5jFb5vf5Do5UKN8xYG43vDafS3C5V+CcTHn+zQpl4gBcSD7SsWPWH5OHFlxP17voV0iGEssxwMQh8w5s52ZFwNhENEMq/xwClCj+Nndi+uIpQwoPC3a1DHlwAnrj/jiyLhBdcQH+vd+ppPThQ4978dq9WJi7ko4TxRxctL1DT0xEX8jg9fg2b6zP9rv4KtElPy6ripKwmBm7pxXnPjNt8UjTebMn58wb1HFI1rcihKNJEYFi+Rzy7AlTYZKpRSOX4sX0kTDbPhye3Lat9KAZS0cvEz1hgWPWlZ4EFMkMLkLT9L6gJujIGHuoY3bWzxOGzPszxEwhD0osS87knPkXuFwu2kVsemNUKOBksxfe6p9NyikI6bEzbbaaWpSbS3lR0Qw59jnGUUVIIkBLgvF4aiku8hRIYksmDy2kiccUU5edvzmW4v50izzLTIsdz7JZhml3u6cMLZzIwPUjDlD7ie7mcCW43PTUQhEmXI+D8Y1DNQf9wvxFuWMiCXegLCyTcwrmYvNxvDZTg72WMsjtcn2H8/5lwlZIghLLEhPcxKM9j80my4VaiFsDNgd/X8hp2CgvagB8lN84drx6YcABNmwvLm0TacuiwZU95iQDY1cLsyXaMQbPTckpXDA5+9XOoq/NYVXlPY5vqmi2Ke4YWtD38CEDv0AhMg3NULMnXELFLkRbYZLpS5a9i6eVQatNskhngf2nFo14UdhhMaF3QUZSFvuIARspuuwiEef9p6bkFNwpbIUEKLEsKXijXIizIcWTOTUp0ux7X6geZmJ60eiiytqGA4DzV0RXm4MBf3SWPoZ2MivCoGOHrEvwZEbInMM0z9Ip2YUjhN22cFlUTKTtFCUxoDL2OObd5GFGuNkhojtUkr1edygLMkUTUKpQzu3JrCIBj22sqD50WtHIiBYD5FF2pbK3cI50sAAWu9uMA0thL0osS8jE7IL98UZ5AptOe4+YBuwxymMq7FZ5eMV5lfmL8s4DnY9Dsy7Y22ao1Rvr5oi2wiRGjm8G4Twi74Aj0zx63NnWPIa6RZ5l1oY8yxRzPHHIoE/xr3oAzTDTmLHxJGiEoTBJeYA/R6eg1SaowBXAiPyi3GtoQ7DoC5vkdmw23nG0wd1R8Ca/d1JOoconLgFKLEsG5RJ1aYweF1m1kc8sCcBcL5qdePKL857wc34wNn8J9sQ+HOCFacsu3CFMhUl6D4Fz8BT25it63On1epZMGlpAWS/aBBoELBG5HN8c0YxZKCXllKGFVydo7kUWCJGOyVlNbiJVhICRZ5jzJ4UZ63zfADxn2qK8AmFHxJSh8y/Gu+1CYTqNhiLt+ckDXwon04bCQpRYloy05K6UcJ8KjESTfZKyjHLXppixKG9JA9QdiCLzWdEVy3B/wEirpAgTjRkpDiOlC/6cNyhF0029nssUfTFLQHdZNebG9Ng9ZeDLe04aMv9/KEIexcOqjVI3UTiHaCvM4mt8BP/vDxoxCU498NBKPz/Sqk2/wUw+Gj3xiCbtWIJXzUVRRg0sEjEx+5V2DECKGCUG7AZjoDAJlYOeWpR7KY5bF9EOZNEdg/APZi4e2Wa85E4zZei8o/B0UNCKHMbgopSM1KUomk8RXTGJ5tIt8QgzHrueZWOnf0JiMf4Fx4kuq9h3QvYgx8rftzWoQBCqzdeFGWuU6pyfnV+Ue6NRytsiWDJMwFP7oBVVRkwZXGDZeKowjxLLEuHSPBT3mxG0ok4KS4KwN83kF+W9oHPfgdhcHOyJLQJcpYuLCOaywqu8O91RNC+cklM4O5RiOjKiWxRrzCkQIwbBz24e7fTHpi3jHL4pqkhJBPBAIBbHva/9fiPs4k1hWwLtl2DAaE6WAu5ipp/2KqxDiWWZ4IwyB0gDY+xiiisUpmmmFY/+tbaU02ZB2qwYS/w6c/HI90VbYZI7hszrj6fTgpbl0PU41pOQdm/QjDF0i7JYsNgpSrIrKPJLRNMW8OI4dNKQeYcLU2ESKh6Dn1HE5dgdQgfOZ35VvPToGUvy1ok+y/B6PefhKTloRR9cZp9GVQOFqXAYJZYlYdLgggE40vcVpizsfUf2y0NFOyweWJtXl1+UO44DnItmZbBXeh6mEt+irTCJR3NRKJGtns+ArkdUqjZaaBZ5llmMepZ9Ph/FXupByx40ly1PNeIGprNYiI8t4aCfmr8ob8LH+l22xFnjBDBaNGXB5U5wtc2UmjGAEsuSwNzM6vg9S3BxjyWva2pR7qsBP98fmz8Fe6SltAHqXhBthUmMXdsMLhCmXXw5ffHIWPF+/Q2rUsfxGI1Zvmfpuavwtb8tTLs4g4qbiLbCJNuWlM7D06agJSWf+hr8OVOLRtj29I8KkOANRmGEUsEYO140FQ6jxLIkMOAReXDtgjPIEc2Imb4kb3Vl7ebDcaanBPhSem458Dm0SVGYCrN4vFQGPdTKa2GhAzwomrGHZlUxEWtEdzTQdds/P83DmCqBHSZGESYOjwpTJgI4d/xrZTE/fubyUbaKeZYG5NhxBy2poPSsiiigxLIkoHKU0hOCM3If0bSEh1eMb8hflHc9BHgummXBXmnws0BAxkkiJqBNdyjhrhSmXfy+upi/Idoxh1VhGMBit4Lf9MW5n+KpKGjZxkVtuWy63dQ3+GifiUxFpragUj4R54675up5AdFnGxpntO9CRjpOGviCDNk54g4lliWBAcsSTbngYMvryl+c91qgwb8fLhK+E10yUJi/eNR60VaYxJOQTqXS2wUte+CcP+zEZGkXnFuUOi6GPctBuN3eZS/TPONFW2GS+34ZvR0/IyqOJQMfNEBd9vSivI+FbT+MS7vQ0pmni2gqHESJZXmQZtft32D2va7py0f9sb249EhUEPejGf2wDB6TaZOkYJh2txuvlRuEaRcV/saqmNzY9ycaFeSKnFhNHbeTlX6Yiye742Kvvi3nxRTRVpjE7/PTRr9ojst+/O2TphUvPeXeogtszaKyO7gYlTY1pdutxWTazFhHiWV5qBVn2bD1URzFx+UvyrtV13Wqf7892Os85OHOXzTyW2EqTHLYkIEj8bRn0LIHzuHJmcsvrRJmTKKBNZ5l1MoxPXZT4QjO+WPCtIusBEi6TLQVJpmxdPQyPH0YtJwFx+MN+P9j8xflTtf1u2zNntIUuBj1iaZ0BLgm7WtryyixLA+yxe/upFScbWVa8Yh3fLwhBwXRF6LLaZRXOQIYY3YXg/AzX8N/RTtmsSobRqymjtsV7qubhSdbnQT4Jt1oPPVQhIWu69EYF39sqPfl5BflfSlsx2GcyZvmVIcK0VI4iBLLkoAr6ZWiKRecO/a6Zi46b8PXi5cOwzdjq+hyBPJibC8uLRSmwiQTs+dTOiPLsqY0BQe+gMrxCjN24dZszEOpHPNiedqyC3fgvWd3msa9Dxs8YLhoK0wyY8mod/HmWyFMp0gOxkxHDxxv1oimbPhrGreofTVRQIllSWAcikVTKjhjjr6uwwYOHIQywNHNFQz4o0a6JEVYuDTbvcp4f+ixmy5uFzSLPMtImxi7ue4jzyVqZhtx4Ppsq4jiTJTq00kGTM5+dYhoR4cALBct2VhNGaVEW+EgSixLgh/4R6IpFXog4NwOZMLteNWkWr2xbo5oK0wSnNTYicK0BZytv2kr8eS6y6IwjBgtSrI7VBIfP+F3hWkLDNiBE4cUHiNMhUkaWN1zeHI2TJB5olo9b/qyZYvx5EgIohlwLPxMNBUOo8SyJNyzeORSPP0WtKRh/cylvzhWcU/TNBQAbJQwHYEeA9PjYGEqTMKYh7x2tgo3Zn8RC+ewKgwj5lPH/UVAtz2NHLhcoLzLYSKKNDnqUMCre3RwPogOxqZCzm2rEBgunPN3RFPhMEosSwI97kLhRit4aeDAn3dyJ/KkQfMPxdFxL2E6AfcHApQeSREGU4bM3QNlsq0eILwn/vhqydLXhBnzWBaGEcNFSXZn5pJR9FSNPHl2cuqEQa8OFG2FSfx+TsWa/EHLEfaeNOTVqFar44xLNR8jJTsWl9n6FEbRPEosS0RDve9xVAfVwow2ddDY4Gg1O+5yOgSDfzBz8chfhKEwCdfc1+PJE7TsgQH/78f6XU5O0rbCLUodF/tFSf6CHAW6bns2Gub2eG4WbYVJZizJW0ebbIXpCBy06IZiFC//H55+DVoSwPkstbcmeiixLBHGDmAmSQozzh+duuz8zcKynVFagQtn/xHCdIQAV+niwmVC74IMlGtjhGkXlZW1jU+KdtvAqqIkPPZTx+1Kdf3ml1Ed2Z0F5/w7BsztJtoKk7AAc/QpHGNsJM0LwnScYCiG/i9hRpvyADc2wyqihBLLklFbyqfjaXXQihprywJwt2g7wr5DGG3AcbKM568zF4+ULiYtVnCnsnF4Sg9a9sCBP/XwivPkzXcaBsyicteoJNrU2G3s8Ge2FylJcCe6rhNthUnyF+d+jafvg5YjdN0nG44W7agwbfGoV/H0adCKHjrnE6cXnytrLYa4QIllyXhgbV6dDnABNhuDPY7jQ5lywSNL8hwNB0EFca5oOsXDIi2SwiSjBhck4Admt+gI4A0Q80VIdseqjXltoSjJ7ui18DiebK0YyoCNu2PAM6pccLhwZ4uUuMDx7Eh/g+aIRl/jWGxGb9HO4aMZi5fNFpYiSiixLCHTinK/w6XktcJ0FFSPNztdOUmILycLB5Q2QJ3dxRDaLH1cnBY23YOWPeB1+Nq9RXm/C7PtYNHGPHx/2pxYnrYibxv+YS8J0y4y3Z70K0RbYZJti8sL8LQxaDkByzXmhyhyz9JzV0GAX4LNKJTdhnUNrO68aJT8VvwdJZYlJb847wm8VSYI0xE45/83tSjXcW9eHzc/CU/tgpb9cOBzRDokhUmMdE5Ms78ISaANpYvbBcs25vG2OXb7/U4UKYEbrtTm2Lox1WomZhfsL5pRhTaY4Yfj5MbvrH01OEG0o0b+4rzXOLf9adrubOO67yScq0qErYgiSixLTH5R3kxcTl6JzUCwxzZo1Xr91EV5jsYp78ThXc9+Fgg4muWjOSj12uScgn/dvGdBkuiSnolD5p+Mp0FByx5wMv5OxEe2ObhFqePwh7Q5zzIxY+noZfgufSBMW8A3rmfHwVkjhSk1wTGisNClsR8mZb/aT3RHFd5Y+wSeaoOW/TCNOR2i1yRTF+XSvHEVHrZn5yGPst/nOzZYtEchA0osS860otzZus6Pw6Zd9eA3B3T9pPyiXKdLmhpc2WNOMuNwpjCdoDB/8Sg5auu73OMZsCnJWWzJ5KGFp4heqWGM3yqatsHA/iIVUcOqoiSs7aSO2x3uxOevwS3RLHrRGsO0u91ThhbeApp7Ob5IClHDT9wtxeZEUcTpxaDlCGfSPCHaUQXnyVmBAJyGF6l9mVs4fAyN9YcEF44KWVBiOQaYVpz3WU1F9RCcaEnQWrWqJW/1Y3pj7eDpxSM+DHY5T8eO7c5AdZQqTPvhASnS79yW82IKnnbGTu6D0uedyTmF86f0K7A1FjgSgo+C2bHCtAXyqHxVvKxQmG0OCzf4tdmxe3rxKPIs2y0Uhk4cPO940ZaKSUPmHX549qCf8EO+b9exEdXyRTcPLsgSZlTR/ZzSyNkbLvMXaR3bZ50m2lFn+uLcDzj3ZeMf/zKaVr4HFfjTbpy2eOkJTqZtVYSGEssxwr/XXFyevyjv+saAvx/nnHaNVwW/YhqK1X1Ch8AAXCVfE+1SzzjSOBaCgb/ru/xFI78VZlRJ5EkX4+lvEx+qqDxIYr9MySm4iTxLolsaXBqz36vMoU0VIdkdplmUOs6qSoASYlQzdSAHOtOYVCWwb+3/age895/SXK4v0BwS7P0bKUluZndu85CYtiRvOV6EtobL7AouDaOaFWN3phaP3jq1KPd8CMAROLG8h12RiOYq4Px+rvv65i/KfUht5pMTJZZjjHsWj/pt6qK8q7dtK+2Cd+e5eDyL3ZSXubkbjPp/M75PhwvK/LwLiuRx04pGrgx+OXrc1Ou5TAbMyfADKbzKmnY33XfNPVJNw2n8AfIsTRlSeJjoizq35RTsjafcoGUbVTWV1W2rCMnucGuKkiBtViwTdWWcsmJsC1q2ccKEIfOyRTtqUDjI5Jz5l3m9nl/wY70Mu5r9bPEL18iykObcuSIl+HefSoWQhCkNtLcCBe4pPs774xtCBUwW4RGK2K3Fd/B9XBSOqamo7pm/KO9WEuDiawoJYbSEV8Q+l/V6zts1LXEvjXuyAkxPdnGt1geBspLqut+fXnNxvfg2qZiUXXgpSoenhWkreJVv2F5c2kuGcqGTswtOYxp7W5gtQYPuk7V+PuGBJXmlwa7oMGVowcPAmL0xk5z/h56eCCtqTBla+CTOzpcL01J0ro+dtmjEHGGGzZScQrpvLg1a1sJBv3xq0QhH7suWwGvubrzm7hSmLXDgL04tyrtQmI4zOfvVIaC5H2PADhddrUJOkqlFuVQsI6qQyJ+UPX85Np3ZeMj1S/IXjXhOWNIyaeAL7XlCUrZLh954/XbAzyuVAcd5h9Xg9baB6WzlSs4Xz12SF61aCoowUGJZETVwwqcKeicGLbvhEyi7iDCiypScgv/hrWcmXnI7CpjbpxePeiYahVQoTjLZzdZhk+Ks7SIQ0Bv7TC8+d42wo4adYhnV8rhgWsjImJxT+AwDoNyvliOLWEYh2ZlpnrXYTAz22IIPAv59nN70O35wQWo7F9yFYuoGNE15inEA+A7F8iHCjCo4hlO2JgoLtB8O75EXV1gKhaOoMAxFVLgt58VOeBoWtGynVm+si9ibZwUThhYMRqFM2U3M0IGB9tTEIfM/mzDo1YGizzGSXEa6JDuFMvGmDELZdjRrylS3xQp+uyMeS9MmKjvxgMtFgtUxJuUUDm/nZstRKFPMtOmQCvzgD56UXXCoMKOKKO7kzFMvBsdP6lvQUVgKhaMosayICok8KQ9PjsTecYAXor2RcSduYBRmEJbQYQyOdHs8RVNyCu8R2TRsh8J7GDDbq0nqvG0WIdkdnVsjcq3K1yw7XHegSAmwK5yIh52Y/UqvKTkFC3HSpWwvewR7wwOXXI4K/Oag4k5U5EmYduOGJKB5Q6FwHCWWFdGBgVOJ5rk/EHBsI0pLGN50BucLM1yo8thtCZC0fFL2/LODXfbRNT35QnzNnYVpCzjZ/jBtUS5lAGjzaLTksQKLymbLztTi0YvxCvlImHaR7k5l40Tbcqhc85ShhRNdWsIS/OBOFd0RgQvY4RMGF/QUZlQRRZ4cyWCjMbmyYijiByWWFY5DVanw5FCmB/7BzMUjfxFGVEGBSxOyN2hFBiqunpqmvTZlaMGbEwfM3Ut0Wwpl7dCYdpMwbYPxNlyEZHcsKkqCYikuPMuErjtwfTC4nkStsCxjYk7BsD5uVow/fxqaVhbWcLvcMF60o4qI93YoNzo74o6hL/cQhkLhGEosK5xHc4+i/wcNewk4kK81FK7v+0giqpurhWkdjJ3hSnQvI8+V1ZP9pCGDzsCTrTvdOcCGbYvLC4TZ5uGaNSIX3zepxTIttIxSzdmvDpkypPCAO4bM639935fTxZdNMWPJqHfxZHfZ3277anCeaEcMbU6cnFPwggsYFXyy5R7CBdMVtFFQmNHFuWJPmoclxESpckXbQmXDUDjOlJzCH/G0f9CylV+nFY8YEI0MErszZej8i4FplBPbTpbjn3o1VXwUdkTg50ShEUcELZvgcHv+otx7hRUStCjo44aDuM4OZIz34Yx1QuWYyIHX4LkEdFgBnH27cikvmqvnUaVKU9iaDQPXTVaUlp88tPAVlN22PJIONxsG5Sx2u1wUU3oMHnR/J1H/bmzEz+krnHje8Vez12eszqsQ/S0yKadwHK6uZwnTLpbieDEkkvGCFgm4yLxSeJIzg732gdP3+KmLcikMIupMGVrwDS7encjS8SPeQweKtkLhCMqzrHCUSTnz+uDJCaFMPCyDUDZgmhP5gwdoGvsEhdRzIttI2Ijd9nYL5eoAbwx5cxCV26YKZ33crATf0C+YBv/GyflKFMjD8cunMWAjsX88aOy/4IIf+gxhGycPLXjo9kGv7Bv8CRLArRlzUShL41mmvOGTcwq/RqFMBRkm40HXTVNCmehufE64cHSnsY2Uv/v2wQVdxNeaZce2Usq6YPcm3UETBs8NOzUZedAnZQ/6Dj8ZEq+2C2UCr4PrRJGjqIOLVqf2hhwwcXBBb9FWKBxBiWWFo2igObVBo1SkNYo6E4cUkqctJ2jZDsMJ9KJESPp1ytDCq8OdSB0pBcz4s9OLzy0TVrPQAouyCLg09iP+I6pwFlrmAgad8c24PsGT8CstICYPfKmr+ErU4NwakcslSB03pV9B9yk5he9QgR18MeGkMkvBq/W6BDdbgZ/PNVTkQvT/g1kbxtTimzdbmLaBL8H0dU+ZNIyiPS6gUvoHBHsdo8+E7EGWbBqMlO3FpRS37Ei+apeLqY1+CkdRYlnhMM4McpTOiNIaCTOquFxRSfPUjjxcE7MHfT0x51VTQp08saha7M60oQf80KonyhBRQB7LiLIIUKTwRSzBu8SJDCItwTSrRK41+ZrDZVJ2wdGQxIqxaUWRiHT8fB6ZmD1vQUspEX2NRtYFm6uesWPpCYYwWmXy0ILz3GnsFxL9aLqCvc6icTnSyAWro/LHhGkvKiuGwmGUWFY4BsU04ql/0LIVv0hnFHVuHzJ3HzzRRrmogMrsYBd4fiDPV6gbrBLcHsqAYffY8Nb0JXmrRfsfkEcchchjJKLQbO6Rvlnaa5q2YHJO4e3Cdh5uUVESi/I1h8OUnPlnaBr7AJvtgz3WwICdnci9H94x4Jk00fU3Zi4ftQlXwXOFaRsujd0qms1yx9CCvlOGFn7IGHsJzeg+sWAwzCibLQG1fqDqlLVBy1YGyvI3K+IDJZYVjuFyaU7lVi50unxtcyRoLvI4Rfs+c5HnKz058VcUii16ZIK5oNnFwrSN1tKBTcoeOAuFCFUOtBrU3zAThc5twnYUq8InOAXbRIFJQ+YdjpfzPGxanmbNgLFDPAnprw/T7m6yYFGA+ZxIM5h7W07B3qL9N27esyAJF553e5iRDs5sJU67YExzO7EnolUeWJJXCpw/L0x7YR7lXVY4hhLLCkcIxiMyShlnP86lMWoRoyoYY5cKUwa64ofwypScwg+a2/SWyL3X4MkqT26TpGZp6/KLOmTr+qcTOf9kKh73cf7pw3h+HM9Pv3v/wh/wWhkjvt0eGMyMRkgGM7S6FThflOTW/q920Fyu+di0JFd4szAYdnj2IMom8Q+mF40uwtOnQcs23IlNhDZMHlp4SnIWW4If4Z1oJgZ7ZYGdF+mmXqvw6Tple7F9YzXeSKNainNXKKxEiWWFI0wYPO8QHNVsKZ6xKzhCf5e/aCRttIk67jQj/ViTj5SjzAkJnoQl5CGjctaiD67sMScZhYD1uaB34+Sbk3tqGjyMxzTG2CQ8bkEJeR2eryxZHbj0u7kNTmySYjjRPkX5cIXtDBZV3rNOdIeO1+u+H0+OhBygBrpt7c8fFuHi6SNcRL2Lx2t4vIr2U6fcmlItvs0+GLv85sEFWdSkjYyTcwrn4zv+DpoUViUj3kTwXinaUcUoAsXhfWHaB4NeE7LnHyQshcJWlFhWOIKDZUql8CqP0gpcHNi1wpSRRPKQdc9IXTxxSOGJ1NGhQxZ5wTtQ2y7SO2kw6MTmnXJvz6yBgN+xbH9ZfY5M/lrXP73J7//oiM2b37aywlqT4DVhici1KqtGqATjQ9mFwrQdyvj46ZzaofhuDcNF1Ml4nI3HKLQvO/Rc7+nte9q+ly4lyQXXTskpuAmS2C/4ZlP+aMlhV1HxI2FEFc50R8ZhxrlToX2KOEeJZYUzMDZCtGwDJdYGkb4o6vQZws92wpNuAfu6XPD+c9e8tS2rm8v2PKkHj/KCq8loVIA1P/jgj599wnKG37719arYrD/gdru+6NIltYLzT3/udbDbtsIKzCKRi6LR9rG7ouKNzEDgk2G6/skdfY9KeQu7HJ0vVn/rgy0r/1lThpYbh55nbyQIgeL8//D/D2BTxqdDTdElPamzFHG804tH0QbQX4KWfeBn5FTOfkWco8SywilaLTwQKQz4o8H0RRLANCnSOYXK6q8bO5RtDtjqrktIYnBgXvMi54eCBtFyDh212I8L6o02ijA3HjnturkHGh32YNWYa5tn+ZjLU87j/JOi9PSMHS4X+0j3sRl//OTrKb7sKIvebvqa2O+sREhKV9PXP3Cm+FGrUDEoHVpPDWkB6iJQOIK60BROYdvkLqjVG+tCrgZnJxOHzKNSrPZWv4tBhp5OAqfpyyCAS5wVn9ucQrcZln/k3O/lllXesy91XNYeruMYYxQCYcwP5O1vrItOIcxVXzf92Xi8DA7IlWyPnRzkiCJIUceJqot4Vdo9rygUBkosK2zHiR3LOGi+MG3ZhXaXww0Jl8slhXdHJoxH5+c371XesNQPvvroCLLtawNQtU0Xlr0wq0SuRfmaQ2HjMr9oOc+2NYFmr4tDRlNIj9JKuxOlIkj/QFRdtNWBgZ/+P+N0FAobUGJZYTv0SA5Pds643B8IOPHIr1Vo5zyeRgYtxU76HpkAHfZsPsqj5LfoCTKi5Ddn5lxulchlzhUl2bE+enqE48hRur7phQxtFh14gj3pnmOcM0QxpKjjg0YqDmVjaByXI+xO0eZRYlnhFDY+6+YfGOmKJIB7GeUp9gQtxU4Ou7DlDVlV26LjVd5J1fYY8ywbvnpnqK+K7mfT0u8//AL7N/rFIJoohhR1Zi46bwOOil8K03o4c36jgyIuUWJZ4RTBXVT28LU4RxXKU4wSZqwwFYKufd2w9wEtrx+iFYKxE6d+v4Uxy46N3c7J8mZo4fd3G+CGPXPU2vQfMHapURRJAvDO2iaaNsBrREOhsBUllhWOgAOmbYUEOLAy0Ywqnbq2ozLR7YOWYieHheD98yRFV5FRpg6HsGbM5c5J2GhnnWhuU+hOlHe5SdJEUSQJYLWiYTl4G1SJpkJhK0osKxwBpzvbBjXOueMBrzU1/+sUCHx0PBW04PyTZyg/b/seborPU+xCWgcNBp/cetaC9I7RHYrSHPr9VuVZRhwTy+17Ru+zoSVBVo+WMxr2Oyah1e+JRxJTtDtqyj4b9NlndzeT2dwhuH06Ay+PctFUKGxFiWWFQ3DbMlVoHGybKdeufc7r8328n65/fAkK4gfweB+PzSkpnq0ul+t/mgYPMMYuWf2NL2f7HwHHBEys0FIRkl3p3Dt6YocEWefezugJ5rLoWnWgKMlOug+KntbqvK8b3K2stWjLpBNFSmKNhhrece3PDUuOOuroKhyzfsLjOV3/5JZA4JMT6+o+7Ca+zX4YpIqW5XDOt4umQmErSiwrHIEDs21Q4xprJ5phQ+nt6us/6hkIfHy6rn86kfNPXsHJZVnPnntWeTzaT/j1Z1BU3YTHiXj8o8DKNy/ViZZiJ57ElouQ7Er3gW5ITI7OWqNjLxekZDnzuw/ITbqosfHjAcIMG04SxCH2HOqBxJTofDZ9Dg8tHpmKlHjTovMaZebrl+ppMejFYz88LsJh7j6Xi72flOTeiONbCR4f4Vj3II55l/n9nxy0dev/UsQ/tQ4OHUXLchi3Mx5aofgLJZYVjsA4LxFN6+G8q2iFRDCEgsr4fnodThaz8fgKRXKZ1+ta63Jpb2kaTGOMjcbJZQAerbrVKBfs6m9UBqPdGXpGIiRnhiZgNHyX6XF6NBh4vHPFLbwprCstvvDaC3sjaHn5Rxmd93H3E6btuFCvDgkhlMZq8N6DnDND+70JuNA64BzlXd6dtUU+2LS86Sg1fH874jEMx7obcMx7yu1m33Xq5KGS7yvwKEQR/X84Tg5vbPxw34KCgrCfiODvsC2Nna6xTaKpUNiKEssKR+AAG0TTchiwPqL5N6qqPm7v9390hK5/MgYH/4fx+AiPrcEQCvYRThAP40A+Fo/D8Ah75/g3L9cb+WAVf4HvJxzWQhGSpjhohPNih4pa7H+2c0KQrhN8b7x47dEi7Xmznjy//9P9MzJcPyels86iyxEOv8gL+Jodpe9RCdBhr9A12iHn4muMXjSPtJB3OVTw2nTh0QeP4Sii78JxsjAhwb0yN7fDLqEcn96GIvpUehLXWsGpmwcXZOHJtpAPPRBYL5oKha0osaxwCGbboKa52P6BwMcnoCgej4P5o5x/8gmeN6eladvdbtcXOJ4/gYP/dXgMw6OT+GeWUFvOYdHbKtXn7ux7uDmhQ/Qc6oZ9DnY2Ddh+KJQzujg3DPJd0jnjtXhhp06eb+rrP9lTdLUIipSrXS74Cv9dL6cXZ+17uuCAXOcWMy4PgxOuTRZWaNDn6ORTglhh6f8aI65QiddcEh4ilAPuQRG9kJ7E4bhbjmPtV3g8gePvDYHARyc3NLy/1913323cVF43O8z4ATbRUF23VjQVCltRYlnhCIzxNaJpObrOM3f8wT9AUfxfHMyvZowdg+d/xBXbwY+F9eBrUG7l3QklXVxTnH5HCrhRKDlBSpYGJ4w3J8isBq/TwYmJ7Fu//6MDRdc/+PnnOR4UI0+jSHkUvz+oBqNwyZ14XTK06+6M6/bYMUnQaR/zv0tt9PsnAR+H7+bak+Yer8d0POjJ3Bgcfx90uVzvJiYm/n7nnbSp8JOiIccnPCC+1Q62/XvNxSobhsIRlFi2iNrLtC6NY5P6U1vXPx1Fq2zaMEETnfENcQ7X/atE0xZWfGFjgcBmCPgBvrVpEtoJedhi7dEybQbr1i+8DArkjT71NvsFLE7ukDc1FZIynBHmO2nKI4yvpQuKjE8DgU/OEF1/UlHxRmZOzr7v4fdcKroMeBTifhJTGZz7QJrtOan7HZ0AR12RJKzQqd6uw0eP2pbS1xY8Xgan3JwCXnxv7eSHwgbwO/gADK9XvInZ0PVL/E2GyFmErXOKQrErSixbQM3FWqckl/cjt86OFl1daJVNGyZwoqvAFfYXnH/6MKUf8/k+HLp8eUF0djJFkanFo7cyxmzzAix533mxvOyDhogfb7bG/mclwthnM6D9HrGjmBtqODw6qhzWLQov/TVl0DjsfPNiyQyn3ZYCvQ91fh3L9aZFLokLHDMKA4GP80QX1NV90j09PeNr/Now0fUn0YqR79rXBRf8xz7BTGE4o+5JMxYzZqANto+MqoDfvo+djbZU2fKqlzKMpzAHj7bXI15brjseLkafScVWW8fHpeIc91DsOGXZQY1xBWqNp1BzvEj9Wy/WUvRxyWOMb1JEhBLLEVJ9vtYhOdH7EQ7ulDnB2KHOOf9zxYt9SSgSj8DzdZR+zONxF/Xv36EaL+hf8IJ+DY8Zuv7JpYHAR8dQrFfUE8iHAe2UpgwTPt/HQyhmTdc/vQyPO/FvexyPt/BvLcZjx5457kzxTyxn869+2LDU2dokX71os1fZzeDIS5OMPLdXv5oB+58dO4+YaZJ86ooK+PypurCE3Sm3JMORl1gvmMlLf8aEFNvFSbO08F7gGOHBMeIVvHfOozhmr5d9hn3G06p/ECWxTFDp8sufTIf0TtZOH5T54sJH0lvNq7wregDgf/+pheevqYSaUnsXrlaBnykccVESjHsxw0hbSNDi0G6P/TevOJve8usX7P19g0/2plLOaBKJO3a8mSa62zybN7+d7PN9lBPM/f/Jgzi3fkax4wkJ2jIcP+bg9XWZ+FZon+jph1fVLH2c93zRpQgTFo3HeW2Fqku09qkeQyhnk43v5QdsTt1JDQ0f9E5MTAjrERF+HKT41mNrI5630IF9W9HGMyvF6aFU11mp3892NDZW1mzc6KsdMCAvYrcqCd5hw1JTcIJOcbs9aZqmp6PIR3Gr4Zmn4zkL/872+Dqy8LKhHc7U7oxt2jDXHr/Wqutz4b018O0r9gnM/sckwHkPOjNmri3yw5OXVQjLHih37Dn/9/d8/sv+1whvTK2BusrYEAYEeQvzpqVCanvz4mrxOw3w5vQaw1sdKSTucqemQq8DW/Yov353Dfz0uj3XKWVsIK92S+B9/iv+nzZUNbvxb9YFFbBxmT2LQ7rm6NprjboKDm/PrIEl7zeEtSDaSUo7DU7FxdGQU81tzqvYrMO8CdWwrjh2vMnGNZiP1+BB/7wG33+oFr58zl6BefFj6Y48UXFifBz3fAb0GPyXbwmvwXL8/wackyidHJ75JryXNnOu07kkEPCV1NToJVlZJ1cG/4W8UCYnrxf21DToifPwXjgW7IXdffFvI4cc9rXs6NR1+D9NO+ZuEskaaC/i7enXgY92za4rFN+iMIkSy2FScZmWme72foirtv1FFzl71rEnavck7/BRRx1dixe0I8958SMksVyDBz1nozbNonhuqgw0o9GFwkB2nmmGSsHXantoSDEKn4JJ1cKyHvwbYMwzGbBHtv3O+VduqYLlH9kX+kFpuq57LdPIQrA7lSU6FE6uhjU/xI5IIKFMgjmcbBf095KQWPJeeKKM4r4PykuEYVclh1S4wk6xTBUNaRNjS+DfuA6v5Z7CbJLHz6uATb9EVyzvhMJtPnuqDlZ91Wjq80nO0Iz3g8IQzBYU+eXjRnjt7mpcNMbO/DXguAQ4e0rzcfI1pRweOLXM1g3D+x6WABc9aq9Dgbz9tJijp312QZuAJ3+VZeQANwteo3RzU0VZPHgpzhx40BnKUVRXYRvFNKc2nnUKgq/nXKvl3I+Hq5FzX6Ouu/DgfhTgPrR5IJCoBwLVhgfD5UrVEhL8CS6XNwGFrlvTeCJjWhq2U/G+pgMHAJ4RdEBxKqiVia+BCrdQvQBKs9cFvyeiR18ols9HsfwyH5ecj1fbZOrDq6pR5/wc1xN17xjfpDCFEsthUD5Ky8jI8H6AF+FBossA30le0lCf1vk5vYbzT3/FCx5XgoqdlK7X4cEzy4RlDxQHSI83QymxHC5lm3R46IwyGpBsI/vURENcNgfdtl89VwcfPlZn7HaPBfB+gKOvSIJjxyWHtWlx+9oAfD+33ohPrw7hkTtlbhhySgIcPMILaSZCBmwVyyNRLE+wQCyfi2LZJjFiVizvpBzvi2W4gPz9Rx9sXOr/x2dEi5b2PTWjImCfIzxGekGzYieA68P3H6yBb1+NndzmFF5x2u0pIb2n79xbA9/Y+PSN7sFrCzL/DP+wg0+fqIOPHrd3o2XPbA+MeTZdWIrd8fv9B7rdx/+IYrkAP/Jc0U0apQ4XM6e5nqz9RHQpQkSJZZPsuEJLy2Le93HQOVR0/Q0/BA5wP9HwE8Xq4krydNGtENx7QhlUbbc3hOCIi5PgpBvsy6jw9owa+G6eHBPa5l8DMH9CFWz7IyB65GfPHA+MnJEK6Z3Di3mlIWvrygBsWObHBVjAyHXtb+SGKKGKgeSN32OI23Se553YKZap8MoZEyMXy4+hWLbLcxeuWN6dxlpueH5J4CYkASS30yLK7EKL7bm3V9nmUbeDHoPcxqK3qSdETUFPUR48vRz8Ni6A7QxX++1bHzw/vtLwLtvJMWOS4Liro5v2UWbKywOZmZnHVaBYXorTyUDRbYBXVnVAD5zontPwjehShEB4s1WcQjtLszTvwuaEMqHpRkwRwlRamyZoKlbPar56vs627BjbUZT+uMDeXeX0uDZUz0/Xfi646pVMOCgvdjb/UQneR0dVwIrPw/uMaDHRpa8LDhieCCdenwxn35ViCJIzJ6fA8eOTjY1i4Qplu7HKN7FrcRNZoRLUVCgkaw8NUjtEJpSXvNeIC4TymBHKFEZFgo7CwkIVygTFNFuxUGmJXz5thF8/s358pIX7q7dV2S6UCSfmkVgFx5gSEsqfDdPo+eq+wd6/wOEz1aW53vFd7t1PdClCQInlENl8lpbcKSHxLbzQjhRdTcKYtjMjxkqjQ/E3eh9i/yBHgmTBlGpY9bW1Mb00CSy4sxoCfvu8PiQEj7nCnMfEgzr5jEkpcP5DacZmqVigtkKHl26ogvf+XWvkq44brLp07LsEpcJXD/DGv2pg3oQqSzZ5OkFmVw0uezLD8HwacsUklAGHMuHYyev4ntIGSavYsMQPz15ZCfVV9n9GFN9OoTyK5ghqj0P3Ttwbr6Im9yJhf6bbrb3vG+f9m9dZ0TxKLIfAhlFaUpfOiW8wxo4VXS1hpHriXHmWm6LPkQmG18Vu6DHmyyjGyCNlFQvvqYH1OCnYSV98f8hrGg5UzGH8vAzY97DYmEhoUfPVC3Uw5+IKKN0QA65SC7DMsxwHYrnktwDMuqAcfnzNvpAnqxlyciJcMzcT9swJf9NEZjcNsk+zd781pdl77ppKo5BLpFD+5qfHVhoLYCfoczjOIfbv4Y5hgtrD5W4m7aQABXMHN2j/axiT3Ft0KVpAieVWWH2altg9I7GQATtedLWMyLXs8wWUWG4Ciint6ZBXgATz/IlV8M59NRFVryJh8u4DtfD9fPsnbXp0Gwn0uPuiR9Ph1FtSwJ1gr3fKKjYu98Pj55bD0g/syy4iC6GFT7BWpXBb32vy02sNRkYFEsyxAFWtpFCgETNSTWf2aIqjLkuy3amw7fcAzLmkMuzQFirI9OqtVVA4pRp89c5dj4NOsD1xU0yDY4OhPXAUESGhzYNXatcEDT6sv0RrcY+EQonlFlk+SkvYp7u3AIXyKaIrFPalWKF77vlyA85nzmaBjxEGn+zcYEea4puX63f0Ps8AAHwnSURBVOGRkeVhxchWlejwwvgq+PpF+z9Kyn9KBUis4NDzvXDlSxnQuXdsuGDqq7mxeevNqZEtbOKGNqqVaVPg/AnV8Pq/nBVgkUCL//HzMo0MNlZBcc6DTrI3dpko3RiAJy6qNFIz0kbZUKjcGkzl+NBZ5bDsQ2cXuLQQoaeTiubhnBlhGCiEWxXLBH7fnomJiR/WXqRR6jpFM1iWDWM4az8YtXcSB2b4TnQ8u/5s+4w29dFBfW48B0Q7AA2658820/2g6QniTH0JUIvt4NcbsS9JtBvApdfhkQYlehX9GmQbnjuK9qd41nl4Cb5+PlDz5Az1zmMMzhZdIdPYyPsmPFu3kvNPF+O/x/dFsSu1ZRzuPbHM1tjf5ujW3w0HjfTCwOMSWvQAVWzR4YeCeqOISgNO4E5Am4F6DrVW3PpxLvvgodhKtUUCf9S9qdBx7+hs0rMzGwZt3tq90Mzu4OfUajaM/wwvNzyDdmBVNgyzbF4RgLm3VcGOdbHhTaYNi8eOTTbSITIb3E7b1gTgv3nljt23Hi8zQrkojItScFK6RfJu19dwI+sMFcFZ9ZXP2KAbrbGENjLT/gxF8/h8erbHM2wxH5f8Dc5wh4juVsGPdFlNdf0xqS/p289hnQ7AKzyBQ0DHS0DfXde1pOla0nNNabmdOo76dmq5nTouEg1nNRaK5S5UoOM4YcoIveE73/Sd7ab6aKXlu+6Y+l+P2rexxc18zRHQ+VmuJ+veRLFciJPecNGt2IW5t1XD0v9Fz4VIEx0JZ5oUMjpr4Eli4G/gUI4imXLEbl7hd3RC2Gv/YAlhu6BJbsFd1VC9Y+flLjdmctNajZ1iOeeMRBj+r1bF8locN5qt3kc8fHa5kXfaDqIhlmlR+v6DtbamTLOSrB4uGDE99W8V5OyAwhyc9t7KzDWvZoa9pyMewLGDb9lSndq16+m1KJbLUMtkii+FBN59P1f66o+77Jn2BwK4XscumfLz7dRof2o1cf5HH/4dOv7tu/ZXvwYl/VB4hz3AWLge5utFQ1bob6WRjQ56jkO5tuhCoJmLDlIqmQxY+kWHNKwKVygTTNv5+ENlxGiOA/OcF0G7QpktNqAo/qGwHj58rBbefaAG/vdIreFNpmIPTntOIo1Vbo19D/fAtfMzod9RsfEIs7GOw2v/Vw0Fk6uNdlvB6etKdih7wis3Vxml8GNFKFNqwmvm/r3Usl1QZhxcOCkQys+uhHKrbCChXHuZ1sWsUCbw3+yX7vG+M2vkjm9Qd5+MXTKVBt+p4Xbqt101nKHfxJGFf0cHPHfCowse3XDkrY1EKBMWimW2QTRiGX7uAfXfnjm44TBhhwUKbpURoxUoT2aXfe2fbGIBKqARThlosyS3Y3D+w2lwxoQU45FrLFC8sMGoVrdlRWw8mm8Vi/RgWxDd6xf74dFR5bD849jwnCalMxh9bxoMvzvVyCHtBCQOKUOOAuCIi2Inl3wUMTRHouZtMRNGS+CVfWiHzMQ3/jNy248cAidgF5UCj3HYCtEIG8vEMgc91sUyH7Ffw1e5OZEJZYHhWdZ1XYnlFjjiYjX4EceMcfZJF8VsX/VyhhGCEgtQuMHsCyvgu1djJ4VYc1glcmOhKElz0HvwxTN18ORlFVBuYa5fO9n7gOAmvoFRyMRg91OnWIAcK32PVouG1hGZMP58uh0eDNiw7hnegqkjdyzyAQzDrpLgV2IWecQyvr2yh2E0C2MMzslu+HL0/g1HiK5IMS7UhgZQYRgtMPjkROiwZ3w/VqO46T5HOJ8XmTbPjXsxA468JCkmHvPSI/q376mBV26pcqTwgV2EKJZb/64YfQtqyji8ML4SPvhPrSOV3iKFioOceF0yXPpEetjl2SOFMuTESu50uxh2ZWyMU9Hmr0wYPCKxTOD7fWr/TO/LNx9bsswP+tHYtTH4ldiDgy6TZ9kfk55lEsqnDWz48oKDGsKOUd4dvKczKQ1LSsqwrTg5yhTzIxW0yW7YlTLtH3CeY66IntfI5QajXPQls1AIdIqOEDDL8o8a4dHRFUa8eUwSmshtVRbEolb+/Ucqc15ueWVNu6CF/Njn042KetEWak4/fZIJilXuP0x5lUNhZ45lJOwwjF3Byz73qH29T+/Htq9shIajsOv34FdiiwCwX0UzbCybIQOgx6Rn+aR+DZ9femi9VR7lP0lM8O5c2alQjBagnMt7OLBRRkY693ZJMQlQ/Pj4+Zkw8PjYmJDKNwXgyUsr4ctnYy+NuXVhGLEjlylk5OPH6+DZcZVGIYtY4MBcL1z9aobx5EcGKKUkhYLEG7RIOfWW+HaomCEQ8Af1BmMRe5Z3gh/BhXeOSXxsIav4XQc/eZhj7Yk5r4Kgxz0SLBPLb/GyMjzVBK3YYFjfxs/GHFFPqyXL2SVmSIVitMJpt6VE3XMTDY6+Qp5JwNi8dF+akTaM0rbJDuXofv/hWqNgDOXtjhUsE8sx8idTUR8qhfzJE7UgR7bUlknO1OC8f6fBmZND3wRL4SSUbpLS3709owZevK4Knrq8Ep68rBJeuLYKFtxZDZ8/VQerv/EZRVfCJR5jl2l/RbcBaiN4KOCY4F+9umLNtlEaZYfoEey1BgZsXGCM9/7X+Pb1Aag9Cq/iJeJLscDGj/mWatEOG6ufvcaMd/mo3v7PrzmqnlZJtsCA73wMojzLrUAxeYeMjq/NfvSIV8ayrZRflzxqPSyqJGg3K79qhEdGlRuP+GOC0LRS698VA2J55Zc+/Gwq4I+fYuOzoQqa187PgP7HhnZfrvnBZ5R6nn50Kcy6sMJIf/fdvHpY8UUj/PFzsHjHyi8boeitBiMt5XNXV8K0o0rh2SsroejNBqNgkBnoCRCFJMQLGV00OOFa5VU2wdoBA/Ia26V5+uEyz3KPB/7Am/i45PzXeeVWBvXHYtePwa9IT8QhGITVYjkm4pYP29v/+fXH1triUd4Fw7PMucqIEQrH46DYfo/42ex3/PhkW6p+WQGV2qVqguTJogpeskOP9ukR/8ez6qTPEhFa+ETr85zMWln3g1Fg5MXrKqG2XH53stvD4JSbU+Dix9IhtUPrFzwV+Hn8vAp4ZmwlLHq7ARpqQv80yAv923fBAkEPnFoGX79Yb7xfoXLmpBRw4ett69C4kzc1DRJT2v7fah3BeGVNsy4EY3fw05isj0u6vZCX76iHwHH4O78UX5IYHvHmPsLiqVD6wiRwQE//5zcfb7tQxrcieMHqeuSxMvEAPfqnili0+7yt0/+YBMvjg+mxPE3aDdXcEsGouQGOuzoZLn8qAzK7yb+IoUf8n8yuhWckj4sNUVa1ehPIuigo26TDnMsq4MvnceEis6IXdNonmBXmsAtaf7JF1S9fur4Knh9fCZt+iXyDKf08Kob0yIhyWF8c2s+j13vkJW3/KdzRY5Jhr/1V+IU5RCYMptkmlgkN2Ex9TPL4hXxbZQ1sOxlnnCl4q/8bjyfwyy/j8SYeH+PxPfYtx/M6PChXc1QSquNrsEQsW1bumshlXf6FpylBKyJoKrDcpzV0D//nU052QCgj+K7y7RX16Ylz3vakpye3gaTezvDNy/Xwzn0xFfpuCm8ag+sKMiEtguwT5J2iR9sUekCT7La1ASM2dNdbOSldgw57akYu5b0P9BippxJTw1uIUKq2t6bXwOL3olee3Awp7TSjpHS4KfnsLHc9YFgCnPtAmrCahnP2B2N8L2E2yb0nlEHVdnsUc7jlrqm4CFVdjIXUfrRH4uBRXjjphhRwh/CnUsjFvDuqoabUnvecMgPR0yZK5dgaAdTVsy+oMEryt0X6HpUA5z+UFpf7WCJB1/m1mnbsI3xsciG+d8NFty2QvsFjjDa79inRFRIHMs3TATLSEoDiql3JeCdSeR+amf488NtS8Wdjmx2K7dONfxgRgRML+bb/CSNsLBbLncfgj6TVRYToF66E7fN6QVq6Dlq6C99YBp4/30x8xekMeLp4Q1PwH2Afxz7APma82bu86Ub/oK6B7+4+vcay9HCh4NcDB7qfbPiR80+34cVL5RcVIVA4uRoWLYwNYWaWEdPTYMgp4XmVyzfpxmKi+N0G05O2J5EZk9Ch53mNnfXhUPxOgyGazTx2jhY00R5xcRIcf02y4SU3g51imZ4qnPdg5GL5nuPLDM+kHZgVyxR7+94DwXjdWCA1S4Nz7g59MbXkvUYovLMaAg6U46YsHGdMan3Dc8lvASMUxN8o/71oBio+csUz6Sr8IgwCATjZ5TrmfT4ueRm+ewNEt23glRfgXL9Qe6L+FdFlKcNZ5ymo78gBGxF+8O35Bt9B3u2IsFosn4I/8h1hhg0K30kL+NbpwowY/Yqka5nGHsYLyNE7UEfRjxfSiyiWv8LBz4rKgHFBwAfw7FWVMbMxKFQGn5QII2fSGs4cdRUcPny0Fn5cUG94lSOFSmufemuK8UjXLCTYC3AxQ5uXYoEeg934nqdBu26he/LtFMv9jg56zVoiFLE887gy27ycZsTyjnUBmHtbdcx4Oal0NP19KVmhTQXL/tcI8+6ocjSTBwlmysbRGt/PrzcWr22FzK4ajH02I6KnbvFMQ4Ov17ennLT+qH29NXh1O7J7HNWjX9f5CNecutdFl2WgnnwOJdtFwgyXmtegJE23INemxVdlwJKYZVxN7CGaEaOPSR4XDaFMML4zdujPROGKEHB5AM5/MA269ms7MWuU/eKsKa1PgLvzyyeN8NDZ5cbEaFXFM9pgRMUhwtkQl4mi8/In0+G4q5KNR8eys2GJHx4/t9wIEZACq3wT1vk4wqZ4YQM8Njo2wgEoDdwZE1Lggv+khSyUKR1cwaRqx1Pe/VBYD1+EkEP8oBFeGHKy+XAZGaHqiJc+oYRyuHAODW+9VbHu0F6J+zgllAn8XW5NY68GxiWfJLosgwPrLZoRwFdZIZQJS69MDrpV2TAsEcv6FcmXMwaPR0MoG7BgFR3OmRLLJqHY3ktnpRsxt7EObV4cfb+5nd30wIcyCrx8U5UtGQVIeNOGOEpjZTbGlLJ4HDM2yciYkdVDfsVcV8nhlZurjBy4ZtN1WY1VD/IsfCBoGl89N7I50BOGxroovpAQoTHkqpcyjJy9oUIbZV+5tcoosx4NPvxvLawtan0RcvZdKTHvVMjq7sIFOI0lSihHwJq8vLyA66/6Do6Bs1oifnIL/OMSLU3Fiz/XArEceeW+nVh6dS7gpeV4ijj5Mw5PPUUzbPQx3otxUn8iakKZ4DsvXK4yYoRBUgaDy+akQ8+hsZtblGIPc6emGtX6QoW8vQUTq42MAnZDG5fmXFIBNaXmRQGFOFwzNwNyzowN7xbF1D5xUYUROhAtLBPLDns7d7J1VTBWlvIEy44Rt35REox7IQM69jK3qPvgP7VQsSVKbzJC3uw3/kVx0qKjGchjfsHDaZAWQso7GSGhP+bZdCWUI0dkwnBeLBN4qyW7wPWW//LEg0VXRJzGOqbjqVPQCh8cbi3JhEHYcYVGHIqBb3xEnmUUyucxpj2FPye6dyCD3p8N09yBQEB5lsOEPMyXPJ4OA49z7MmSpZx4fbKRAcEMb05zNvNEyZqAUTAhnI17CckMht+dCqPvTTOqAMoOhQxQ6ACFEEQFi8SyhT8oZH4sbIDZF1bAtt+jt9gIlfROGlwyKx1OujHZCOsywza8H34oiP5mxW1/BOD7EDZN0t960aPpMXH/7QqN6WOeCS23taI1gqGeDNjOYmiOg1dfmsvtetd3hTdbdIWNB7R9RDNCdKnFshWhGJnnsE4t74JpBv0K70gUys/hBxf158P4GhIohqi0lK/iPAqzWxvB4wUjjOHYscmt7hKXicMvTDIyMpjh21frjY18TkMiksryhsvAExJg/LxM2PsA+Z8CUOgAhRBQKAGFFDiJVRuqnQzDoJCEubdXwxtT8f1qkH8Yo8UpXYtU8S4cPn1SnhzRFLvcmneZ6NLHBRc8nB4Tpeopl/5J1ycbY3qoJcUVLbNLqGdUPMs7wU+zndulfdA4Niki0Y7izYIQDNSDsoZhCCzZ5KeDbjoUIzA2aTjTtJfwA5MmiItiiDp3PoG2LG8K9ijCZdhVSYYHJSVLfk/EgXleOPkmc6Vat64OwHv/rhWW89AmuFA8Wc0R3KSTbkyEsVBljEIJKKSAQgucIjQR1vp3ORWGsWm5Hx47twKWfiB/2AUJxbPvTDXyWFMIVzjUlnNY9qEkm0ERyqVNm3xDgVJC0lM4ehonK7TRmVLDHRFCPmlF6HAe2BnqGVWxTODV18nD2P8arkjuJbpMgwOgFWKZ18M2y0JgZfUs4xvuNh2KoQH7l0xCmWB/xS2rUAwL6H2oB64tyIQBEodlHHZBklGW1ixv5DuTy7UlKFazOoJiF0acKE6EY59LNyZG2aGQAgotoBADR7Dq43XgMqFSzE9cUgmlG+QPu+g+0A1Xv5oB+58TWfz80v81RP0e3B3Kbx4qe2S74bI5GUZohkxQ5hx60nbN3EzoMajtZDmShcZGbVXdFVo3HH4zRFdUwdfRPcEFH5WP0sJ6PcySTBiw4T2uW5Zb0fI7Sreo5LULeBhxyzzixNNW81cMkSp7bRUp7Rice3+aESdL3kxZIKF48o0pcMrN5jzKBHmP1i+Ofgouilv+7KnINxZ260/iJRMOypO/NC+FFlCIAYUaUMiBnVjlEbYzTIDyelNZZyrFLJtw3B0Nb/+jL8fF2bMZ0L5n5Iuz1d/Ilz/89x98oJsYGrr2dcGVL2QY96AM7LW/B65+JdN40hZKtUSFOXAsqElJOW5Tgssbda/yruB0uJeWHnY4rBUxy5aFYBCWKw0OzBLPMv4c8xkxuFGDXC7E7lTOlWfZaihO9vrXMo3JMtqxb7S55vyH0+Hwi8ITh1YIVKv4cUED1JZFLpIo1pyqkVERDipBLTsUakAhB7Sxyi5CFLmtXsx2iuUPHq6BXz+XJxShOTK6BHPzUplos1Uam2PdIvlyRjfUctiyytzronzFY3ABEc3FKlXju+A/6UZe9s77yv+UKXbhq3Rd5zhoSCWWcYiqTp+jlwrTLBF7ljlwyzb3ETaIZb9FhUnMe5bxw1krmjIhxLLKtWwHFKdIk+WNb2bCIaO9Rllnp6HUdte8mgl9jwxvQxHFKm9cJs8kTSV0zTz6bQ2qWjd+XoYRQiM7FHKwblHUvYutS2EbxbLTRTjCgaph0ia+vfa3zntK8co1ZXL+8eFkIHEn/LVYzXDwCVz3AW4jbvzquRlhj4kKMwS1BWomqcQyEpYWPItp9Gi2W9CKBCa3WK4DblFhknCq+HHpxDJKtwyKJQoE/CoMw0bSOmpw2u0pcNPCTDjq0iRIzrB/ckhMZnDabSlwxdPpkNE1/N+39H/yefGsfk2UHurix9Lh1FtSwB0Dm//swiohaqdnWWaosE9ufqpRNt7qjWyVW+VdJUTy2mixet2C4Lho1xM4uqepmiCFw1z5UoaRkSSWMhfFNn/WcYha2rimCS8s1gXtKAQj4quHQUBusfwB31GBp8qgFQnmPcs6k08sEwnc22/dOv8anODk3ykT46S21+CE65Lh1vfbwTn/lwp75ngsH7Qp0wN5sW98qx0ccq434p//27fyieUNS31h5V1ujUPP98KVL2eYKtLSprDoLY1HsbzHECqCkwlDT7cn8JXCHWQl0nuR8qHTuEhP4KhQixULDRr3qDDR6benwG0ftoMRM1KNDYYKZ/nrqTWTy7PMw/Msc/BYlDaOyx2zTOBtbYF3me2hMc3UHe0Dn5RimWnQr3fvk+m5tnwx1W0U2kiy31mJhtf3+tcz4birkiMWaCTEjxmTBDcvzDS82ClZkU84tOFr86/yraGoHPaWlfa8LvocrnwpEw61YKERa1gmcuNILFMmhWPHJeO9nAHtutv/xKgtQ0/gqFDLbR+0g7xpqdD3yARToWvkKOh1oMd4QnTzO+1g3PMZcPBob8wVRGlL6DpfteMKjepSdA/2yAEOUWHpHbzDrRDLNW9AqUVRDkHsGnmseJHecyC1o2iHxMIK2IwfkHTbmRnwnY9HVChGFKBd8seMTYLx8zPhhjcyjYF+38M8rT6SJCFHm1TIi0zVwGiCOe7qZGPCsYryzboRIywjdlZqo3jKU29LgQv/mw6pMZA32ypCFMutfpdVxU1kJ6u7yxDJw65MMkSznVCIh6wkplr72mjsyz41ES74TxpM/DwLLn8yA065OQX2P9tr7C3o1s8NHfdyGQd5j8kbTWW1J37azsilTk+IaIOlIvrU19eszHB5+uEVItcFzFi4+9csyITBV+pct3SQZHYMusNZlyfxU7tcmGHDQT9gAS/5SZghwccmrWHA9hamFHDgH7In6k7g/JP/MsbGi25FlAn4ATYu9Rsp2/wNnJ4AGI8nKXND1h4u6IATBWV0sJMN+Pspz6+MnHBtMhx1mf3FAyjzxmv/Vx0TGRgipWe2B8Y8my6spsEh+XdcqLU4ht253w7rvNSSQuEWp9+R4piIravkMP3ocDfv28uI6Wkw5BR5c8srogOOAWWMHZOlj/FeqGna86JbCgIAx7lm134szJBB/fgh3vHHCTMscGh8ZQHfcp4wLUFmzzL+wZr59HHAJAzFCMYSqYwYcuFyB6teUbq3o8ckwVGXJ8FBI71GSrqu/ewXykSjxHGSTr225HaUdi8NzpiQYtsGJFmIF49wJNCCdeTMNGMjn5PeXgoloFArGenUS6VeUzRJMBMG02TLhAEBf3g1N/COtyIMw9LNfYRNI4M1hUm0cAqTcCnTx3WnmKJdSlIqFAbuBHnFodOvjRYqV72UAV37tt1NQlZp5baquamABaWEG3xSdLyoe+bId+15Uxl0itcNsYpWEJkwmFyZMHB44pt5g2kdeBrTaPduGJnQ/g6zOMcyYYtYtqowCf7J4bxpMqaPYxm6p5/frynPsuJvWJ3+ykqsjpMMhY69XDDuxQwjRrJNbv6zQOS2RaHscjM4YXwyXPZEelRjYXsfKl+oQ6+DPbbHaytik12eVsvmWd6259N6vWiHjBfa98JTxAMAalBLM2EQNo1KAUs8yzgnmA7DwH8jZUYMzcX6ffvt52txomv7gZmKkGnX3SWtKGy/R3RmaAqPoR37tKkyvVP0hJMdhCh0W/6uNiaWaQMuxXFTGBTtG4gmg05IkO5pz9BTVY1oRXPwVT8fqFHlF0vSrVlImJm/NCvKXPNaKLHcMWnL0IRq0BLPMg5Zpj3LOBlJmZ6Ngdb/6KPvojJta4I9CkWwJHRWDzndRtEuUdvroOAj+QHHtZ2NTZQqMARaVGttybN8wDleuGZuBnQfaD78YcuKAHz7Sj28fncNPHlZJTx8djnce0IZ3H9KGTwyohxeuLYK3rmvBpa83wjV20N74+lJz+CT5bneqPJen6PUxj5F0+g6WzlocOI+OGDIVioxLIcpDm1WiP7173G9RrQtwxaxvJBvo6IkVmzxNy2WA1zOwiQ4/e18TKJCMRR/Y+8D5SsJSwJehtRQSRkMzr0/Dc6+M9UobR7zWCF024BYpgqb5z2QBmfdaW5TZ1WJDh89VgsPnFYOj44uh4X31sBPr9fD2iIfbF8bgCoUxRVbdKOE/MovG+Gbl+th3h1VcO+JZfDU5ZXw8xsNEGgluegxVyRLE/Zw9BVJxpMWhaIpKivrV7lc0oVgEGE5LXEkkHJzH2HnbGiFd7nrMKaZGirWbWlYh3OJjNOJEsuKJul7lHxiWbbXtP85iXD1qxnQY1BsKwdLtHKMi+V9jCcGGdB/WOgeU0ov+Oa0Gvj36eXw6Zw6KN9kLgc4vWd//OwzUhQ+cGoZfD+vvlkvf9YeGhx6nv0pE1ujSx83XvcOpORRxCR4TW/Nyjq5kv3liJMGzsNO8mCBWLa2ct9ObBTLlmTEcCVDO1NVaXov1KlS3pagJRW9KbYIL3CVEUPxN/ocniBdYY6cM81P0iQ+DK/eqgBsXOaHbWsChifQKnFnxLY+k2FUUdTkertCJsQwjBbfsVgVy24PMwpfXDwrHdJMxKIXL2yAB88qgx8K6sHvi/yPJ+/zWzNq4PHzKqDkt6ZF93FXJxnXW7SgSnnn3JWiNvYpWsLQEowxqTJhGHAeZjgss0Ass1jzLFuTESMRPG0lI4aHYotwxaU8y4q/Qc9OqEqgLOx9gAe69m19lqbH2b9+2ghvo/CgGNF/HVIajBcdWQ6zLqiA/+SWw70nlUH+YaUw6/wKeP/BWvjtO1+ogrFJ6L2iKoqXPZkBmV1jUDFbIXRjUCxTnuBxL2TAYReEXuKcigYtuLMaCiZXQ32V9X/05hV+47osfof8K3+HQkNG35cWtbzfJ9+UDN0GqPgLRYsEtQSXz7OsM/PO0gOZsVFxz6AVPjoEYk0sW5NrmYMeRmESOTNiUGyRz+dTYlnxDw451wvJmdEXfyRkjrsqWVhNQ97jd+6tgZnDSuGlG6vgu3n1Roxoc14/Xz2Hjcv98OXzdfDslZXGJiyKO6VH6+FC+XCvmZsJQ06OrUwBVniFY6mwCV1PtBC86uVM6BLCAmwndM28cE0lFL31TyFrJb4GDoUoxr98rk70/EWXPi4YdW+akdbOSQ67IEmqxbNCTsjxpmka22U/lDT4dJ9pz3J36ERCOeIVYiNArIVhWFbFLxzPsqQZMaB/cvLJG3CuqxVdCoUB5TQ+5aaWRaoTZJ+aCHvu1/R41VDN4b1/18KDZ5TDN6/UQz3a4VBdqhtxpw+cVgafP1XX6oar5qDMBSNmpELeNGcrvUVCiEK3xT8mVrQyhRZd8J90OO32FHCbWNPQ9fDyTVXw2/dhXhgmoffz/Ydq4dtX/5kWtu+RHhh9f6pjHubDL0yCU26O/jigkB+8blfWXAzd8MpsuX6+w+Dt5Lv36bBCYa3Y3Ff9LuzYKNqWYptYtqowSThV/PDDktKzzBjrp+s6TXWrgz0KxV8MPSMR+h8TvTRRFNZw6q0pwvo7a3/2w3/zyuGrF1Dc+q1Ra411HP73SC08fl55s7GjoUACn1LM9Rwq30bJf2DFW2fN228rfY5IgPHzM/Fs/jOhDBerv3FGKO8KPS1p6vf2OzoBLpuTbqRxswuK5z5zUooRfqFQhAJqiVUJbq+EmTD4hrvwxQkjZPDuskIsr9S5obEsx7a7n1lUmAR/knmxHJA0fZzKiKFohdz8VOi4l/O7eshzRinaKFXb7lDmgKfHVEDF1giCjVuAQjgodvSXT8Kv15PZTYMrnko3Qkhk3hQVomO5xe+KJObbbjyJDE6/PQUu/G8apGSZ98Yu/aDR2MgXDeizmT+xGmpK//n2UxYWEv9DTkk0QkuspGs/N4x9IQMOzFOhF4rQwGtV37q1bLWMmTBw/IpiJgx7QjAI28SyblnJa246ZlmXNdcyimUjxkjsYlUodofCMS5+3NmSv7Tz/twH0prcUPTZnDojc4B5P4E5KHb01VuqYNHb4ceoUvW3Y8YmGRkzZC30YoXQDU1wOw+lOrvypQw4OMx427pKDgvvsbyWgClqy3WjkElTGGE/01Ph8qcyjE2wkULVO8+akgpX4XsWyoZahWIXNvTokVfHgEuYCSOaOZa5LZv7CNtm5Nd4SRWeyoNWJJj3LFf5GuUMwwBIpxgjlRFD0RIklEnwde5t/wTqRXF+4X/SYN/D/jn5Uwznh485F15Pgpzy4FKGjUjoMZg2/2VAzpmqTLATkKeVYm2vfDEDOu0T/jX7xbN1Rjx7tFnyfgNsWk7FVpuGNpdSWMZVL2fAoed6TaV9JM/7gOMS4Lx/p8GNb2bCAcMTo17iWxGT7NQQ8nmWWXjV+5CIS13j6GGbWGZ27qzOZV2W4GlQ0AqfGihJNVu+kI9NLsMxPFOY0hDgcDx//J16txu+FF0KRZPQhro3plK5XnsyApAncOTMVOi49z8Fzh8/+eGZcRWghx9KHDa0WY88lB32jHyxsOx/jfgeVhteSxmg3L03vNHysMQ5W8MY7yXMf1BXwWH6MaXCii5pHTQY/q9U6H1oZJ5WSg1330llRhy7DNDegfMeTBNW61BO8fVL/LBjbcAIV6LNrxzvHXpSlJrFjM+dwi26D3KrinyKiEHdNouxY6/i45I3oM4xVYvCblCwXqXNrp0lzJDQmOY6BzqRxovIw4GjR84CvmWRMC3F5jWtNenjEqGD+YwYXNZNftCvoUGlj1O0Dk20JGZH3ZMG6RZuLiLv1rHjkg1PYFNCubGWw/xJVVERykRDDf7+CdWWhCwMPCHB2PxnxWNzKwjtb2pZMMoShtH/2OAmvkiFMrH4vQZphDKx4otGqN4e+gXYsZcL9jsrEU64LtnIznLBw2lw4SNpxv176m0pRmhKz6FKKCusAceAlaUXapQFo1uwRx64bl73nQ2ZpPEifRSIU1aJbSGuNotla+KW3WFkxAAmqVgG3j8l5YQSvNgrRJdC0SKDTkyAG17PhJNvTIF0E5XPdoc28dFjY/JsDrsyCVzNaJyPHquDSps284XKpl/88N1cazZ60ULj0ifS4UQUMk7nzP0HVujBKGvKhCQGZ01ONUIJkjOteT+XvBdZ6I3V0EJx6YdyvSaFYicUypnu9fTDuy/KA9o/0QPmq/dxcFmxuW/9G1y3LW7QVrHMLfIs48s0L5ZB+owYapOfImRI6B5+kRduebcdXPxYOhww3Avt92g9TCEpXYMBwxKMLBt3fNTO8HK15KWuLNGN7Bcy8NmTdeCz6KVQXO2RlybB2OfTLQnvCBdLtHIUxXK3/m646pUMOCDXunhw8ihTCINs/BaF9HUKRSgEAmyVxpiEmTAAaqHRtO7TLBDLOCzaFq9M2CyWrSpMwkxnxMDfLalY/vMCV6EYCtPQZiB67H3WlBS44c1MmPBxlrEZcOTMNMPbR8eI6WmGoL55YTuY8Gk7I9PF0NMTISG5dSfENy/VN1uJz2los1fRm9YKdxJ7V7+aAQfmRidNlxUpQO3cZ9IctNg4Chcb4563JpZ8VzYtD0BAkmtuV2QU8AoF3v7+pUtXr2GgSZcJA+/iyoyn9XASO0S8uQ+HKNvSxhG2imUA3RLPMr4Jpj3L+KHJ6lnuFow1UhkxFJGT3I4ZsZCDT0owvH10DDklwRDUlHuYRE6o6KgNIkndZgc/v2H96yEv/ZmTU0QYgc1D4G5YonMd1pVUjIPCWCgeV7Mh5nbbH1EKjm+FmjLd2EypUEjGH/vtN8aHwkhGz3JYmg/vsvj2LFuXazkMscx1WUteM4o14pypMAyFVKxf7JciddeubFzuh4ot9rwm2qB27fwMSzaohUxo2qvF73KyKMmgExKNTXx2bpCs2ibXNbcrVSY2+SkUDiFv2jgwH69MoC6yIGY5ELtiuQo0i8IwwHQYRgPzyepZBoo10vWA8iwrpOK37+SM0VzzvX2vK7WDZoSsnHJzilFy2G5C9Cy3+EJC+xGRkZjMYPjdqTDq3lSjGIedUPYVWaHMLAqFXPCVPx+o0eo14tAFy+HmPcsaMwq1NZsqM1T8sRyG8THfUo2nsqAVPvhOmvYspz0JJTjM1QlTKijWqKamWollhVRsXiFnjKYTr+uwC7xGbme7C8HEQhjGHkPccPXcTMeKushcnlzm16aITzhnqwblJPZGXeTgI7HQwKHJtGf5FGhPeaKTg1a48Kq3YccmYdiC7QF7+OZZ4V1OzmWZ7UU7JHTd2EkjZSgGvin9MjLOKseJs0T0KBRRhwoqyMiOtc48Cu+8rwuufDHTSK9nJtbbFBYIXbvCMEgYHjs2Ga54msqFOxfLTVUkZYVynSsUMkFp41xyxisj5jOgeUGzwEPOVupW7J5uASdGREs2+QUg0XQoBl5VcoZi/HWhK++yQhpqJd3MVFvhXNyoOxGM9HoX/jfdVBnjULFC6Frind6NzG4uuPzJDBh2VZLj3lT63TJCC6bMLsq1rJALv79xJV6aUoplDloYOZatiFe2d3Mf4YRYtiRumYVTmETejBj7BGOOVEYMhTz46uUUy9F4Xfse7oHxBZnQ76gE0WMNVvwlVr8b2aclwvh5GUZWlWjQaR85BWlWD5exeFIoZAEXyvUzZ367jgGTLm0c4feZd46i8LcgEwa3NV6ZcEAsW1OYRAujMAlOKrJmxPBQzBFe+CojhkIa3IlyPnKO1utKacfg/IfT4IwJKUa6OUuwQOlaFYZBG/dGzkiDvKmpkJgSvc+ewl+oeI5s7LW/dCGhCsWau+66i0YA6TzLOLTp60vqw3GOKs9yEKvSx4XjWZa2ih+4dOhHsUfCVCiiTlK6nGI5OSO6r+ugkV646qUM6No3cs9rqEIXF9LNy2oLBPeeOR4YPzcTBp9srec8HCjcwdH0fSHS5wgllhWywVdqmpE9QsYwjJLeC/VwEuNHLJb9wNqCWA5Y4lkOp4qfLrFYZhr013VNiWWFNESzDHRLtO8Z/dfVsZcLxr2YAUdclBTR5j8T8cbNyupIKvi53AxOGJ8Mlz+ZDhld5fHm5pwhV7wDebr7WhyCo1BEDltVcwV0xyEoTXTIAw/7SX6kG/z0HVBi+1N620dLFLlRi1n2g7y5lhln/bZvr17VogdJoXCQLn3kFMtd+kQnlnZ3XPgyTroxGS6ZlQ7pncIdOkO+3S0fF2jRMeaZdDjqchT88uhkA/Isy7Ao2skBwxPBpRzLCsngXF+ZwLxyZsJg5uOVz2bpnfEfRir8133FddvTBNs+ZNbBdovCMJhpsfzdb7ARZxw5k8cy6Ne16+m12NoY7FAookuvg+RUB7K9Lno94+dlwoDjzHseTcQbNyuWw4lZPuAcL1z9agZ0HyTHwmN3SLwfOzZJWNElIYkZTxAUCtmgp9FMlzVtXDie5WQL4pW57SEYhO1i+T2u1+CpNGhFRHeNmUtqdPTHOgllWxNVR0A/EXukQjEUUkBxrMkZcrkcu+zrhnbdJXODIkkZDM69Pw3OvjPVEFehYk0YhmiEAH2e5z6QBmfdmWLqdUaDIacmQs+h0V8YDbsqGZLbyf1eKeITn8+/imlcykwYXDefzAEFnQWZMJjtmTAIp2YhK+KW3adA+66ibQYpQzEo5ohij/CjVhkxFFJAj52zT5UrTnO/s+TO3bX/OYlBj+3AED22oQldUmrNf2eIYnkfwwOeAQOGxUbsLcWCnx1lUd8z2wOHnucVlkIhD7hIrk5JOXEzNqX0LHPNvGcZh7KYyIRBOCWWLQnF8LatXMuQoHv7UelKYSoUUefQC5KMTWAyQJus9jtb/kS3FGs79tkMOPryJNBaGVFNeIWb/c7WfobLw+DkG1Pg4lnpkBZ2bHV06Li3C86+K9W+CootkNpeg9H3pqoS1wpZWRWsTMzkFMu6btopird5xGKZgd6mxLIlGTF0cIVRxU9escyA91fp4xQy0a6bPAL1yEu9Uc3/awbNDXD8+GS49IkMyOjS/LBqdxhGp14uuPKFDDj8IhtLdtvM4JMS4OSbUoTlDJQ28eLHYm9xoYgrVpWP0iiRZjdhS0VjwBdONoyIS1372krMchAetU1+OK/IK5YZ9AsE/CoMQyEVJ1ybbEupZzNQVbfDLoi9TVZ77e82Nv8NObmZBUfoYrn572ziKySMDx7phStfyoQufWPfNXrYBV449dYURwQ/eZQvnZ0hbTYYhSIIX5ma6pHTqwzQcN+zUCJMM0ToWeZVb8MOR/alOTQjWpM+Dl+sebEssWcZUCyvXl2xBl9jQPQoFFGHvGzn/F90HoUTnkQGI6alGanaYhGqjDdiRirk5v+zMp4d2TBS2mlw/kNpcLpRaVB0tgEodvi8B9Ns3XTaY7Db8MR37aeEskJuKGRT0+QMwcBXt+EuXTeVpyeXZbbHU7ugFS5shc4pNMV+HBLL5mNZmgLfEdNhGAGdS1nyOgjrP2BAXiM25BX0irikz5EeIyuA05BAP2tKSpvwjg49PRGumZf5twwPJkb15sMwxJnoc3gCXFuQ2WYLaPQ7OgHfwwzjbCW0IDsOr+8xT2dIVZxFoWgO1KKrmKZJmQkDODOt8XTwxMzmPiKmPMs4j5r2LJfUNKzFycWRlYdZ8O/pSjFI+PJUKIZCOo4Zk+RoZgASyqfckgLZp8m/qS9UKAacquWRMDM2joU2EpE7uvnvxK+4ExicdlsKXPhIGqRk0be3XagADHnOqRjM3gdEllqO3rcDc71w/WuZcMzYJCPWXKGIBerqYCXe+3J6lpn5TBgaMAvSxnFH0sYRjohlP2yzKGbZvFjuMdeo7LItaMlHMAZJZcRQyAnFjR5/dbLtIRmUgYNCP9pi2i4SySTMrng6w0zO6GY9yyntGFz5UgYccm58pTjb52APXDYnHa55NdMoGtJ+j9CePlB2EMohTouLW99rB2dOTlHeZEVMwTmUpqUN24FNScMwwkniwCLe3IfTkmOeZcZNbM+OhFzWZTueKEYlEngZlCR/zPV6YYcEH5v8Pb6pBwpTKnQdLoUnFqZqGvuv6FIopOPXzxrhtbtqoLbCVFhaSGR2c8HIGamwx5C27+ZrrOWQkNzyygOH5D/wlIYLlEjHyzZP1TYdNv0agB1rA1BbrkMDvr9U6ykhhUFmF81IRde1n7tNxXIr4g8cE777ZfSwo/pnemtw9JBuoNQ5jNOeqH1CmCExnHV5Hv+WC4UZFgHwZb/OdywWpq04uLw2X92lCVgqdGxTuZZxQlS5lhXSQzGj1xZkGHG4VnmZyZt8+IVJMH5uRlwIZaI1obwLUoaOyUZaRw36HukxsmdQ6j7yHp9ySzIcd1WSUTCm51AllBVtgpW9UxN7yyiUCc7M6zv8WyINw9C3QZlj2slBsWxN3LInvMIk8m7yQ7Hs9weUWFZIT2oHzcjwcM3cTBh6WiK4PeGp5kQUjIeM9sL1b2TCyTclQ2KqReq7bWG9C1+hUMQkVI/B5ZI2BAMHq7ASKUQqltd+xY0wW0dwTCxzazzLiGY+fRxwmbNN9HvrrbK1nEODsBUKqem8rwtyp6bC7R+1M6qtDT4pEdI7a816nKk/q4cLcs5MhJEz0/DfZcFpt6cYm98UzaI8ywqFQsBX4TAqZyYMpKq20ZS+O5G1z8BTx6AVLs4UI9mJYzHLw1nniQzYNGGGDQrfOxfwrfnCDInA2KSzXMBeF6ZU4Lvv/6WiPqX/qx8vQlEh7c2gULQGxeOWbdShvopDYz03PMiUc7hdd5d6FG4CHJJpcZ+I40GXYI9CoYhnfD59f/c1p9+IY8IFoksaUMOUs9m1pvIlD2ed9meg/SjMsMDf+/ACvuUGYdqOk2EYlniWUXCb9izrfnk9y7hadFMsEjZVKIYipqF4XPI677mfG/Y9zGPEi1IlPiWUw0KFYSgUCoPKyupVFLIpTNkIQ9tZkgnDsbRxhINhGLpF6ePMxyzXNTZKXfQjGIukci0rFIo/UWEYCoWCnjRt6djx7GpsyiqWoxGvDDrojoZhOCiWNUs8yxyY6Sp+6S/qZTjzVApTOigWSWXEUCgUu6DEskKhIFbWXgo9UCekClsyopIJg2ibYnkblGzEU8QTAAsvGwYhbUYMBqwf57oSywqFYicqDEOhUCB8lcfllTYTBoo609oK/02kYrnyNV6ySbQdwTGxTCk+8A2iCjQRwtKGs6xMYYROcNOMnHDo19jIVBiGQqEgGB7Ks6xQKICeOjPg8m7+51HxLDvqVSYc3OBneIUtCcXQwwjFwE9UXrHMoN+9936+mXOoET0KhSK+UWJZoVBQjuWVKC7lzbHMzeVYPplpKSh6Isr0g4Nj2xbL3KLCJABu87mWmcRV/ABSb193d3dsrg72KBSKOEeFYSgUCtB1v8yZMCCguUw5Qb3QjjJh0NOzsGHAHc2EQcSkZ9kVRvo4lMtSZ8QQMUkqFEOhUBDKs6xQxDmcg75p06bVqJ6kFMs4SOnLfq435QR1gceCTBisrXuWwRLPMgduOgxDl1wsi5gktclPoVAQSiwrFIr1mXdf6mUAXYUtG1v2+0H3iXZI4MAWsVhm4FMxy6Fh3rPs033SZsMgKCZJZcRQKBQCFYahUMQ9fFWK2yNtCAZiWleh1olULAfKocxxrRSTnmV8s02L5Xufhi34+xuEKR8c+um6yoihUChoiFOeZYVCwVZpzCWzWA7HARpp9b61H3O9XrQdw1GxjL/OIs8ymA7DuEvXdZx/rPr9NsD619c3KM+yQqEglGdZoYhzRCYMidPGRaN6H3c8BINwVCyXW1SYBOmuMS2c1y5vRgwGXQLXnerjHN8mhUIR7yjPskIR54jKvtJ6ljkz54AcxjQvnnoErfDgUdjcRzgqloXrfFvQioiEk6FjZ9EOHZkLkyAiNkmFYigUCiWWFYo4JxAw9jHJK5ZNxixnQPteeIpId3LQHU8bRzgchmFgSdxyIuimQzE4Y1Jv8tPA1R9fpQrFUCgUKgxDoYhjOAffjuceJr1EAlNKeEA3GdrKLMiE4XxBEiIaYtmiuGGX+VzLutyeZcYpI4bx2EWhUMQ3yrOsUMQ3f3T48f29URy6hS0dDT5zWcY0C8RyfTyEYQThlniWNeDmq/hJHLNsYFTp4SoMQ6GIb1Q2DIVCsQrFpcwhGPVpL5gOq400E0bFO3zrZtF2lCiIZatKXpvPteyXXSwD76/rAeVZVigUKgxDoYhrJM+EAXy9ruumFvU8cs9yVLzKRBTEstkYl6YJp4rfb1X1G/CTlXgSYnvXf/uj5IJeoVA4gPIsKxRxDIVkMok9y4hpLYfiPyKxjINiPIllazzLeBGZ9iwPmKs34mlT0JIPik1KfOr/OnEOW0WXQqGIT5RYVijiGM4DFJIpsVg2lzDhQKZ58GTaybkrLEo5lgnHxXIjNFq0wc98zLJA7owYHqYyYigUChWGoVDEMX6/ezWe5BXL3JxnuSd03BtPEW1W5MCikjaOcFws61BhUWES1nkw0xKEYQbpM2Lg/9UmP4UivlGeZYUiTuEc6vn4UzkDSBFd0oEDlFnHY6Sb+4CBP348ywu53oBvcokwI0HbCzLCqQQjt1hmrB/nyrOsUMQxKhuGQhHX8NUezvsKQ0pQyZvyLOOAFunmvkAZlJK3PSpEIWbZmAksiVtOgATz6eMkz7WM9Fe5lhWKuEeFYSgUcQtbxVxc4kwYqFw5N+VZZpFnwvhDVIGOClERy7jCsCgjBjNfxQ+47GK5r64bJS4VCkX8ojzLCkX8sopJvbkPoKKiwVHPMv77qIVgEFERy/hnW5Rr2fwmPz1gbjXkNBSjxKffXM9R1YsuhUIRf6j7X6GIU3D+Xwlc6oIkpR3n6tXCDAnUNhGJZfz38SiWmSWe5XDSx5XXNkqfx9i1fsVeeLJoQaFQKGIQFYahUMQpus5XocCROQzDlIbTmObCE+masOGgRy0TBhElsaxbIgRxdWM6DINWQ/jvdghTShgzYpVURgyFIj5heCjPskIRp+ifvFaCg0BnYcoHN5cJ4wzIJK0WTvayP2HAlGc5AsLNtSx5RgyKVVIZMRSK+IUrz7JCEYdwDlXavNnthCknjJvScG5wRbq5DxrjUSwHwGdRFb+2KZbxL+unMmIoFPEMU55lhSI+WaWBS+pMGDg4mfIs88jFcvlbfMsW0Y4KURHLa6CcCpNY4TnJPI11TBdtM8RA+jhdhWEoFPGLEssKRVzCVwWfLkuMbs6zjEQqlqPqVSaiIpaXcL0RT1YUJgF3GBkxuMn8gE5DsUq86IetwlQoFHGHCsNQKOITo4Kv1GJZN51jOVKxzONTLAssCsVwmxfLTHrPMsAL//ZyDn5hKRSKuEKFYSgU8YhRwTe4yV9a/Mxn1rMcUalrHAzjWixbssnPFY5nGXTpxbJWW7Uvnv4IWgqFIo5Q2TAUijhFLy3BeZ/tLUzpwIEp8N1vQKG0IaExjXRmr6AVHgxYVNPGEVEUy9YUJgmnil99jU96sSxiltQmP4UiLlFhGApFXPLswzqulikvsaxsPvpjPeSn3mdBVnc8JQWt8PCDP549y1YVJjHvWU59Sd+Oq6MaYcqKEssKRdyiwjAUiniDc9jBVhZ1FaasmNzzpUW6uS/gh9LVoh01oiaWuUWFSXBSCS99HJc9bpn3N0peKhSKeESJZYUi7uCrGEhduY9GJlOOTg1YpJv7fl/I9QZhRI2oiWUGmiWeZXwjTYdhGDC5M2LgC9ybV5apmGWFIi5RYRgKRfzBVjLG5E4bZ9qzHNnmPnxPoh6CQUTRs9xolWe5h8Y02hBjDsk9y0bM0uvPqGwYCkVcosIwFIp4w8iEIXnaOG6yeh8OZBF5lvHfx7dYXm9dYRLvOZDaUbRDBj8A+Tf5ffdpJucQ9ccPCoXCUVQ2DIUiLtEoNrdvsC0nqElM5liONAxDj2+x/APXffi2W1J4QwdvGKEYXHqxDAFfH/z/b0FDoVDEDyoMQ6GIN/hnb1XiSjlFmFKiB0L3LIun/hGFYegSpI0joiaWg1iTEQP/DNOb/HQmv1hm3IhdUhkxFIq4Q4VhKBTxBOfA4f35CcKUlob6xpA9yydDxy54Sg1a4VIX357lINbkWtbCSB/nD/gk3+CHMGNXrMqIoVDEH8qzrFDEF1tYacleoi0luIKvTX8FdgizVZKARbi5D8pe55WWRCBESrQ9y1ErTPJ2NWzCD94nTFnpywOBqOcXVCgUTsOVZ1mhiC9WimJk8sJhva7rIY9N+I2R5liWwqtMRFUs6xaVvEZMe5bz5uoB/CgtyshhDwwgGX76tEKYCoUiblBhGApFfEGZMCRPG2cyEwZqmEhzLCuxTGgWiVX8QMIrTAJM/k1+H73pFi2FQhEf4JCmNvgpFPEE54z2J8ldkMR8juU2kTaOiKpYDli2wQ/CK0wifRU/ZN3qTpxDtbAUCkV8oDzLCkU8sWHlJlwldxKWnHDTmi1CsSxHJgwiqmLZDz6rwiC6HMg0j2ibQf6MGAGdci6qjBgKRVyhwjAUirjio7elv+fN5lhGItzgF1CeZWIrlG3CUyBoRYSrM7TrJtohE8YHHwUYPZZRYlmhiCtUGIZCES+gFtGh6Is0YUoLZ6HvMzuLZXTAU2bQCgt/I+yQps5EVMVysDAJamYLSASP6bhlXMbJH4Zh7I41SmAqFIr4QXmWFYr4YR1raIg0zZrtBHQesoORQUKkm/v+WMh1aSoYR1UsCyyJW8aFmem45QCPgcIkAJ345vVUGlyhUMQHeNurMAyFIo4gh5jcmTCQHdsaQtZrrojLXMsTr0xEXSxzizJi8DCq+G3mDetxRpJ/Uvr8XfVIVqGIK1QYhkIRR6BY5lJnwkChtL3rG3qtMFsFNVmbyYRBSOBZtiYjRjhV/PZ8Wq/H05agJTE/feUVLYVCER8oz7JCESfw2qo1qIWkrt6HI5IprcYizITBJMqxTEgglvWoVfETSL/Jj5Vv78E5lApToVC0eVQYhkIRN3z7aR2KS5ewZMXRTBg4AKowjL9jjWcZVyFhFiaJgU1+wUTlapOfQhE3qDAMhSJu+OFj+YuPmazeh2I3Qs9ynfIs7woHZlGuZdZ2xTLjKiOGQhFfKM+yQhEHcA4+tm5VljClxUyq3eEsK5MBUOq4cCkr5JUloi0FURfLunWFSdqfzLQU0Q4ZnJFiwLPM9oL6ujXCUCgUbRuVDUOhiB9+h4DeR7TlhYfuWebgjjAThlwhGETUxXKVdYVJIBE6mM+1HIiJ9HEu/tOXquS1QhE3qDAMhSI+4Cvxf1JnwiB0LfQcy1qEaeO4ZJv7iKiL5Y+57seTJRkp3GHELesxkGvZ4McvZQ/+VygU1qE8ywpFPKDDavy/9J5lv99nJmY5os19DJgSy81gySY/DprpjBg1NY3SZ8Mg2G/LpS+FqVAorIIpz7JCEQfwVUt2MIBkYUoJrtz9b1cDRQGEBH5/RJ5lHPyUWG4aawqT4ARj2rOcOVevwA+2XJjy0lC7N+cxkBNaoVBYAN7tCoWi7fPjp5aEodrMpry5esivE8V/RGJZg4CKWW4aq9LHQXgZMbhKH6dQKKRCiWWFIg5gyxcliabMmHwCH1HMsn8l7PhNtKWhjXmWIbzCJCwmxHIf0HUllhWKtg9lw1BhGApFG4dzqIMdW7sIU2ZCdmgOY11S8dQ5aIUD/30J1xuFIQ1tLGY5TM8yxERGjGRY8+s2YSoUijaNCsNQKOKA1Xiv9xVtmQnZs4xKmTb3oWQJDw5MuhAMQhKxHLDEsxxuGAbOSrGREaPoK8ocolAo2j5KLCsUbR96Wix92jhcuofs0HRHXLlPvs19hBRiud6imGUkOZdlthft0OGh5w+MKr8sShAthULRplFhGApFm2f71g0oDjsKS1q4CY2Eq/wIM2HIl2OZkEIs18EOyvJgidc0AImm45bxw4kNz/LWDe1xhacmUYWizaPCMBSKNk/xNzWiJTW6Fnr1PhSVEWbCUGEYzSIKk2wOWpHBwihM0sB8sSGW/b598f9WbYZUKBTyosSyQtHWWfJ9TBQbq9NDr0cRqWe5Huqk9CwzLokDI5d1+RpPhwatiBhfyLc8KtohoWkaC1zhrWEAUqdwwU9qG8xeWMwYO150KRTRg8aOmiqAqvLgUV0JUFuDI2s1Hniur6MFHkBjA65I8Qhgm/6NTodI2anhXOHCNbvLDZDoFQfehnSkpuGRgUc6QHo7gHYdALxS5+63BHyLduDpKcbgtmCPQqFoi/CbRs1iNVVXClNKcLSuZrNrQy6KhlqOvNA9gpZpSlG/mQ+ldQCJxHLnefhyRggzbDjwexfwrbcLM2T42ORfUSxLvyuVz3juGda+46XCVCjsgcaFCtRs27fi8LUNjxKAMjyXlwIv2x6A8h2cVVW4/xS9DsETvZxldWLQqStAZxyPO3UD6NoTh+a924yQDopl/iQuik2PYzFDQ71xTfHS7T7YsaUctm+pw2vKB5VlHKoqNWioc+Eiyw3+Rg8uuBIgoLvwjcEVFcez8RN0YIyDRrHdmh8XW35wu3zg9vghwRuApGQfpKRxPDRIz3RBZvsEyGifgudU1q69C9vBhZlCESXwPq+EK0/9AnXHaaJLSvB2+wXF8gBhtsjhTEvqAp2qsRlu1MI3KJYPE22pkEYsD2ddHsCL5iZhhg3+Na8s4FvOE2bI8LFJHzBgJwhTWvh51/yXHXPatcJUKCKjsgxgy3qArRuNg2/dqKPtR4HsZn6fFGFaIYGDB2/XOcD23McFe/cD2Kc/wJ77Anhib0+sEMtzUCzfIbpil7oa4OvW1MLqZVvg9199sHWDG8q3ZzJfY3sheqMG11y1kJRUAWntaiGrow+67OGCbnumQree7VnHrgnG0wyFwibwPv8Jxp3SDu/zXqJLSjjwD9jsupOE2SJnsQ4D3eBeKsww4M8U8q2XCUMqZPIs34gv59/CjAD+Jb7ZRwojZFAsz0GxfIUwpYUPPfy/7OpJSiwrzEEhEhvWAGxaC3zjWg7rf2sg4cLq69ziO9oc3OXiKJw5G7ifBgP2R/HcG4cY+fV/UCzDbMZgYrAnRsAXzjf83gBLflgPS39sgA2/d2SNtZ2iLYrDBcV0PSSnbIOsTtXQcx+Anvsm4TXUhXXt6VVeaUWk8Pra+XB9Xi6u86UelFAjPsmeqBsjzBbJZZ3Owj/ndWGaRge44zW+5R5hSoU0Yvkc1iUPr5j5woyEdYV8y56iHTL6mKTJGmP5wpQW3q7D0+ye56VceSkkgONws3UToBhGcfw78D9W1sHG3xmrqoj72Z0npfgh5zAX2+9wBv1zANwe8RW5CIplPosxNkl0SQun0InvP1sDP36K4viPPVnAnyG+1HahpxgebwlkdSyFHr18sO/AFDy6oohOMmLwFYoQ4Iu/n80e/b9xwpQWHfhd2uy6fwmzRYazTjcz0O4Xpmk46Ocs4CVhi207kUYsn806HuIC1zfCjAT/a1Di1bm5YEp9jPdCjWnPC1NauKa9B4+/fTxjlPtbEdeQMN68HuD3FSSK/fDb8noo2eRlvkZ1bbQCp7jW/Y9g7LDjNegzRPTKgRDLj6NYniy6pIKXbKqCT95cCT9+ngqV5X1QO+J/ChybGyEpdT1036sSeg9wQ9+hXdhevTvGw6ZUhXn4y48+yj5beI0wpQVnmUu12bXPCrNFclmXx/EU9oZFP+j93+AlUqaOk0Ysn8k6dveAy5K0aPUQ2GMh32bqZ/nHJB7lZq7PhCktHPgamP1uAMUypZFTxBPbtwhhvCIAq5bVwsY/vMzvk9M9GkPwjHb17JgzvXDkSQBpmaI3euCQXIqnR/AevzPYE314bU0DfPT6YvhsYSqrLu8fq6EVjkNe6ISkTdC153boO8QFAw/owvbu0x4SEsU3KOIV/q9rnmQbf5c+9DOgw/GuObUfCbNFUCx/gKdw9375V0JJyhKuNwpbKqQRyxrTXOdAp3psRuwVw5XQ4a/xLZSKLmTqx2h7epn3D2FKC35aOvyn8H/MmxRSwL0iRqFsAWtXAl+9nMOK4mr4Y1UCq69VM6yNcM1F3uZGdlJeEuyxj+h1nqBY5v9ljN0luqIGX/Prapg3ewf8vjKbAVeBuhbAgQUgJWUDdNu7HAbkJMKA/XuwPXqlgkuFcMQTfPzZC5ivcbgwpaXRz/skPFVHZblbBcXyGjztHbRMs7KQb5E2I5k0YpnAN5qKg5iuwLc7OvDRr/Gtc4UZEp8N09xH9fbWMQvEut3w6/71Eht0wPnCVLQFtm0CWPMriuNljfBrcQNs25LKuK4eb0cD8gb2ya5mZ1+UCr36i07nILGMx8OaBneLLodBWfz1Bz9DwVOJrKZyoOhU2AjXtDrIaL8Oeg+oh6GHZLF+OXsY+cUVbRK8v7fDladuxKEmW3RJCapDvs5Xn7zn0zo5MltkMNMS+kCnWmyGu+p7E8XyWaItHVKJ5eGsy1d48UScY08HuPU1vsV0kDkfm7wWf3/EYt1u+AnnPM1GjFGb/GIVijVejwvw1cuA/1pcDauWulhttdQFceIV3ntgFTv3qjTo4Vx2p6BY5g9pGgtpU41VcB1/8ydvfg2vP9eRNdb3Ed2KaEALtsSkzdBt7x0w+IBEGHJQD9Z97yRg+AVFzIP32rdw1WnZ+GnKXgithM2u7SzMFjmHdeqrgRZBvDG/r5BvlbYQk1QpS/DCCbn+eEtowMMVvLFR9vq3X1ScaixBFexWFAN/+yXO77u1il873AfTrgOYOxtY8bepSijLC1u9LI3nj+f8iekVRnEW53DMi4ESmfPvPv0ars9dxebNPlwJZQnAT5/V13Vla5YPYm88vy/LH5/Erzmzmt817lc+d/avfMXiKvBJGdqpCIWNv5NXORbG/ZA1GQcWUZlrvOSlLHO9E6nEMr5Zlmzwww9tD9E0S2yI5S3rVbZ8mamrBVj6A/AFTwdQaFXyG0bo8O8JwN56iZH4Yr5GtdiJIXBSY+ynLzP45Mt9fOGrdRCwvWoh/UpdtG2Fr121HG4Z/QN7+t7DlEiWGxYIpLIt6/uxj9/ox/59Rxq/brif33HRH/ype1fyH78sM0rPK2KDX36uES3ZWSfOreICiGijBwOmxHKoMOCWeJZxpglPLPMYEcu1tT05h1ZjiBQOUV0BUPQV8LmzA/yucdX8xhEc/nsXsPcLXGzDmnQW8Et1nynCAz9HD3vz+SQ+6bJyY+OlrdgbH8cbGkr5gxPfhxk39GHVlQeJbkUMwXTdzcq278W+/7QPmzO9Hdw8CvjN527ij+ev5N98VAYVlFRFISUrl6JMiQG4KU0WkWfZD3VSpozbiWwxy1TNpkCYkbCtkG/pJNoho49NHouqZrYwpQU/sTqYtfB3prGQ6rUrLIYmoZVLgK9c4oflRQ1sx+YU+lAU8QNnTIdjz6xgeZe3A5e1e4JxSC7DcfleTWMzRJel8G8//gKee3Bvpgd6iC5FG4WnpJZAr4HVMPSQ9qz/0AxoH1L4qcJm+B0XLcCFjvSZMHTOb9GeqHtAmC2Syzq/g5LyFGGaZQdqtg6iLSVSieVzWMeDNXB9K8xI4FugJOUrrtcJOyQClyef5HLBe8KUGn7nox+wHnufKEyFnVB+41UkjpcG4JeiRhzkVIyxwoBnddrOrvtXB+hq3b7goFiGmZoGlpZ95Q31pXD/rT/Dut+OozgP0a2II7g3pRx69a2E7IMp40YqdFHrJafBe5vD1Wd8i4vVQ0WXtOigj9Jm188TZougWF6Jw0pY9R9QhX69gG85XJhSIplY7tRNA22jMCPCB7zPm3xrSLkBd9J4WVK/BDf7RZhSw0dfWcCGnZknTIWVbF6H4ngpiWMdVhT7WWVZgviKQvEPuMvVAOdf52eHn5AiuiIiKJb5DE1j94quiOErlhTBQxMzcYIONweqog3CE71V0Kt/NQw+uD3rNzgBuu2FqkCto+wE7+9NcOWpCfguS+1JJfw8cKj7iYZWHZjDmOZuF0wbF+5+nKcL+ZbLRVtKpBLLGtM0UZjEgg1Q+nGFvORjYYTE5rO05C6dvdWx4HXhOYfPY1dNGilMRbhQVfR1vwXTuK1cwmHlkgCrq1HlohWm4QcevY1dclNHcEc2fAmxPB3F8n2iK2zwZ3GYN/tD+PjNoxlwtehTtAj3JNTDXn1qYNCBGazvYDf03BdUsRRr4eWlX7HbL5Dai7qTusb6HknP6K06MIezLvugaFotTNOgCr19Ad9imXPADqTaeKRznXaAbwpakcFBM/1ctOsbOq2MHM0PFTYb1iSLlsIMfh/AysUAC18GeHgy8BtG6jDjBoD5cyiNG1NCWREu7IfPOvL8a0uMDZ+RQev1iLNh8MbGWrhrzOfs4zdOUEJZEQrM1+hlq5a2Z68944aZN4GRcWPmjZX8zRepkmgwDaYiMlYviYmdlyhgffc+B5uF2RoRZsLQpc6EQUi4S59bkj4Of07bTh9Xtt30Bsa4RKRxg9efA7jvVhz8czk8cAfAmy8CLP8ZWEOdylShsAy2ZV0nfufYUtgS6TAW2SM/XlG6DW4773e2dePRokuhMA3z+9zs9xXpbOHLjNJf8uvzdD51fC0seAZg8bcAtSpdnWlWLo2VBNkb79INB2YoRJQJA3+J1JkwCAmFArMofVyYuZZ56HkFo0rAvw9Op2qk2h0qHPHDZwBzZ4FR+OOmkUBp3ODduUaoBQv4pQ+xUcQ2rKYqi+dfU8N/W+4TXeEQtljma39bAxMuaWR1tapUtcJSmB7Q2Po1yfD+fIBH/4Xj62jgd41tgFcfB/jpi2CmIEXLrF0ZK3n2Q9ZCOKlGIpZ9G2D7GtGWFhm9alZ5lsPbns5iw7PMOG8PlWW/CzM+oeIQf6wE+Oh1gDkzAG6/EGDCxQBP3gPw8Zt4q6/GJasjtR0Uir/B/L4UeOB2nS//OUzBHF4YBv910UqYeX0HXBR2F10KhX1wDmzLhkT45C2AJ3AMvu0C4BMv9cPT9wF89jZVqjO+R7ELWzfFSlExE9X7whfL+G/X/MD1SBwLjiBjGIYlnuVwq/hx4LERhkGsWb5dtOKDcvxzf/4SoPApgPtvBbg+F4x443lPAPz4BX59h/hGhSL6sEAgEf5zJ/Dib8J47GpeYfCir1fAQ5N6MF1PF10KheOwHVvd8N0nAC8/BvCvayh0g9P+EHjrJSP0Deppa1B8gnd1AOprwg0RdRpHPMv4b6WPVyZkDMOwxLPMwoxZxhkqdsTyymWm8kjHFDSg0oaS9+YBPJ4PcNv5ALdfBDB7OsAHhQCrlgH4YiX0SxGvMK57YNY0jS/+3uTFas6zzL/7dCX+nr0Z52rjr0IqWEMdM0Ty2yiWSTTfMALg7qsAXngY4It3abN6MCtRPOBr3IAiw7qk7DaCWigksUxZzPAUdkpKDlz6eGVCqtRxxFms04Fu0L4XZkQ0QkPWW7ysTJgh4bvMO9Tj1oqEKTV8nwHvsdvvP1mYsUsDan5K30ZhE+vxvHYVwOb1+AfKdW0qFOHCNVcjXD/Vzfplt+qgwMu+Ao+JOAU9KrpahC/6Zj08PrWzynihiFkSE8FIU7d337+Odh3FF9sOfNWyb9j9t0pfjIQI6Px015y6hcJslrNY+55u8ETgZOSXF/KtTwtDWqQTy6eyzl2TgFmSPi4AvuzX+Y7FwgyJygu0dunJ3thI7ZKa/g3796sxceP9SXVl0JOwVghjEsgl+HErYaxo43CXu4Hdel+iIQRaICiW+QRNY4+JrmbhvyzaBg9PTmNc94ouhaJtkJaBArq3OPYJnjt0EV+MTfg7cz9gbzwXE5V3fT59iOfp+iXCbJZc1mkYgPaRME0TADjidb7lK2FKi3RiWRQmofCCiL0kAeCnv863troy2h0+NrmS4a0qTGnhmmsdm/WWnI90GusBNq0D2PgHwGZcdG7EYxO2y9VuaUX8whO9tWzKo8nQsavo+SdBsQy3axrMEl1Nwv9YVQ333KQxPaBCLxTxQXLKXwJ6j14A3fcC6LIHgCs20uPzR+5+jy35LiaeBlf46ttlPK2XC7NZhrNOYxlos4VpGj/UdXyDV0i//0o6sUzksi6/4wnvgsjAv+zqBXzL48IMGRTLS1AsDxKmtODfp8Mjr5ezhIQs0eU8lMd464a/DkMg48e3bQu+QOUtVih2h2d2qGJ3PZoGyU2vx4VYvg3FcrMTEC/dxuGuMWWssTF6975CIQNUYbBTdxTOewbFc4+9wSjb3b4zKhycySWCT7zsc7Zjy1HClBacuavY7NqQNgrnss734ht9qzBNgb9nO2q0mIi3kVQsd/4CX9oRwgwbDnzGAr51ojBDho9JfhvvsdOEKTX8tvuXsN4DBgvTeuj6qNiBl/RWgNISFMGbgweFTtC5stWFp0Kh2A2+d98aduv9KU2VEg6KZX6rprEnRNffqa8FPmXsVlZZimpAoVA0CcVBd+mJRw9x7AHQGc8duwAkRCdqiY8/ZwXzNbQchyUBOOsvQ7EcksMQ9Voh6rXhwjQJ/6qQb41Y6zmBlGJ5OOvyMq4HzxVm2OBf9iKuWi4UZsjwMUmPMsauFqbU8LwrvmAnDj9SmOaoq8H1I4pdEryVZcHUa3SUbf/rXLYNwO8X/0ChUFgFP/q0BnbeNTij/52gWIabNQ2eFF1/gV/g99y8lf3+qxLKCkU4kLM5IwtFc7egcM7CW6lDp6Anmo7MDkFvtcVwXffB1WfoKLr+cc/LBo4y77LZdacKs0VyWZdiPA0JWuZAjfYUarQrhCk1snqWw3br78bnhXyL6XKv+tik2zRg9whTavh+h3/Cci87FlYvpYh8FLZ4BFDcNjYGs0wYR30wXKKmKnhQiVI60/crFIrocdktAAcPE0YQHJIr8bgRxfJToutPeOHTFeyDggxhKhQKq8EbD9Izg6K5HR6Z7YN2mjionZoORhgVxVBroQlrvmXj7+yuMWGnWHMS1IVPsCfqxgmzWTSmsXOgE1USxjciLG5DjXafaEuNpJ7lztcyYP8RZiT8jh9EL9EOGX2MdzReBK8IU1rwk9Mhq8MsqK68mPkaw71YFQpFlODuhACb+KALuv81hwbFMr9B09jf0inxxd/p8OjdFIUpVyCmQhGv0J2YhFOvNxkgMQkPL7bxTGEebg+ABw86d+0JPDXzB/bs/QcG/6Hc6JxP1p6omybMZjmHdeqmgbZRmKbRQT/rNV7ypjClRsKiJCQCrSlMgnQXCbNNocdAFT8UypQx5EEo236ZEsoKRWzC/I0uPmtaIzQ2iJ6d7FaUZMdWgDkzfUooKxQSQb7G2hqA0m0Am9cB/LES4NdigMXfBavNUiXDrz4AKHgS4OX/bMdvp5CFGCC0Ssqo1XqLZrjERPU+QkqxjHLVkpLXSMLJ0NF0bJ+P+6QWy3jDbQfGn8Jp80acOVV+VYUihmElmxKMEu5/h6bhIHoA+KypNayxQfpYR4VC0TSssfEUPFWhwHw72CMvHLSQqve5Iihzjfg2wPY1oi09UoplP2hWeZYhEXTTeYjvfRq24Ey1u6tHCjjjv+Gn9h4DNh6FsqSLHYVCYYrPcP5csmvh0r/i4/jbr3C27jf19EihiHFwzj4C/9ebM/YI3uB/LYglw++DEB2WbB/RCIfffuB6zGycklJsLYSSEjw1Bq1Ice0hGiFzl67reB1b5d22DFyRfo//W8U4XCC6FApFW4Bmzuce0o3Nt8acKsIw1vwC8M6rRlOhUMQ+jPN+uBbO45xPwdu+XnRLAw1F60vqQ3JY4vdG4lmOmRAMQkqxrHMSqxB20PiuaMBNi2WBVKEYeFG+jXeZxhiLieo/CoXCHKyqXIP5c4SFt7zfB/zpB/yM6ypOWaFoQ+AN3QXn8js48Ek4t28W3bKwtfdCPaQn6/h3RCCW+a+iERPI/BjfEs8uBxZuOeiQYnacgDP+HDA2EC/MA0SXQqFoi3zzIcCyn9x413N4+yVg2zbFRh1fhUJhCpzPUxmwezjn/8G7vUh0Rx9uSvuELZZ15Vm2DIvilsPzLKPIjrpnGVecATwewtvqdAY8JvIzKhSKCMAbHl5+JBG+er8nf7+ALIVC0UZBwezWGJuBzY9Rc7wW7I0yLDRHZS5L74SnkEpiNw1TYtkarIkZxpVbeGEYenTDMHCWrMXTv/EPuBJvqPbBXoVC0eYp3w7s3XkjmK7CLxSKeIAxuBn/14Dz/gw8or1IDtGznBDJ5j6ohwYVhmEFuMqyKiNGWGEYeLVGTSzj7y7BG4dSw92Ms6VKDadQxBO6XgsVOyqFpVAo4gDG9dF4Ogzn/3F4RG3jH9dDzbHsjmRz37Z3eVmpaMcEEnuWdavEcqfTmGY6P6k/SmKZM1iJIvl9BvxaFMoyh8koFAo74LwefL5qYSkUijgB5/yj8bhR1/m5KJijsvGPa6F5lvF1RrK5L6ZCMAiZxZhVqds0DTK6i3bI/FZVvwEv1r9X0bIZFMrfAGNr8CK8UHQpFIr4g3aiS5nnXaFQ2AvO//01jT2uc35FNDb+cT3konBhi2UeY/HKhLRiWYfQ8vyFggc8pkMxBszVKc+zYys7ztibeJd4GOcqNZxCEc9w3oBjgRLLCkWcgoK5i8bYXJ1p01AwLxDdjtAY8IWaDSMCsQwxFa9MSCuW34RqKkxi0YShSZ1rmXP+JJ4GM65SwykUcQ9jOO6hYFYoFHELCuZUDfRXuaZ9iOJyKh74n73gL2i471kg7RUKYW/wY6Arz7JV6FynC8OSwiR4CUgplvEPpNRwD4DGzlGp4RQKhaABBwcllhWKOAcFs1vj+mM4Hrg5sAtRL9i88Y9vCFYwbpkzWLt2eAo7SxdTYRiWY1X6uHALk9gmlvGir8H/3Y8v7hq8IVRqOIVCsRMUyuRdVigUChwNGNzBgJ8W4IHjUTvYFx7KWUiaSwNPJJkwGstg2xrRjhlkF8uWxC3jxRVeYRKbci1zDltQJD+J7/6tKJRVajiFQrErKmZZoVD8DdQK57qYa5pf10+0beMfCy0ThiuiTBjw28dc94t2zMA4vuuykss6z8CXeIcwwwb/wiUL+JYhwgyZwNikU13AFgrTEjijwHbtBwa6ynihaDPgPUYDSR0e1disxPuW8gRXY281DsDUJ9qMvqeBA/fhuR50Vo9frwfQ6zkY7Ubsa8Tv1XFE9tOZQyCAVnCgYqAx5tLQxrkDPKBxN7bc+NUEBhwXnloy/q5k7EtkwJKxPx1HuXT8h2nY3w7PWfjv6GiPPwD75APH5P/h+/QNvr47RZdCoVAY4ED4i4/zXA+wqYzBcNFtCfizp7HZtZOF2SzDWecpOL7+S5imwN/xOuqxc4QZM0gulrtcg6dHglZElBfyLRRjYwrfpd6BHo+2VJgRg0L5S/x/FV5kp4guhUIqcDQgMbsNj+1o4cF24LkMz6UocCvwIi7HczmKuXLdr5fqXCuth/ryh56FylBi3WRi68VaSmaCt6uLB2jneVeU4XsyTk+h2J4otmkPQW8UrCi+nQU/g7dxXP4GX9M00SUF+LrK8bQFj61o0HVB1wddF2V4PVSCrldyjVVyPOPXazlj9Tpo9bq/vg6vDJ/fBY21O6CxzAv+bduCaTk//RT0ndfN3ZqmjRgB7pQU0BJ24KqnPSR4ALwu8HppIcTcPIHpPAG/1ctcLlwYYZ/Ok3CBlIYzWSr2p+LYmoL9qfj5oc1S8XWItlGWNxMPWiil4edKiy2FIibBe3FLQNPOcOn6WWhOsup61jmM056ofUKYzZLLOj+Hv/IiYZqEzyzkWycII2aQWiyfwzqdqYH2hjAjoh4CGQv5NlNVsbaN0lI7ZnirhBkR+DYvABfriW+4ynihcAy8u2lDCO1upmMLXogodlgJZ7wER8ZtnGvbda5vDwQat5eVwfaub+hUZl2BoHZjNVdA9wTm7YP37RDGYDC+d/SEajDOTKYLHYUKfmaFQizfL7ocAX8vil9YicdqFMCr8FpZx0Fb5/fDH7/V1G8S6TRjns+Gae79u0KmJ9mbiQulTBTemfi3ZqLQRiHNOzDGaA9JB3xDOhhn7MPFQAf8zElwKxRSgPdrta7z0biQzGCa9hRenxGHdAaAn+qaXfeuMJsFxfKXOBYeLkxT4Ou+dAHf8qwwYwapxfJZrPN+bmA/CTMi/OAf9AbfvkyYIcPHJm/HizCiDXicsdl4OlFlvFBYAd6xdNPuwGMTTvKbgOEZ2Cauw1au8c08oG/VXVpJna+hJONpnbyBCgtZPkpL6JPmGaK5XAcxDofi+38MjhE9xJcjBj/cl/Gz/EbT4L+iy1Lw51O84FK8dn7E9hIcn5bW+euXpD6l0xMFRTOsPk1L7N4V2ru1hA4a0zoxrndBEd0FRXZn/HInfD87kY1tOjriNeGif6dQ2AXdy3hcq+uBn12a63W85rqKL4WFD/RBntn1reqk4azLFvxddN2Hgf+wQr79G2HEDFKL5dNYRkcvJIWa869FAgCnvM63vCfMkEGx/BNeFPsJ0xTGpMTg39i8HH+GynihaBW8ZujpxwZsGQIYOzZwBhu5zjdxpm/xN/o2LV8Gm/f7QaeYX4UkNIxJ7u1hcALe56fjPT8Mz2F7eXBMfgYF7DcaQKuPQ0MBr6la/P+XONR/ooP+xbatviL1BMFeKKTk5nMhKzE5oYvGtW7MBd3wgw0Ka4ZtoIOjqGZd8VpJCf4rhSI88N6e2aCxxxN1/jpjkCO6TVNaW5+R9YLe4hP4c1inNA00U0/pd6UWGtq/y8tKhRkzSC2WcfXOzoFONKhH/HiBgz5uAS8xPfmgWF6Ag5npYHR8V6twUKR46xsjmTgVbQO8HuhGI88dZXghMUzl1DeDzjbhLbghwPmG6saGDa0NVAr5ofCt9hkJpzGmjUbzFLz/TYVscOCzgmEY2nOiyzRGGAWwt3SAhSvK679sKyEUbZGKy7TMJEjs4vKwbozrPfBz64GCpzud8cs7D/JU438KRdPgfPJKVU39NWnJ3ifD2fiH/76cza5tdW/X2axzjgvYz8I0S0kh3xKmRzq6SC2WiVzWZTWewq4UsxP8K6cu4FumCDNk+Jjkh/DCu16YIYG/axNoMA8b1+HoJnt6PkWE4OdNj7U34SGEMKAQ5hvxKxt0PAI+16b1W+s3916oq3RgcUblBVq71OTEixljY3Es6C+6WwSvp4c510ksvyq6QgL/HeVIfcUP+iue2fWLgr2KtsDPB2qeAQOhqzvR00MzRDQKamAoqP8U03SQl9qDZ0WcgmPAZ1V64vA0reFGNE1t/MN/uwTFcqtZw3JZ5xH4Y+cJ0xQ4L36xgG89SpgxhfRieTjr8gl+2scIMwL4c4V86yXCCBl9TNKNGmMUShESnAHF+1DoRpg7RRUygXcH3SDkEV6HrXVokkd4I3C+Ttf4On+Db8N362DT0R/HXt5IhXPQZkHfFd7jNQaTcWxocbLA6+teXeffuDT2muhqFvxeyiTxDi7KZr9W3vBu3lw9EPyKIt6ga6zqQuiY4E7oobkNMY0HimjK8MKgJ45ZPYCx7thn2+ZURfTBMeGXRh+c6nHph5nZ+If/biGK5dOF2Sy5rAul850RtEzzZCHfMka0Y4pYEMsv4Id9gTAj4RP8kIaJdsgExiYNdwErFGaL4KrpMxyUanGQUqnhYgS8+mkDHAnhDXg3rMPbYT32buBM2+DXYd36TfXrlUdYYSX+sYlHupjrPhzXDhZdfwOvwXydoVgG9o7o+gd43dLi7GWfj89IeLru12CvQtEyOwV1osfTE4VUTxLTDAU0fomq3NJBHupu2O/GsyJGwfFhSyAQOAP1iBbqxj8K/2Kz664SZrOgJnsSf97lwjQFB/2WBbzkAWHGFDEgljtPR/FpQU4+vrqQb91XGCGDE9v+bnD9KMxm4cAKQIO98A1VqeEkAa9sSvtniF8848E2kBjmKIIpRriKNaxv/6RuSWpAhcIMJFr8VyRcyJh2P048HUW3gc75ZNrg5wL4SHT9Dbyu3/QBvzVhdh2leVMoLKVglOY6LQO6epin558hH5xRFdygmGZGRdzOeN2qEEOJwXGiRgc+2udvKE50ed9obeMffu9EbXZdqx7jXNblUzwdHbTMws9AHfa2MGKKWPAsX4035aPCjIT616AkWee6qT+4+nytQ2qKt9mUSvjD6L/HgGmnqtRwzoFvOm38NDbKkQjGtuEVxtWxESdcxxs3pM/RY27HrSK+qLlY65Sc6H181w05eP3eiuPUN27m+lJ0GeA1v1bX4UrXnFrTWX0UCiuh9In7pHl7uFggGEPNjE2JVNBnp3eaDrUpMcrgmGGklttWX/9Cp0Tv8y1t/MMx50LtifoXhdksKJZpvqWnEabBRX6fN/nWVcKMKWJALHc6g4H2pjAjIgC1XV7nlVuFGTJ8bHI13vH/SO+D7xyl73oAhwPavEOVoRQWgO8rZYTYhC1Kn7YRO9Yb6dNICPv5hob6xnWpL+lUQEGhaBPoY5OuY4yRl9mDYvk6PYBi2eX6QXwZbwH+dFltw40qW4oiVqC81Ht08+7h1qDnblk+/gz5UPOmM6DMm/mv7rdPunPTPXej2eTGP78eONo9p+FzYTbJWUxLdkOnamz+49+HQGMZlKR8zGNzf4/0YjnCNCV/Qwf9wNd4SashFbuDYnk5Xhl/28luCDpmFA24Gb+mUsOFAL5ndJNswUYwcwTjlDZtM37FiBEO+Pimal/DJiUIFPFIYFzyMA3gdbwnbgn49W88Hm0x3jONXIfrtDm1VNhIoWhTbD5LS27fJbEHzvFG/DSqum5CUHfDeaIbzrHkoaaQD1XgJUJwLHnltw31l/bqlpDb1Ma/BoBeibNrfxdmk+SyDoMA3EuEaQr8/csX8C0DhRlzSC+Wz2IZHdyQZEllKR1g+Gt8S6s7zHeHj016lwE7WZj0oaPQA9r0R6nh8L/4Bt8Puoh24P+3kADGNoVGbMLOzeQN5gF9kw98mxZWwVa1W1+haB7/uMTDmK51Cmiw3APsJxyzznLNrv1YfFmhiDuoPPlBvaGLh3tQSGsUP02CumtQSPNuhrAOeqlVOfJWwDn586qa+rOTkzz77rrxD/v1X8rrk1rLxz6cdTqbgWZaQwleK+RbTOd/lgXpxbIoTFKDzaRgTyTwGwr51oeFETJ8TNIsxtg4o81gCd6kixiHC40vtlHo5sETZYqgCooUuoIHL8H+rfgmbOGMb0ERvMWn+bb8UgRbVUU5ORnGNHcaQEIVdNKSIKDp4HcnQ8DdCMmaG3S0A24ddLcLErUANOgo0OhzhwCe/YBfFiSgzaE+0AAuXwMk4oBaUh+rj9NigZqxWudE8PR2P9HwlehSNAHOD64TAbwuaO/aeW3r4MUjeF0nQIJx1oDjxcx0OsQ/BTe26TqnNl37HLSAB69vHRoa/ZDQ6IYd/iqARnWdxwZUDCgjM7Gby9iQaIR9kKjuhvMVCesuOH9RxcQuKBBTxT+JS3AON1LLcVYf2LnxD/s2sdm1rcYhn8O63KIB3CdMk/CZqL8sSNYQHaQXy0Qu67wSX6rpTBa7g3/pAwv4lluEGTL6mKQJGmPTOXDy8DSicP7TyxwL4N9NHzJlfaANb3jwUhxAUAjjmbESvAa2AUchrGklOte3+/yNJT/8AduPVrmDbQMnee0UaE+DdnoCHjSA44eUroErHWfvVGEn4ySfjN+DC0VGZ+Ogfjoz42uMHqXhjzAOau88dvbZmQKKrg/yRNBRHzzzBnxNdK1V4+uk2DaK9zfOwT6OC19WiXcVXofa9gDw7S7wlaIIL13It6nwmzjiNKYlMmjXxQXu9hroWQCuTIZnBloWXiftGDDjjNdLmrjW/7wH8KB7h86UMxgvMVshQW1c53hNN+Ivo1SSeB3zWg6sFm3abGwc+HrrgzbDg4v7gOM9wCrxh1TSPaFh2wcNlQkQqC6D6koU43TvKBxi68VaSmaCt6uLB7rgMNyFcRTQGnTGObATfm4d8GrCs3F0wAOvQ9uvL8fB69BILbfD5/ulk9dLlUK7o1g+NPjV5sllXWbhyXAchsElhXxL2FVJo02MiOUuJFKPDVrhg3/pPBTLo4QZMvoY73kokI9HMfkrrliPw7cNB3aeiWd67GMM3ng3WZpGB18rhSvU4UED6c7BmNrYh4MwR8HBeKVxBqjgO9tMr+S6VslZoFxnWmljdUPpT5uhXAlfayGPbTtIzfKDN0sTkzsK2wyc6OmawGuDZ+D1gWejTdeKaBuPCumgDaNtbhCOEBIk2/Ha34FvzFYa0PG8Bd+/zdjegMJkgw6+DZugbPMPXD3JkJnBTEvoAx33CgDrhUK4J94X5LWi+FNKO9YVP0/y8LXHtroHguM6PcUTB8eDleN7VIlvDgpsXoFiu4yDXkYLTDyX+nGBqYN7u1pg2gtVTuyfDR3dWkIHjWkdcP7vCEzD65Zjm7XDq5c2KP7jwM9N+jzVeH0ZqeU8cxoW+i73DnPNqW0yVeWuDGddPsS/DTWQeQIQOPR1vu1bYcYcseJZxtUIs6Ii3je4sjlMtEOGHu90nKuTZ6xJKGfqxjMgKaUTeN0BSHCB18s0nohXowvPGt5QwQNHOR5gfjqDR7R1ythSr3M3+HUNAg11ULdkI9Qqcescp7GO6Rr4O3jA3YGD1gGvtQ74YdGZJnMUwsbgt/uAmIaHmuijA3n6KFvKH3hegyL6dwb6ahQVK+vAv/pdXqZSBjrEaSyjoxcSB+N9MwA/j74o6vphdx88SBirPLz2QwvMUhyjSnEwooUmndHm24XARnvnE5wACmyttBG271jIVaEluyA9sO0ySE3GOcKlJ6ZrLj2daa504DydAU8FrqWj8sI2wznEeHKIh/GEEM9/Pi0M9jNOTxWphDmJb7qf6GiqTWMiaQY6yNFGzoSdT/x2PgmpBs6qcdaidgX+3FKuw7ZNlfVP9Zirk2OuVXJZFxpz9wxa5miEhqy3eBku+GKTWPEsT8PTxKAVERtRLNMgrmijUAzjOZDaXodEQ/jigNQJJw88ONpU/MGwqQgECWF6zEYHhSso2gj4OaNQgOXYxIP/gsJhsQ98xf/f3tnGyFWVcfw5987MvkGZ3e7OLi9W1KJIbAVEXgSRVIlCgb4s8YMa0Q+CRj+YEBMT9Iv4EjXBiIQgJmgwkU+7SwNtkVgEoTEoIhUIyEuEst3Ozsy+tLu0+zL3Hv//O2fKUqVl37pzZp5f8uSc58xsOzt7z73/e+5znsfnE3UtgJvKM5olvBDdj+E7vgDf8Xr0e5IXFd/g4g9vKrkPpYB5wr0p6Btupk/GMG8KZYkLe2Wk8Kw99sYvpf5h2FRzZf/YvDOT4Hga7rd5r88VXojlrabnGzgx3+ncxRDtlUKLPsL1Cz7SXSOrcxkxPQEMQ4wty+HIZUqhanyZG09EsKYZUo6GJ7rXYXvQfToWeWpGpv6+3R5Ykkw79QY3Vl8rHeeEkvoU5tgnMXQ5jFkHlMaEISJHRDXOv661I2+Nx4UpmR3eKRMjsY250qnUEZtM7uyUBC84d778pc/mF1j1rzbwJQzjGnzUB5y7KKZl9swH7QgvmsoKssH0nLSqEreYMxLDAohdSwHMqk/om7kimLG+irIcvIrjbjeOt79amd19v4w936gX+l6TxY1m5ip8F1fCPoMhFcfKQmAYAG5CbR5tHud0tsmqdSBxPsZ4kLw2UxiQSQprTSfqAYvUYb+BWL7R9b3El5XlcyGg/uncRWHFXt5vhx93rrKEbDBBc1ayPbGEEMEUu0nIA8UuV4DZOktWhxs6fY9Sm+BsWDJiH8WF/TEj0a4+W1zoSooXXG26T20R+Tx+382Yo5dhqOY3Jil1xRFhjWMwWa3GcQhBLcMU1laCQrmy2Xd4uxSKKqxXjq2m+9u4rv/CufPE3txnh29zjpd4srLMFY/mJSlvbCX+Yr8t/MG5ynFg1oc2yXWmIXJxAusJYBS+OGoSAYw28fFWmq4AK/XGazhr7MAVesdBKe6qhzRfl5qgpVty16P7Jcxd7mzXsCXFB5ywZthHEledZMtBm4zh+pTH9Ql+XBiUUlHDLZeWXtN9ByTjN507LyKx19xvcb/jMV6IZdJrehhYzh2iiwIT6rsDNv9T5zYk3AS3UXJdocwy/CHHOOBYAgrh7rni1/WZ+YG7bRWl0ZmEcH7Iih3A3HhgwBaYR9cbek3Xh6GLv44uCyq1J4OKUp9Q2TAFZRICQoNPcZ0U14Lq5so1RHaE/nhhm42ZmlU5BhDLOyEZF1RjAt/3Wffb/CvO9RKfxPK/0TAl0SKxd/bZ4QXdHdUyRwvgOWEQbxPAGGPLbBC6mqQoC+cwBTNuv+97WUo7ajlbAM6dDK/4DuwamN74Ksr/wuwgFNV8gp2Ia4pqtMVYDFPyJdlBRMqlCRkrNGIhGYjll6Ef1jp3PkwPSKHN9xAan8QyE2ZvqHgLhxe4fpu/zrk1TeVxabb7qBhgtm4T3JFMEDTNAqEoKwDOKbzA3htJ+Z5ttvR8ZXTl2WS6z0+J/AjnC68qjiqKBxykmGacNa7FTmBbiGrmtrajgZjResptXSnClWMu5oXsaXi+z+Y/4vre4pFY7v4dPu4Nzl0E9pk+O3yec04oxyl+0YW/xNEiWDfBKYpX2Ccwj3/1hhQHVipmsrJpz/wc3S/AcEpRFKUGYKgHhLUdxbSE2VGI61FTacfQQmxbiGszSpE9JYbp+g7ulJHJlc7Qs9n0rA1FXnbuPLH90Fy9zvEWn1aWf4jmloq3KEZxl0NxumCY9aFNctmMRO0i4epY4g7cSXbiIEcr7fhGOytFMEy18psWv1CUxuINXN1uPyBy1yM2/47VP5eSwATBFun6Fk7rt8JlSXVFUfyHQpllzZ3ZcWgLVwo9GZtEfxJ97utiOwkdkrQYPxSJfRMi/HAo5alZyUylZWZqXManHhWZhgjH244PxPLnIJZ3Onde4P/+Sb8dXoqiciuKN2J5i8ndFEhwl3MXBX7jtZHE6VDsKvRXBRImLQRu0uItJxsxbLN4N8wwy8NcYzlKRVGU4zGCc8jtE1L+5cN2BNp5edhkVq9JSfq36C46VE1RlIaA4o+hIYy/5p4LlsqmMKclpbPxhjIEN/1TYO+BzRv88A0DNn+vc73FG7G82XRvDMU86FxFURSfGMGZ9meRFO5Y6p33vabrSpHwPnQX9cRMURRlqYklunjAFp90rrd4JJZXrw8lvce5iuIbnGjcIMHHaJOYehRMRwwvorWHjJipSj/xcddvcMdvYWbGujZAiz7exz7jYk0UiSnjZpKBbbGRqBxJ4PxZ+EE5Rh8/F9DwbzPvJfrpoNLawMDws0Eo1lgJmtDNYCyDfxtmM/j5pMXna+Y4PiNa04aW6RxbTSW+ntbKsaqP/ir0uSqRhimVvy3DMpKVG2dc1amu7CSrOXPH8P3Btxg3yTh8/P05zjF+14ap4HRzr6IoNYeVmfZ+O8r4a6/xRixfZdo7WqWJdegV5URDUTIOcYIJn2y6gL3Vh3A94Ppo4wmImYMYS2LGoHaSOLOdMvJmI1efYnnzFomyzUlYUwrG1mYhzLP4Xk+BEOzE98Zy54z3z+H75AZXjfNXFEXxl3yfzZ/q+l7jjVgmvaaHKzJtFU9RFsSRfJo48lnamOl+uCN5jC3ELizAWDxaltnRWFIlCN2Jd7sRQllatpoOiOl0LoaYhsuqkafDcPK1Z+D0dRr+KKfBR183tHkAV9UZjsIbSs5DPmVJNijRMM4NSdykNIG/LfNYT2E+zuCGik9TpmKJpwIJk9ZINI3xKJCgHInBXeh0nE5aPkEJy2UJ4owcisvwU2KDGWkNUhKjtUkbosX/I7PJU5VMGEqcxpxPGQlxcxZkcLOLPv4J9PEZU2wDiZtwHLbw6Qo+G5+w8OlKC/p8koKxxOd+Fj5tOfKk5Si/BYa3K0pD8BjE8hWu7zVeieWtpudFnGU+5FxFIXxUTfHLSk2uWtP/TyZfkrHibhszFEKpM5iWMQXxDFUDAR2swdCZOA7eC/HyfvRpp8G0IMfSwg2L+zHHqmWHMf9sEd/5KOYcb0BLkUSlWQlGUzIyqlXScACaILhCcq3tcqg1ktZV+J4YpnRSiJs99vGWk3D8rsKBejK+T76GMY5XN5knG875PoY2NcEUpWbBMXx3v83f5Fyv8U0s/wknj087V6lfGK5QxFRLBHDlYmyG0O7HWCKG8YZ8KOV8PcRCKcvPOhNkPiC5NUYiiOjgzEDM+3A8rYWg+yBOg6wMuuhS+nUG46P3wl6DiENrXmffSLwXLwxBzO3zrdx3vVFNYRpIzFAmiOiQ/Q4c3x3wO6yYdrb426Ev1TSmVVtIcQlFmSf25j47fJtzvMYzsdz9W4imrzhX8Q+moOGq7xANR94QTub7MJgIYVoMUbxdCsVGju9VTixc7dss2TWxZM4OIZ5xHJ6F88zZeIl2Ogw6oy7hyX8f7EUI4hfRvoSBVyGEX9krxf+sVFEVZXnB8W6uktUnN0nUEUm6I0z2CyTiGiI6EdftbDEHWDOAhbKqAlurxCrzIha7ccAO73Cu1/i2snwrJu73nKvUFuM4kiB+KYQtzAzC308/kghiOB4akrH9egFWfIIbE7MSnWMlWB+IWYdjej2O6Y/iJQgKn7BcBd6Dz/8M+s/i93luRqLnttsiY4YV5bjwpvKzckq2VTIswNUJKdTJYlzcnItjajXENfcVwOcm3SOFuBg+ouFPDQqOhbX9Nv+qc73GM7Gcu9FI8GvnKicGrvAOwwZx6MMSEbwPJ0r0KY7N0JtS3PeQjbkxR1Eago2m64xMRUCvh7sORgHN/RS18Hj7MObqPyBinjRin4L/9IAUX1npkrlK4/FOAhvXEWa+6cLxmYhtiGtmv6lmwNGQqPpgekAKbfXylNgrsbzFdF+NibbducriYfUePoal8E3ELy6yDIeAIDaDscwOTsjY0CM2ZvyioijHYJMJWgPJnYsL//mw8zB0Aewc2LIKaMzXYYiO3Wgft2KfGJTSHn2Co/gK55FIO0R16FJIGvQtBTbDQBJRjWN97uo1n/LAVWqM5/psngsJdYFnK8ur1xlJ/8u5yrHhznMngt9aEbYSQwSbwZQcHhyQScYG+3MAKIpnMIxjlViIZ3MhLvgXYR7CFlY2dg5jmNN/xg3tLsznXduk9JLOY6VR+bgJ0mdIZ5eVqDOU0IWFJHHYVYF9dGhIF4wp/JRlBDfuff12+Hrneo9XYvla096ekaZR5zYyDHngijB3q9MghGMIYQri8uA0BPFOO6bfk6LUINeZrtNTElyK0+8luIB/AkNchT5WhUOcpO0evH9HLLJ9mxSe1A2wirJwuHodSjYnEuasBIm4rq5eV4R10qewnru5UVP1zY8f99n8La7vPV6JZdJrerhRhcnd6xWKXK4Gc5Mcs0aoEFaUOoYX7pR0Xoz5fhnm+aW4UF+CPotbPIaz8zbM+20DtvRG5d2KoqwE1fCQUNIdRmJmD4GoZlq+JIMIxHSSQQT9SmYRt5JNod2Qafpw7vpyv83/3rne46NYfgENUzr5BmMIk3hgXAwTIYz+2zbKlaU4qIn7FaWx2WCCVEra2x62Iyz6oSiKp1TT9AVS7kxLuh3Cup35sCEls0FSiKZaYCYpNsPMIS5ndrUITVKZ1MtsIlaii/pt8W/O9R4fxfLDaK6seDUBv8ER3EWyeAbzBu/H17qPQrgaH+xyBxd0N7qiKIqiKO8GlwOeghnCOQOLs9AWrPAIoR3AZwVI0wYR7qo9sgKkSUqrOz8ZgzHDCMNIMHximJDZbD3d8Hsolrvvwcf+qnOXE8YEFmEMheAqMNOnQQjT4qFYbD6QKD8t4/u325hZJRRFURRFUWoOCO/wCsm1sNS6lRQsbIVyhpA26Bv0TYuRuCUW04x+BkI8g7YZ2ge+bcJ72GbQNqFN4+cYXhLg9QA++iaFPsdoh/ptfgv/33rBx5XlH6D5fsWbN9wyPspVYPRZSa4Af5g+2nwMwx1bfhamVeQURVEURVEUH1eWv4aPfbdzKWZH8BuUIHhLuBMq4a4n6VuxRfgQw7S4EEm6oAJYURRFURRFmQ/eieVK+rhM1yGZKf1RDoxrHLCiKIqiKIqyPIj8F4b8PLa/fA/sAAAAAElFTkSuQmCC', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
        { src: 'data:image/png;base64,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', sizes: '512x512', type: 'image/png', purpose: 'any maskable' }
      ]
    };
    return ContentService.createTextOutput(JSON.stringify(manifest))
      .setMimeType(ContentService.MimeType.JSON);
  }

  // Consolidated three-file project: the complete UI lives in Index.html.
  var template = HtmlService.createTemplateFromFile('Index');
  return template.evaluate()
    .setTitle(CONFIG.APP_NAME)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT);
}

function getSystemConfig() {
  // Login-path function: read/normalize configuration only.
  // Database setup/migrations are NOT repeated on every login.
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var coreReady = !!(ss.getSheetByName('Data_Users') && ss.getSheetByName('Data_Santri'));
  if (!coreReady) setupDatabaseSheets();

  var userProperties = PropertiesService.getScriptProperties();
  if (userProperties.getProperty('ROLE_PERMISSION_VERSION') !== String(ROLE_PERMISSION_VERSION)) {
    userProperties.setProperty('ROLE_PERMISSION_VERSION', ROLE_PERMISSION_VERSION);
  }
  if (userProperties.getProperty('PRODUCTION_HARDENING_VERSION') !== String(CONFIG.PRODUCTION_VERSION)) {
    userProperties.setProperty('PRODUCTION_HARDENING_VERSION', CONFIG.PRODUCTION_VERSION);
  }

  var configRaw = userProperties.getProperty('GLOBAL_SYSTEM_CONFIG');
  if (!configRaw) {
    var defaultConfig = {
      appName: CONFIG.APP_NAME, maintenanceMode: false,
      features: {
        dashboard: { enabled: true, roles: ["superadmin", "supervisor", "walikelas", "admin_prestasi", "admin_pelanggaran", "admin_perizinan", "admin_kesehatan"] },
        prestasi: { enabled: true, roles: ["superadmin", "admin_prestasi", "admin_pelanggaran", "admin_perizinan", "admin_kesehatan", "walikelas", "supervisor"] },
        pelanggaran: { enabled: true, roles: ["superadmin", "admin_pelanggaran", "admin_perizinan", "admin_prestasi", "admin_kesehatan", "supervisor", "walikelas"] },
        perizinan: { enabled: true, roles: ["superadmin", "admin_perizinan", "admin_pelanggaran", "admin_prestasi", "admin_kesehatan", "supervisor", "walikelas"] },
        kesehatan: { enabled: true, roles: ["superadmin", "admin_kesehatan", "admin_pelanggaran", "admin_prestasi", "admin_perizinan", "supervisor", "walikelas"] },
        biodata: { enabled: true, roles: ["superadmin", "supervisor", "admin_prestasi", "admin_pelanggaran", "admin_perizinan", "admin_kesehatan", "walikelas"] },
        catatan_wali: { enabled: true, roles: ["superadmin", "supervisor", "walikelas"] },
        superadmin: { enabled: true, roles: ["superadmin"] },
        portal_wali: { enabled: true, roles: ["wali_santri"] }
      }
    };
    userProperties.setProperty('GLOBAL_SYSTEM_CONFIG', JSON.stringify(defaultConfig));
    return defaultConfig;
  }

  var existing;
  try {
    existing = JSON.parse(configRaw);
  } catch (e) {
    existing = {appName: CONFIG.APP_NAME, maintenanceMode: false, features: {}};
  }
  existing.features = existing.features || {};
  // Legacy cleanup: remove the retired FM Payment Portal from stored configuration.
  if (existing.features.payment_portal) delete existing.features.payment_portal;
  ['PAYMENT_PORTAL_VERSION','FM_PAYMENT_SPREADSHEET_ID','FM_PAYMENT_PORTAL_ENABLED','FM_PAYMENT_BANK_ACCOUNTS'].forEach(function(k){ userProperties.deleteProperty(k); });
  if (!existing.features.perizinan) existing.features.perizinan = {enabled:true, roles:['superadmin','admin_perizinan','admin_pelanggaran','admin_prestasi','admin_kesehatan','supervisor','walikelas']};
  if (!existing.features.portal_wali) existing.features.portal_wali = {enabled:true, roles:['wali_santri']};
  if (!existing.features.kesehatan) existing.features.kesehatan = {enabled:true, roles:['superadmin','admin_kesehatan','admin_pelanggaran','admin_prestasi','admin_perizinan','supervisor','walikelas']};
  if (!existing.features.biodata) existing.features.biodata = {enabled:true, roles:['superadmin','admin_prestasi','admin_pelanggaran','admin_perizinan','admin_kesehatan','walikelas']};
  if (!existing.features.dashboard) existing.features.dashboard = {enabled:true, roles:['superadmin','supervisor','walikelas','admin_prestasi','admin_pelanggaran','admin_perizinan','admin_kesehatan']};
  if (!existing.features.prestasi) existing.features.prestasi = {enabled:true, roles:['superadmin','admin_prestasi','admin_pelanggaran','admin_perizinan','admin_kesehatan','walikelas','supervisor']};
  if (!existing.features.pelanggaran) existing.features.pelanggaran = {enabled:true, roles:['superadmin','admin_pelanggaran','admin_perizinan','admin_prestasi','admin_kesehatan','walikelas','supervisor']};
  if (!existing.features.catatan_wali) existing.features.catatan_wali = {enabled:true, roles:['superadmin','walikelas','supervisor']};
  if (!existing.features.superadmin) existing.features.superadmin = {enabled:true, roles:['superadmin']};
  // Keep the stored feature configuration backward-compatible, but always
  // guarantee Superadmin visibility for every operational admin module.
  // This fixes older GLOBAL_SYSTEM_CONFIG records that predate the expanded
  // Superadmin role without changing unrelated feature settings.
  ['dashboard','prestasi','pelanggaran','perizinan','kesehatan','biodata','catatan_wali','superadmin'].forEach(function(featureName){
    if (!existing.features[featureName]) return;
    existing.features[featureName].roles = existing.features[featureName].roles || [];
    if (existing.features[featureName].roles.indexOf('superadmin') < 0) {
      existing.features[featureName].roles.push('superadmin');
    }
    if (featureName !== 'superadmin' && existing.features[featureName].roles.indexOf('supervisor') < 0) {
      existing.features[featureName].roles.push('supervisor');
    }
  });
  if (existing.features.dashboard && existing.features.dashboard.roles) {
    ['admin_perizinan','admin_kesehatan'].forEach(function(r){
      if(existing.features.dashboard.roles.indexOf(r)<0) existing.features.dashboard.roles.push(r);
    });
  }
  if (existing.features.perizinan) {
    ['admin_pelanggaran','admin_prestasi','admin_kesehatan'].forEach(function(r){ if(existing.features.perizinan.roles.indexOf(r)<0) existing.features.perizinan.roles.push(r); });
  }
  if (existing.features.prestasi) {
    ['admin_pelanggaran','admin_perizinan','admin_kesehatan'].forEach(function(r){ if(existing.features.prestasi.roles.indexOf(r)<0) existing.features.prestasi.roles.push(r); });
  }
  if (existing.features.pelanggaran) {
    ['admin_perizinan','admin_prestasi','admin_kesehatan'].forEach(function(r){ if(existing.features.pelanggaran.roles.indexOf(r)<0) existing.features.pelanggaran.roles.push(r); });
  }
  if (existing.features.kesehatan) {
    ['admin_pelanggaran','admin_prestasi','admin_perizinan'].forEach(function(r){ if(existing.features.kesehatan.roles.indexOf(r)<0) existing.features.kesehatan.roles.push(r); });
  }
  if (!existing.features.biodata) existing.features.biodata={enabled:true,roles:['superadmin','supervisor','admin_prestasi','admin_pelanggaran','admin_perizinan','admin_kesehatan','walikelas']};
  else ['supervisor','admin_prestasi','admin_pelanggaran','admin_perizinan','admin_kesehatan','walikelas'].forEach(function(r){ if(existing.features.biodata.roles.indexOf(r)<0) existing.features.biodata.roles.push(r); });
  var normalized = JSON.stringify(existing);
  if (normalized !== configRaw) userProperties.setProperty('GLOBAL_SYSTEM_CONFIG', normalized);
  return existing;
}

function updateFeatureToggle(featureName, isEnabled, token) {
  var auth=requireCapability_(token,'settings.manage');
  if(!auth.ok) return auth.response;
  var userProperties = PropertiesService.getScriptProperties();
  var config = getSystemConfig();
  if (config.features && config.features[featureName]) {
    config.features[featureName].enabled = isEnabled;
    userProperties.setProperty('GLOBAL_SYSTEM_CONFIG', JSON.stringify(config));
  }
  auditLog_(auth.session,'UPDATE_FEATURE','FEATURE',featureName+'='+isEnabled);
  return config;
}


/* ===== BEGIN Dashboard.gs ===== */
/**\n * TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0\n * Dashboard & notifications
 */

function getDashboardStats(role, aksesKelas, searchName, filterType, token) {
  var _auth=requireCapability_(token,'dashboard.view'); if(!_auth.ok) return _auth.response;
  var _session=_auth.session;
  var role=_session.role; var aksesKelas=_session.aksesKelas;
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheetSantri = ss.getSheetByName('Data_Santri');
    var sheetPrestasi = ss.getSheetByName('Trx_Prestasi');
    var sheetPelanggaran = ss.getSheetByName('Trx_Pelanggaran');
    var sheetCatatan = ss.getSheetByName('Trx_Catatan_Wali');
    var santriData = sheetSantri ? sheetSantri.getDataRange().getValues() : [];
    var classSantriList = [], santriClassMap = {};

    for (var i = 1; i < santriData.length; i++) {
      var nama = String(santriData[i][2] || '').trim();
      var kelas = String(santriData[i][3] || '').trim();
      if (nama) santriClassMap[nama.toLowerCase()] = kelas;
      if (role === 'walikelas' && aksesKelas !== 'All' && aksesKelas !== '' &&
          kelas.toLowerCase() === String(aksesKelas).trim().toLowerCase()) classSantriList.push(nama);
    }

    var totalSantri = (role === 'walikelas' && aksesKelas !== 'All' && aksesKelas !== '') ?
      classSantriList.length : Math.max(0, santriData.length - 1);
    var totalPrestasi = sheetPrestasi ? Math.max(0, sheetPrestasi.getLastRow() - 1) : 0;
    var totalPelanggaran = sheetPelanggaran ? Math.max(0, sheetPelanggaran.getLastRow() - 1) : 0;
    var recentActivities = [];
    var search = String(searchName || '').trim().toLowerCase();
    var filter = String(filterType || 'ALL').toUpperCase();

    function visible(name, type) {
      var n = String(name || '').trim();
      var classAllowed = role !== 'walikelas' || aksesKelas === 'All' || aksesKelas === '' ||
        String(santriClassMap[n.toLowerCase()] || '').toLowerCase() === String(aksesKelas).trim().toLowerCase();
      return classAllowed && (!search || n.toLowerCase().indexOf(search) !== -1) &&
        (filter === 'ALL' || filter === type);
    }
    function addActivity(type, typeLabel, r, detail, kategori, badgeClass, createdBy) {
      if (!visible(r[1], type)) return;
      recentActivities.push({
        type: type, typeLabel: typeLabel,
        tanggal: r[2] ? Utilities.formatDate(new Date(r[2]), Session.getScriptTimeZone(), 'dd/MM/yyyy') : '',
        santriNama: r[1], kategori: kategori, detail: detail, badgeClass: badgeClass, createdBy: createdBy || ''
      });
    }

    if (sheetPrestasi && sheetPrestasi.getLastRow() > 1 && filter !== 'PELANGGARAN' && filter !== 'CATATAN_WALI') {
      sheetPrestasi.getRange(2,1,sheetPrestasi.getLastRow()-1,12).getValues().forEach(function(r) {
        if (String(r[10] || '') === 'Approved') addActivity('PRESTASI','PRESTASI',r,r[4]+' ('+r[5]+')',r[3],'bg-emerald-100 text-emerald-800',r[11]);
      });
    }
    if (sheetPelanggaran && sheetPelanggaran.getLastRow() > 1 && filter !== 'PRESTASI' && filter !== 'CATATAN_WALI') {
      sheetPelanggaran.getRange(2,1,sheetPelanggaran.getLastRow()-1,12).getValues().forEach(function(r) {
        addActivity('PELANGGARAN','PELANGGARAN',r,r[5],r[3]+' - Tingkat '+r[4],'bg-rose-100 text-rose-800',r[11]);
      });
    }
    if (sheetCatatan && sheetCatatan.getLastRow() > 1 && filter !== 'PRESTASI' && filter !== 'PELANGGARAN') {
      sheetCatatan.getRange(2,1,sheetCatatan.getLastRow()-1,7).getValues().forEach(function(r) {
        var name = String(r[1] || '').trim();
        if (visible(name,'CATATAN_WALI')) recentActivities.push({
          type:'CATATAN_WALI', typeLabel:'CATATAN WALI KELAS',
          tanggal:r[3] ? Utilities.formatDate(new Date(r[3]),Session.getScriptTimeZone(),'dd/MM/yyyy') : '',
          santriNama:r[1], kategori:r[4], detail:r[5],
          badgeClass:'bg-purple-100 text-purple-800', createdBy:r[6] || ''
        });
      });
    }

    recentActivities.sort(function(a,b) {
      var da = String(a.tanggal||'').split('/').reverse().join('-');
      var db = String(b.tanggal||'').split('/').reverse().join('-');
      return (new Date(db).getTime()||0) - (new Date(da).getTime()||0);
    });

    return { success:true, stats:{
      totalSantri:totalSantri, totalPrestasi:totalPrestasi, totalPelanggaran:totalPelanggaran,
      recentActivities:recentActivities.slice(0,100)
    }};
  } catch (err) {
    return { success:false, message:err.toString() };
  }
}

function sendNotificationEmail(tipe, santriNama, kategori, detail, token) {
  var _auth=requireCapability_(token,'notification.send'); if(!_auth.ok) return _auth.response;
  var _session=_auth.session;
  var role=_session.role; var aksesKelas=_session.aksesKelas;
  try {
    var recipient = Session.getActiveUser().getEmail();
    var subject = '[' + tipe + ' SANTRI] Catatan Baru: ' + santriNama;
    var color = tipe === 'PRESTASI' ? '#059669' : '#DC2626';
    
    var htmlBody = `
      <div style="font-family: Arial, sans-serif; background-color: #F3E8FF; padding: 20px; border-radius: 12px;">
        <div style="background-color: #ffffff; padding: 24px; border-radius: 10px; border-left: 6px solid ${color};">
          <h2 style="color: #6B21A8; margin-top: 0;">Laporan Catatan ${tipe} Santri</h2>
          <p style="font-size: 15px; color: #374151;">Berikut adalah pembaruan catatan perkembangan santri:</p>
          <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
            <tr><td style="padding: 6px 0; color: #6B7280; width: 35%;">Nama Santri:</td><td style="font-weight: bold; color: #1F2937;">${santriNama}</td></tr>
            <tr><td style="padding: 6px 0; color: #6B7280;">Kategori / Jenis:</td><td style="font-weight: bold; color: ${color};">${kategori}</td></tr>
            <tr><td style="padding: 6px 0; color: #6B7280;">Deskripsi/Uraian:</td><td style="color: #374151;">${detail}</td></tr>
          </table>
          <hr style="border: 0; border-top: 1px solid #E5E7EB; margin: 20px 0;" />
          <p style="font-size: 12px; color: #9CA3AF; text-align: center;">Diinformasikan secara otomatis oleh Sistem Catatan Perkembangan Santri (Amethyst Edition).</p>
        </div>
      </div>
    `;
    
    MailApp.sendEmail({ to: recipient, subject: subject, htmlBody: htmlBody });
  } catch (e) {
    Logger.log('Error send email: ' + e.toString());
  }
}



function getDashboardTodayInfo(role, aksesKelas, token) {
  var auth=requireCapability_(token,'dashboard.view'); if(!auth.ok)return auth.response;
  var session=auth.session;
  try{
    var ss=SpreadsheetApp.getActiveSpreadsheet(), tz=Session.getScriptTimeZone(), today=Utilities.formatDate(new Date(),tz,'yyyy-MM-dd');
    var classMap={}, san=ss.getSheetByName('Data_Santri');
    if(san){var sd=san.getDataRange().getValues(),sm=headerMap(san);for(var i=1;i<sd.length;i++){var n=sm['Nama_Santri']?String(sd[i][sm['Nama_Santri']-1]||'').trim():'';var k=sm['Kelas']?String(sd[i][sm['Kelas']-1]||'').trim():'';if(n)classMap[n.toLowerCase()]=k;}}
    function dk(v){if(!v)return '';var d=v instanceof Date?v:new Date(v);if(isNaN(d.getTime())){var m=String(v).match(/^(\d{4})[-\/](\d{1,2})[-\/](\d{1,2})/);return m?m[1]+'-'+('0'+m[2]).slice(-2)+'-'+('0'+m[3]).slice(-2):'';}return Utilities.formatDate(d,tz,'yyyy-MM-dd');}
    function allowed(n,k){if(session.role!=='walikelas')return true;var target=String(session.aksesKelas||'All').trim();return !target||target==='All'||String(k||classMap[String(n||'').toLowerCase()]||'').trim().toLowerCase()===target.toLowerCase();}
    function read(sheetName,start,end,status,excluded,type){var sh=ss.getSheetByName(sheetName);if(!sh)return [];var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[];for(var i=1;i<d.length;i++){var n=m['Nama_Santri']?String(d[i][m['Nama_Santri']-1]||'').trim():'';if(!n)continue;var k=m['Kelas']?String(d[i][m['Kelas']-1]||'').trim():classMap[n.toLowerCase()]||'';if(!allowed(n,k))continue;var ok=false;if(end){var a=dk(m[start]?d[i][m[start]-1]:''),b=dk(m[end]?d[i][m[end]-1]:'');ok=!!a&&!!b&&a<=today&&today<=b;}else ok=dk(m[start]?d[i][m[start]-1]:'')===today;if(!ok)continue;if(status&&m[status]&&excluded&&excluded.length){var st=String(d[i][m[status]-1]||'').toLowerCase();if(excluded.indexOf(st)>=0)continue;}o.push({nama:n,kelas:k,type:type});}return o;}
    var izin=read('Trx_Perizinan','Mulai','Selesai','Status',['ditolak'],'izin');
    var sakit=read('Trx_Kesehatan','Tanggal',null,'',[],'sakit');
    var disiplin=read('Trx_Pelanggaran','Tanggal',null,'Status_Approval',['rejected','ditolak'],'disiplin');
    return {success:true,date:today,izin:izin,sakit:sakit,disiplin:disiplin};
  }catch(e){return {success:false,message:'Gagal memuat Info Hari Ini: '+e.toString()};}
}


/* ===== BEGIN DataIntegrity.gs ===== */
/**
 * TAICIMASTER FM — Stage 4 Core Modules & Role Permission FINAL v4.0
 * Non-breaking integrity layer. Existing sheet column positions are preserved.
 */
var DATA_INTEGRITY = {
  LOCK_WAIT_MS: 30000,
  DUPLICATE_WINDOW_SECONDS: 45,
  ID_PREFIX: {prestasi:'PRS',pelanggaran:'PLG',catatan:'CWK',perizinan:'IZN',kesehatan:'KES',user:'USR'}
};

function withDataLock_(callback) {
  var lock = LockService.getScriptLock();
  lock.waitLock(DATA_INTEGRITY.LOCK_WAIT_MS);
  try { return callback(); } finally { lock.releaseLock(); }
}

function normalizeText_(v, maxLen) {
  var s = String(v == null ? '' : v).replace(/\u0000/g,'').trim();
  return maxLen && s.length > maxLen ? s.substring(0,maxLen) : s;
}

function requireFields_(obj, fields) {
  for (var i=0;i<fields.length;i++) {
    if (!normalizeText_(obj && obj[fields[i]])) return {ok:false,field:fields[i],message:'Field wajib belum diisi: '+fields[i]};
  }
  return {ok:true};
}

function normalizeDateInput_(v) {
  if (!v) return null;
  var d = v instanceof Date ? new Date(v.getTime()) : new Date(v);
  if (isNaN(d.getTime())) return null;
  return d;
}

function generateRecordId_(prefix) {
  return String(prefix || 'REC').toUpperCase() + '-' + Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyyMMddHHmmssSSS') + '-' + Utilities.getUuid().substring(0,6).toUpperCase();
}

function cacheDuplicateGuard_(moduleName, userId, payload) {
  var raw = JSON.stringify(payload || {});
  var key = 'TAI_DEDUP_' + sha256Hex_(moduleName+'|'+userId+'|'+raw);
  var cache = CacheService.getScriptCache();
  if (cache.get(key)) return false;
  cache.put(key, '1', DATA_INTEGRITY.DUPLICATE_WINDOW_SECONDS);
  return true;
}

function getSantriRecordByName_(nama) {
  var sheet=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri');
  if(!sheet) return null;
  var m=headerMap(sheet), nameCol=m['Nama_Santri'], classCol=m['Kelas'], idCol=m['ID_Santri'];
  if(!nameCol || !classCol) return null;
  var target=normalizeText_(nama).toLowerCase(), data=sheet.getDataRange().getValues();
  for(var i=1;i<data.length;i++) if(normalizeText_(data[i][nameCol-1]).toLowerCase()===target) {
    return {row:i+1,id:idCol?normalizeText_(data[i][idCol-1]):'',nama:normalizeText_(data[i][nameCol-1]),kelas:normalizeText_(data[i][classCol-1])};
  }
  return null;
}

function assertSantriAccess_(session, santri) {
  if (!santri) return {ok:false,message:'Santri tidak ditemukan.'};
  if (session.role==='walikelas' && normalizeText_(session.aksesKelas)!=='All' && normalizeText_(session.aksesKelas).toLowerCase()!==santri.kelas.toLowerCase()) return {ok:false,message:'Anda tidak memiliki akses ke kelas santri tersebut.'};
  return {ok:true};
}


/** Stage 11.19 — server-side scope index for transaction rows. */
function buildSantriScopeIndex_() {
  var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri');
  var out={byId:{},byName:{}};
  if(!sh || sh.getLastRow()<=1) return out;
  var d=sh.getDataRange().getValues(),m=headerMap(sh),idCol=m['ID_Santri']||0,nameCol=m['Nama_Santri']||0,classCol=m['Kelas']||0;
  if(!nameCol || !classCol) return out;
  for(var i=1;i<d.length;i++){
    var id=idCol?normalizeText_(d[i][idCol-1]):'', name=normalizeText_(d[i][nameCol-1]), kelas=normalizeText_(d[i][classCol-1]);
    if(!name || !kelas) continue;
    var rec={id:id,nama:name,kelas:kelas};
    if(id) out.byId[id]=rec;
    out.byName[name.toLowerCase()]=rec;
  }
  return out;
}

function assertTransactionRowAccess_(session,row,rowMap,index) {
  if(!session) return {ok:false,message:'Sesi tidak valid.'};
  if(session.role!=='walikelas' || normalizeText_(session.aksesKelas)==='All') return {ok:true};
  var id=rowMap && rowMap['ID_Santri'] ? normalizeText_(row[rowMap['ID_Santri']-1]) : '';
  var nama=rowMap && rowMap['Nama_Santri'] ? normalizeText_(row[rowMap['Nama_Santri']-1]) : '';
  var idx=index || buildSantriScopeIndex_();
  var st=(id && idx.byId[id]) || (nama && idx.byName[nama.toLowerCase()]);
  if(!st) return {ok:false,message:'Santri pada data tidak ditemukan dalam Data_Santri.'};
  if(normalizeText_(st.kelas).toLowerCase()!==normalizeText_(session.aksesKelas).toLowerCase()) return {ok:false,message:'Anda tidak memiliki akses ke data kelas tersebut.'};
  return {ok:true};
}

function ensureDataIntegrityDatabase_() {
  var ss=SpreadsheetApp.getActiveSpreadsheet();
  var definitions={
    'Trx_Prestasi':['ID_Santri','Created_At','Updated_At','Updated_By'],
    'Trx_Pelanggaran':['ID_Santri','Created_At','Updated_At','Updated_By'],
    'Trx_Catatan_Wali':['ID_Santri','Created_At','Updated_At','Updated_By'],
    'Trx_Perizinan':['ID_Santri','Updated_At','Updated_By'],
    'Trx_Kesehatan':['ID_Santri','Updated_At','Updated_By'],
    'Data_Santri':['Created_At','Updated_At','Updated_By'],
    'Data_Users':['Updated_At','Updated_By']
  };
  Object.keys(definitions).forEach(function(name){var s=ss.getSheetByName(name);if(s)definitions[name].forEach(function(h){ensureColumn(s,h);});});
  var audit=ss.getSheetByName('Audit_Log');
  if(audit) ['Record_ID','Module'].forEach(function(h){ensureColumn(audit,h);});
  return {success:true};
}

function migrateIntegrityRecords_() {
  var props=PropertiesService.getScriptProperties();
  if(props.getProperty('DATA_INTEGRITY_VERSION')==='3.0') return {success:true,skipped:true};
  var ss=SpreadsheetApp.getActiveSpreadsheet();
  // First guarantee stable IDs for existing master records.
  var master=ss.getSheetByName('Data_Santri');
  if(master&&master.getLastRow()>1){
    var mm=headerMap(master);
    if(mm['ID_Santri']){
      var md=master.getDataRange().getValues(), seen={};
      for(var mr=1;mr<md.length;mr++){
        var sid=normalizeText_(md[mr][mm['ID_Santri']-1]);
        if(!sid||seen[sid]){sid=generateRecordId_('SAN');master.getRange(mr+1,mm['ID_Santri']).setValue(sid);}
        seen[sid]=true;
      }
    }
  }
  var maps={
    'Trx_Prestasi':{name:'Nama_Santri',id:'ID_Santri'},
    'Trx_Pelanggaran':{name:'Nama_Santri',id:'ID_Santri'},
    'Trx_Catatan_Wali':{name:'Nama_Santri',id:'ID_Santri'},
    'Trx_Perizinan':{name:'Nama_Santri',id:'ID_Santri'},
    'Trx_Kesehatan':{name:'Nama_Santri',id:'ID_Santri'}
  };
  Object.keys(maps).forEach(function(name){
    var s=ss.getSheetByName(name); if(!s||s.getLastRow()<2)return;
    var m=headerMap(s), cfg=maps[name]; if(!m[cfg.name]||!m[cfg.id])return;
    var santriMap={}; var st=ss.getSheetByName('Data_Santri');
    if(st&&st.getLastRow()>1){var sm=headerMap(st),sd=st.getDataRange().getValues();for(var i=1;i<sd.length;i++)santriMap[normalizeText_(sd[i][sm['Nama_Santri']-1]).toLowerCase()]=normalizeText_(sd[i][sm['ID_Santri']-1]);}
    var data=s.getDataRange().getValues(), out=[];
    for(var r=1;r<data.length;r++){var id=normalizeText_(data[r][m[cfg.id]-1]); if(!id){id=santriMap[normalizeText_(data[r][m[cfg.name]-1]).toLowerCase()]||''; if(id)s.getRange(r+1,m[cfg.id]).setValue(id);} }
  });
  props.setProperty('DATA_INTEGRITY_VERSION','3.0');
  return {success:true};
}

function runDataIntegrityMigration_() {
  return withDataLock_(function(){ ensureDataIntegrityDatabase_(); migrateIntegrityRecords_(); return {success:true,message:'Data Integrity v3 berhasil diinisialisasi dan migrasi aman selesai.'}; });
}


/* ===== BEGIN DriveReports.gs ===== */
/**
 * TAICIMASTER FM — Stage 6 PDF, Drive & Export FINAL v6.0
 * Official reporting/Drive service. Builds on Stage 1–5 contracts.
 */

var STAGE6_REPORT_VERSION = '6.0';
var STAGE6_REPORT_FOLDER_PROPERTY = 'TAICIMASTER_REPORT_FOLDER_ID';
var STAGE6_REPORT_FOLDER_NAME = 'TAICIMASTER FM - Laporan';

var STAGE11_18_1_LOGO_BASE64_ =
  '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';
var STAGE11_18_1_LOGO_MIME_ = 'image/png';

function getReportLogoBlob_() {
  try {
    return Utilities.newBlob(Utilities.base64Decode(STAGE11_18_1_LOGO_BASE64_), STAGE11_18_1_LOGO_MIME_, 'Logo_PPFM.png');
  } catch (e) {
    return null;
  }
}

function appendReportBranding_(body, doc) {
  var logo = getReportLogoBlob_();
  if (logo) {
    var p = body.insertParagraph(0, '');
    p.setAlignment(DocumentApp.HorizontalAlignment.CENTER);
    var img = p.appendInlineImage(logo);
    img.setWidth(62).setHeight(67);
  }
  var header = doc.getHeader() || doc.addHeader();
  header.clear();
  var hp = header.appendParagraph('');
  hp.setAlignment(DocumentApp.HorizontalAlignment.CENTER);
  var hlogo = getReportLogoBlob_();
  if (hlogo) {
    var himg = hp.appendInlineImage(hlogo);
    himg.setWidth(28).setHeight(30);
  }
  hp.appendText('  ' + CONFIG.APP_NAME).setBold(true).setForegroundColor('#6B21A8').setFontSize(9);
}

function getOrCreateReportFolder_() {
  var props = PropertiesService.getScriptProperties();
  var id = props.getProperty(STAGE6_REPORT_FOLDER_PROPERTY);
  if (id) {
    try { return DriveApp.getFolderById(id); } catch (e) { props.deleteProperty(STAGE6_REPORT_FOLDER_PROPERTY); }
  }
  var folders = DriveApp.getFoldersByName(STAGE6_REPORT_FOLDER_NAME);
  var folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(STAGE6_REPORT_FOLDER_NAME);
  props.setProperty(STAGE6_REPORT_FOLDER_PROPERTY, folder.getId());
  return folder;
}

function getReportFolderInfo(token) {
  var auth = requireCapability_(token, 'rekap.view');
  if (!auth.ok) return auth.response;
  try {
    var folder = getOrCreateReportFolder_();
    return {success:true, id:folder.getId(), name:folder.getName(), url:folder.getUrl(), version:STAGE6_REPORT_VERSION};
  } catch (e) {
    return {success:false, message:'Folder laporan tidak dapat diakses: ' + e.toString()};
  }
}

function generateRekapPdf(token, mode, kelasFilter, santriName) {
  var auth = requireCapability_(token, 'rekap.view');
  if (!auth.ok) return auth.response;
  var lock = LockService.getScriptLock();
  lock.waitLock(15000);
  try {
    var modeU = String(mode || 'ANAK').toUpperCase();
    var title, data, filterLabel = String(kelasFilter || 'ALL');
    if (modeU === 'SANTRI') {
      var one = getRekapPerAnak('', '', kelasFilter || 'ALL', token);
      if (!one.success) return one;
      var target = String(santriName || '').trim().toLowerCase();
      data = (one.data || []).filter(function(x){ return String(x.nama || '').trim().toLowerCase() === target; });
      if (!data.length) return {success:false,message:'Data santri tidak ditemukan atau tidak berada dalam cakupan akses Anda.'};
      title = 'Rekapan Individu Santri';
    } else if (modeU === 'KELAS') {
      var kelas = getRekapPerKelas('', '', token);
      if (!kelas.success) return kelas;
      data = kelas.data || [];
      if (filterLabel && filterLabel.toUpperCase() !== 'ALL') data = data.filter(function(x){ return String(x.kelas).toLowerCase() === filterLabel.toLowerCase(); });
      title = 'Rekapan Per Kelas';
    } else {
      var anak = getRekapPerAnak('', '', kelasFilter || 'ALL', token);
      if (!anak.success) return anak;
      data = anak.data || [];
      title = 'Rekapan Per Anak';
    }

    var folder = getOrCreateReportFolder_();
    var tz = Session.getScriptTimeZone() || 'Asia/Jakarta';
    var stamp = Utilities.formatDate(new Date(), tz, 'yyyyMMdd_HHmmss');
    var safeFilter = String((santriName || filterLabel || 'ALL')).replace(/[^a-zA-Z0-9_-]+/g,'_').substring(0,60);
    var fileName = 'TAICIMASTER_' + modeU + '_' + safeFilter + '_' + stamp;

    var doc = DocumentApp.create(fileName);
    var body = doc.getBody();
    body.setMarginTop(36).setMarginBottom(36).setMarginLeft(42).setMarginRight(42);
    appendReportBranding_(body, doc);
    // Stage 11.24: polished report cover/header without changing report data contracts.
    var titleTable = body.appendTable([[CONFIG.APP_NAME + '  •  LAPORAN RESMI']]);
    titleTable.setBorderWidth(0);
    var titleCell = titleTable.getRow(0).getCell(0);
    titleCell.setBackgroundColor('#6B21A8');
    var titlePara = titleCell.getChild(0).asParagraph();
    titlePara.setAlignment(DocumentApp.HorizontalAlignment.CENTER);
    titlePara.setForegroundColor('#FFFFFF').setBold(true).setFontSize(14);

    var heading = body.appendParagraph(title);
    heading.setHeading(DocumentApp.ParagraphHeading.HEADING1);
    heading.setAlignment(DocumentApp.HorizontalAlignment.CENTER);
    heading.setForegroundColor('#581C87').setBold(true);

    var meta = body.appendParagraph('Dicetak: ' + Utilities.formatDate(new Date(), tz, 'dd MMMM yyyy, HH:mm:ss') +
      '  •  Mode: ' + modeU +
      (filterLabel && filterLabel.toUpperCase() !== 'ALL' ? '  •  Kelas: ' + filterLabel : ''));
    meta.setAlignment(DocumentApp.HorizontalAlignment.CENTER);
    meta.setForegroundColor('#64748B').setFontSize(8);
    appendReportSummary_(body, data, modeU, filterLabel, santriName, tz);

    if (modeU === 'KELAS') {
      data.forEach(function(x, idx){
        appendClassSection_(body, x, idx + 1);
      });
    } else {
      data.forEach(function(x, idx){
        appendStudentSection_(body, x, idx + 1);
      });
    }
    var footer = doc.getFooter() || doc.addFooter();
    footer.clear();
    footer.appendParagraph(CONFIG.APP_NAME + ' • Laporan resmi • ' + Utilities.formatDate(new Date(), tz, 'dd/MM/yyyy HH:mm:ss'))
      .setAlignment(DocumentApp.HorizontalAlignment.CENTER).setForegroundColor('#64748B').setFontSize(8);
    body.appendParagraph('Dokumen ini dihasilkan oleh ' + CONFIG.APP_NAME + ' dan tersimpan pada folder laporan resmi.')
      .setForegroundColor('#64748B').setFontSize(8);
    doc.saveAndClose();

    var temp = DriveApp.getFileById(doc.getId());
    var pdfBlob = temp.getAs(MimeType.PDF).setName(fileName + '.pdf');
    var pdfFile = folder.createFile(pdfBlob);
    temp.setTrashed(true);
    auditLog_(auth.session, 'GENERATE_REPORT_PDF', 'REPORT', pdfFile.getId() + '|' + modeU);
    return {success:true,id:pdfFile.getId(),name:pdfFile.getName(),url:pdfFile.getUrl(),folderUrl:folder.getUrl(),mode:modeU};
  } catch (e) {
    return {success:false,message:'Pembuatan PDF gagal: ' + e.toString()};
  } finally {
    try { lock.releaseLock(); } catch (ignore) {}
  }
}

function reportCellStyle_(cell, bg, fg, bold) {
  cell.setBackgroundColor(bg);
  var text = cell.getChild(0);
  if (text && text.getType() === DocumentApp.ElementType.PARAGRAPH) {
    text.asParagraph().setForegroundColor(fg).setBold(!!bold).setFontSize(9);
  }
}

function appendReportSummary_(body, data, modeU, filterLabel, santriName, tz) {
  var totalSantri = 0, prestasi = 0, pelanggaran = 0, catatan = 0, izin = 0, kesehatan = 0;
  if (modeU === 'KELAS') {
    (data || []).forEach(function(x){
      totalSantri += Number(x.santri || 0);
      prestasi += (x.prestasi || []).length;
      pelanggaran += (x.pelanggaran || []).length;
      catatan += (x.catatanWali || []).length;
      izin += (x.perizinan || []).length;
      kesehatan += (x.kesehatan || []).length;
    });
  } else {
    totalSantri = (data || []).length;
    (data || []).forEach(function(x){
      prestasi += (x.prestasi || []).length;
      pelanggaran += (x.pelanggaran || []).length;
      catatan += (x.catatanWali || []).length;
      izin += (x.perizinan || []).length;
      kesehatan += (x.kesehatan || []).length;
    });
  }

  body.appendParagraph('RINGKASAN DATA').setHeading(DocumentApp.ParagraphHeading.HEADING2);
  var table = body.appendTable([
    ['Santri', 'Prestasi', 'Disiplin', 'Catatan Wali', 'Izin', 'Kesehatan'],
    [String(totalSantri), String(prestasi), String(pelanggaran), String(catatan), String(izin), String(kesehatan)]
  ]);
  table.setBorderColor('#E5E7EB');
  table.setBorderWidth(0.5);
  var head = table.getRow(0);
  for (var c=0;c<6;c++) reportCellStyle_(head.getCell(c), '#6B21A8', '#FFFFFF', true);
  var values = table.getRow(1);
  for (var v=0;v<6;v++) {
    values.getCell(v).setBackgroundColor('#F5F3FF');
    var par = values.getCell(v).getChild(0).asParagraph();
    par.setForegroundColor('#334155').setBold(true).setAlignment(DocumentApp.HorizontalAlignment.CENTER).setFontSize(12);
  }
  body.appendParagraph('Dicetak: ' + Utilities.formatDate(new Date(), tz, 'dd/MM/yyyy HH:mm:ss'))
    .setForegroundColor('#64748B').setFontSize(8);
  if (filterLabel && filterLabel.toUpperCase() !== 'ALL') {
    body.appendParagraph('Filter Kelas: ' + filterLabel).setForegroundColor('#64748B').setFontSize(8);
  }
  if (modeU === 'SANTRI' && data.length) {
    body.appendParagraph('Santri: ' + data[0].nama + ' | Kelas: ' + data[0].kelas).setForegroundColor('#64748B').setFontSize(8);
  }
  body.appendHorizontalRule();
}

function appendStudentSection_(body, x, index) {
  var title = body.appendParagraph((index || '') + '. ' + (x.nama || 'Santri'));
  title.setHeading(DocumentApp.ParagraphHeading.HEADING2).setForegroundColor('#581C87').setBold(true);
  body.appendParagraph('Kelas ' + (x.kelas || '-')).setForegroundColor('#64748B').setFontSize(9);
  appendMetricTable_(body, x);
  appendDetailGroup_(body, 'Prestasi', x.prestasi, '#047857', '#ECFDF5');
  appendDetailGroup_(body, 'Pelanggaran / Disiplin', x.pelanggaran, '#BE123C', '#FFF1F2');
  appendDetailGroup_(body, 'Catatan Wali Kelas', x.catatanWali, '#7E22CE', '#FAF5FF');
  appendDetailGroup_(body, 'Perizinan', x.perizinan, '#0369A1', '#F0F9FF');
  appendDetailGroup_(body, 'Kesehatan', x.kesehatan, '#BE185D', '#FDF2F8');
}

function appendClassSection_(body, x, index) {
  var title = body.appendParagraph((index || '') + '. Kelas ' + (x.kelas || '-'));
  title.setHeading(DocumentApp.ParagraphHeading.HEADING2).setForegroundColor('#581C87').setBold(true);
  body.appendParagraph('Jumlah Santri: ' + (x.santri || 0)).setForegroundColor('#64748B').setFontSize(9);
  appendMetricTable_(body, x);
  appendDetailGroup_(body, 'Prestasi', x.prestasi, '#047857', '#ECFDF5');
  appendDetailGroup_(body, 'Pelanggaran / Disiplin', x.pelanggaran, '#BE123C', '#FFF1F2');
  appendDetailGroup_(body, 'Catatan Wali Kelas', x.catatanWali, '#7E22CE', '#FAF5FF');
  appendDetailGroup_(body, 'Perizinan', x.perizinan, '#0369A1', '#F0F9FF');
  appendDetailGroup_(body, 'Kesehatan', x.kesehatan, '#BE185D', '#FDF2F8');
}

function appendMetricTable_(body, x) {
  var table = body.appendTable([
    ['Prestasi', 'Disiplin', 'Catatan', 'Izin', 'Kesehatan'],
    [String((x.prestasi || []).length), String((x.pelanggaran || []).length), String((x.catatanWali || []).length), String((x.perizinan || []).length), String((x.kesehatan || []).length)]
  ]);
  table.setBorderColor('#E2E8F0').setBorderWidth(0.5);
  for (var c=0;c<5;c++) reportCellStyle_(table.getRow(0).getCell(c), '#F1F5F9', '#475569', true);
  for (var v=0;v<5;v++) {
    var p=table.getRow(1).getCell(v).getChild(0).asParagraph();
    p.setAlignment(DocumentApp.HorizontalAlignment.CENTER).setBold(true).setFontSize(11).setForegroundColor('#1E293B');
  }
}

function appendDetailGroup_(body, title, items, fg, bg) {
  var h = body.appendParagraph(title);
  h.setHeading(DocumentApp.ParagraphHeading.HEADING3).setForegroundColor(fg).setBold(true);
  if (!items || !items.length) {
    body.appendParagraph('Belum ada data.').setForegroundColor('#94A3B8').setItalic(true).setFontSize(8);
    return;
  }
  var rows = [['Tanggal', 'Rincian', 'Status']];
  items.forEach(function(d){
    var detail = String(d.judul || d.kategori || d.jenis || '-');
    var extra = String(d.detail || d.catatan || d.deskripsi || '');
    if (extra) detail += ' — ' + extra;
    if (d.tindakLanjut) detail += ' | Tindak lanjut: ' + d.tindakLanjut;
    rows.push([String(d.tanggal || '-'), detail, String(d.status || '-')]);
  });
  var table = body.appendTable(rows);
  table.setBorderColor('#E2E8F0').setBorderWidth(0.5);
  for (var c=0;c<3;c++) reportCellStyle_(table.getRow(0).getCell(c), bg, fg, true);
  for (var r=1;r<table.getNumRows();r++) {
    table.getRow(r).getCell(0).setBackgroundColor('#F8FAFC');
    table.getRow(r).getCell(2).setBackgroundColor('#F8FAFC');
    for (var c2=0;c2<3;c2++) {
      var p=table.getRow(r).getCell(c2).getChild(0).asParagraph();
      p.setFontSize(8).setForegroundColor('#334155');
    }
  }
  body.appendParagraph('');
}


/* ===== BEGIN Kesehatan.gs ===== */
/** TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0 — Kesehatan */
function simpanKesehatan(data,token){var a=requireCapability_(token,'kesehatan.create');if(!a.ok)return a.response;var d=data||{},req=requireFields_(d,['santriNama','tanggal','keluhan']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama);if(!st)return {success:false,message:'Santri tidak ditemukan.'};if(!normalizeDateInput_(d.tanggal))return {success:false,message:'Tanggal pemeriksaan tidak valid.'};if(!cacheDuplicateGuard_('KESEHATAN',a.session.id,{santri:st.id||st.nama,tanggal:d.tanggal,keluhan:d.keluhan}))return {success:false,code:'DUPLICATE_REQUEST',message:'Permintaan yang sama baru saja diproses. Hindari klik dua kali.'};try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan'),m=headerMap(sh),now=new Date(),id=generateRecordId_('KES'),vals={'ID_Kesehatan':id,'Nama_Santri':st.nama,'Kelas':st.kelas,'Tanggal':d.tanggal,'Keluhan':normalizeText_(d.keluhan,1000),'Pemeriksaan':normalizeText_(d.pemeriksaan,2000),'Diagnosa':normalizeText_(d.diagnosa,1000),'Tindakan':normalizeText_(d.tindakan,2000),'Obat':normalizeText_(d.obat,1000),'Suhu':d.suhu||'','Berat_Badan':d.beratBadan||'','Status':normalizeText_(d.status,100),'Tindak_Lanjut':normalizeText_(d.tindakLanjut,1000),'Status_Kesehatan':'Belum Sehat','Created_By':a.session.name,'Created_At':now};var row=new Array(sh.getLastColumn()).fill('');Object.keys(vals).forEach(function(h){if(m[h])row[m[h]-1]=vals[h];});if(m['ID_Santri'])row[m['ID_Santri']-1]=st.id;if(m['Updated_At'])row[m['Updated_At']-1]=now;if(m['Updated_By'])row[m['Updated_By']-1]=a.session.name;sh.appendRow(row);auditLog_(a.session,'CREATE_KESEHATAN',id,'Santri='+st.id);queueNewDataPush_('KESEHATAN',st,id,'Approved',a.session);try{queueWhatsAppNotification_('KESEHATAN',st,id,{category:'Pemeriksaan Kesehatan',status:d.status||'Tercatat',detail:d.keluhan},a.session);}catch(e){}return {success:true,idKesehatan:id,message:'Data pemeriksaan kesehatan berhasil disimpan.'};});}catch(e){return {success:false,message:e.toString()};}}
function getKesehatanList(role,aksesKelas,token){
  var a=requireCapability_(token,'kesehatan.view');
  if(!a.ok)return a.response;
  var sess=a.session;
  try{
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan');
    if(!sh)return {success:false,message:'Sheet Trx_Kesehatan tidak ditemukan. Jalankan inisialisasi database terlebih dahulu.'};
    var m=headerMap(sh),lastRow=sh.getLastRow(),lastCol=sh.getLastColumn(),o=[];
    if(lastRow<2)return {success:true,data:[]};
    function gv(row,name){return m[name]?row[m[name]-1]:'';}
    function pushRow(row){
      var nama=String(gv(row,'Nama_Santri')||'').trim();
      if(!nama)return;
      var kelas=String(gv(row,'Kelas')||'').trim();
      if(sess.role==='walikelas' && sess.aksesKelas!=='All' && kelas.toLowerCase()!==String(sess.aksesKelas).toLowerCase())return;
      var status=gv(row,'Status');
      var statusKes=m['Status_Kesehatan']?String(gv(row,'Status_Kesehatan')||'').trim():(String(status||'').toLowerCase()==='selesai'?'Sudah Sehat':'Belum Sehat');
      if(!statusKes)statusKes='Belum Sehat';
      o.push({
        id:gv(row,'ID_Kesehatan'),santriNama:nama,kelas:kelas,
        tanggal:formatDateSafe(gv(row,'Tanggal')),keluhan:gv(row,'Keluhan'),diagnosa:gv(row,'Diagnosa'),obat:gv(row,'Obat'),
        suhu:gv(row,'Suhu'),status:status,statusKesehatan:statusKes,
        recoveredAt:m['Recovered_At']?gv(row,'Recovered_At'):'',recoveredBy:m['Recovered_By']?gv(row,'Recovered_By'):'',
        tindakLanjut:m['Tindak_Lanjut']?gv(row,'Tindak_Lanjut'):'',createdBy:m['Created_By']?gv(row,'Created_By'):''
      });
    }

    // Optimasi khusus Wali Kelas: jangan membaca seluruh isi Trx_Kesehatan
    // bila data hanya dibutuhkan untuk satu kelas. Baca kolom Kelas dahulu,
    // lalu ambil blok baris yang relevan. Perilaku dan data untuk role lain tetap sama.
    if(sess.role==='walikelas' && sess.aksesKelas!=='All' && m['Kelas']){
      var classValues=sh.getRange(2,m['Kelas'],lastRow-1,1).getValues();
      var target=String(sess.aksesKelas).toLowerCase(), rows=[];
      for(var r=0;r<classValues.length;r++){
        if(String(classValues[r][0]||'').trim().toLowerCase()===target)rows.push(r+2);
      }
      // Ambil dalam blok baris berurutan agar jumlah panggilan Spreadsheet Service tetap kecil.
      if(rows.length){
        var groups=[],gStart=rows[0],gEnd=rows[0];
        for(var q=1;q<rows.length;q++){
          if(rows[q]===gEnd+1){gEnd=rows[q];}
          else{groups.push([gStart,gEnd]);gStart=gEnd=rows[q];}
        }
        groups.push([gStart,gEnd]);
        for(var gi=groups.length-1;gi>=0;gi--){
          var gr=groups[gi],vals=sh.getRange(gr[0],1,gr[1]-gr[0]+1,lastCol).getValues();
          for(var vi=vals.length-1;vi>=0;vi--)pushRow(vals[vi]);
        }
      }
      return {success:true,data:o};
    }

    var d=sh.getDataRange().getValues();
    for(var i=d.length-1;i>=1;i--)pushRow(d[i]);
    return {success:true,data:o};
  }catch(e){return {success:false,message:'Gagal memuat Data Kesehatan: '+e.toString()};}
}

function updateKesehatan(data,token){
 var a=requireCapability_(token,'kesehatan.edit');if(!a.ok)return a.response;var d=data||{},req=requireFields_(d,['id','santriNama','tanggal','keluhan']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama);if(!st)return {success:false,message:'Santri tidak ditemukan.'};
 try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Kesehatan']-1])===String(d.id)){var vals={'Nama_Santri':st.nama,'Kelas':st.kelas,'Tanggal':d.tanggal,'Keluhan':normalizeText_(d.keluhan,1000),'Pemeriksaan':normalizeText_(d.pemeriksaan,2000),'Diagnosa':normalizeText_(d.diagnosa,1000),'Tindakan':normalizeText_(d.tindakan,2000),'Obat':normalizeText_(d.obat,1000),'Suhu':d.suhu||'','Berat_Badan':d.beratBadan||'','Status':normalizeText_(d.status,100),'Tindak_Lanjut':normalizeText_(d.tindakLanjut,1000)};Object.keys(vals).forEach(function(h){if(m[h])sh.getRange(i+1,m[h]).setValue(vals[h]);});if(m['ID_Santri'])sh.getRange(i+1,m['ID_Santri']).setValue(st.id);if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(new Date());if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(a.session.name);auditLog_(a.session,'UPDATE_KESEHATAN',String(d.id),'Santri='+st.id);return {success:true,message:'Data Kesehatan berhasil diperbarui.'};}return {success:false,message:'Data Kesehatan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}

function bulkMarkKesehatanRecovered(ids,token){
  var a=requireCapability_(token,'kesehatan.edit');if(!a.ok)return a.response;
  ids=Array.isArray(ids)?ids.map(String).filter(Boolean):[];if(!ids.length)return {success:false,message:'Pilih minimal satu data kesehatan.'};
  try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan'),m=headerMap(sh),rows=sh.getDataRange().getValues(),set={};ids.forEach(function(id){set[id]=true;});var count=0,now=new Date();
    for(var i=1;i<rows.length;i++){var id=String(rows[i][m['ID_Kesehatan']-1]||'');if(!set[id])continue;
      if(m['Status_Kesehatan'])sh.getRange(i+1,m['Status_Kesehatan']).setValue('Sudah Sehat');
      if(m['Status'])sh.getRange(i+1,m['Status']).setValue('Selesai');
      if(m['Recovered_At'])sh.getRange(i+1,m['Recovered_At']).setValue(now);
      if(m['Recovered_By'])sh.getRange(i+1,m['Recovered_By']).setValue(a.session.name);
      if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(now);
      if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(a.session.name);count++;
    }
    auditLog_(a.session,'BULK_RECOVER_KESEHATAN',ids.join(','),'Jumlah='+count);
    return {success:true,count:count,message:count+' data santri ditandai sudah sehat.'};
  });}catch(e){return {success:false,message:e.toString()};}
}

function deleteKesehatan(id,token){var a=requireCapability_(token,'kesehatan.delete');if(!a.ok)return a.response;try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Kesehatan']-1])===String(id)){sh.deleteRow(i+1);auditLog_(a.session,'DELETE_KESEHATAN',String(id),'');return {success:true,message:'Data Kesehatan berhasil dihapus.'};}return {success:false,message:'Data Kesehatan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}


/* ===== BEGIN Pelanggaran.gs ===== */
/** TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0 — Pelanggaran */
function simpanPelanggaran(formData,fileObj,token){var a=requireCapability_(token,'pelanggaran.create');if(!a.ok)return a.response;var s=a.session,d=formData||{},req=requireFields_(d,['santriNama','tanggal','jenisPelanggaran','deskripsi']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama),ac=assertSantriAccess_(s,st);if(!ac.ok)return {success:false,message:ac.message};if(!normalizeDateInput_(d.tanggal))return {success:false,message:'Tanggal pelanggaran tidak valid.'};if(!cacheDuplicateGuard_('PELANGGARAN',s.id,{santri:st.id||st.nama,tanggal:d.tanggal,jenis:d.jenisPelanggaran,deskripsi:d.deskripsi}))return {success:false,code:'DUPLICATE_REQUEST',message:'Permintaan yang sama baru saja diproses. Hindari klik dua kali.'};try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Pelanggaran'),m=headerMap(sh),url='',now=new Date();if(fileObj&&fileObj.data){var f=DriveApp.getFolderById(CONFIG.DRIVE_PELANGGARAN_FOLDER_ID);url=f.createFile(Utilities.newBlob(Utilities.base64Decode(fileObj.data),fileObj.mimeType||'application/octet-stream',normalizeText_(fileObj.fileName,150)||('bukti-'+generateRecordId_('PLG')))).getUrl();}var id=generateRecordId_('PLG'),vals={'ID_Pelanggaran':id,'Nama_Santri':st.nama,'Tanggal':d.tanggal,'Jenis_Pelanggaran':normalizeText_(d.jenisPelanggaran,100),'Tingkat_Pelanggaran':normalizeText_(d.tingkatPelanggaran,100),'Deskripsi':normalizeText_(d.deskripsi,2000),'Kronologi':normalizeText_(d.kronologi,3000),'Tindak_Pembinaan':normalizeText_(d.tindakPembinaan,2000),'Tindak_Lanjut':normalizeText_(d.tindakLanjut,2000),'Link_Bukti':url,'Status_Approval':'Approved','Created_By':a.session.name};var row=new Array(sh.getLastColumn()).fill('');Object.keys(vals).forEach(function(h){if(m[h])row[m[h]-1]=vals[h];});if(m['ID_Santri'])row[m['ID_Santri']-1]=st.id;if(m['Created_At'])row[m['Created_At']-1]=now;if(m['Updated_At'])row[m['Updated_At']-1]=now;if(m['Updated_By'])row[m['Updated_By']-1]=a.session.name;sh.appendRow(row);auditLog_(a.session,'CREATE_PELANGGARAN',id,'Santri='+st.id);try{sendNotificationEmail('PELANGGARAN',st.nama,d.jenisPelanggaran+' (Tingkat '+d.tingkatPelanggaran+')',d.deskripsi,token);}catch(e){}
queueNewDataPush_('PELANGGARAN',st,id,'Approved',a.session);try{queueWhatsAppNotification_('PELANGGARAN',st,id,{category:d.jenisPelanggaran,status:'Tercatat',detail:d.deskripsi},a.session);}catch(e){}return {success:true,idPelanggaran:id,message:'Data Pelanggaran Berhasil Disimpan!'};});}catch(e){return {success:false,message:'Gagal menyimpan data: '+e.toString()};}}

function getPelanggaranList(token){
  var a=requireCapability_(token,'pelanggaran.view'); if(!a.ok)return a.response;
  try{var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Pelanggaran');if(!sh)return {success:true,data:[]};var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[],scopeIndex=buildSantriScopeIndex_();
  for(var i=d.length-1;i>=1;i--){var access=assertTransactionRowAccess_(a.session,d[i],m,scopeIndex);if(!access.ok)continue;o.push({id:d[i][m['ID_Pelanggaran']-1],santriNama:d[i][m['Nama_Santri']-1],tanggal:d[i][m['Tanggal']-1]?Utilities.formatDate(new Date(d[i][m['Tanggal']-1]),Session.getScriptTimeZone(),'yyyy-MM-dd'):'',jenisPelanggaran:d[i][m['Jenis_Pelanggaran']-1],tingkatPelanggaran:d[i][m['Tingkat_Pelanggaran']-1],deskripsi:d[i][m['Deskripsi']-1],kronologi:d[i][m['Kronologi']-1],tindakPembinaan:d[i][m['Tindak_Pembinaan']-1],tindakLanjut:d[i][m['Tindak_Lanjut']-1]});}
  return {success:true,data:o};}catch(e){return {success:false,message:e.toString()};}
}
function updatePelanggaran(data,token){
 var a=requireCapability_(token,'pelanggaran.edit');if(!a.ok)return a.response;var d=data||{},req=requireFields_(d,['id','santriNama','tanggal','jenisPelanggaran','deskripsi']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama);if(!st)return {success:false,message:'Santri tidak ditemukan.'};var targetAccess=assertSantriAccess_(a.session,st);if(!targetAccess.ok)return {success:false,message:targetAccess.message};if(!normalizeDateInput_(d.tanggal))return {success:false,message:'Tanggal tidak valid.'};
 try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Pelanggaran'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Pelanggaran']-1])===String(d.id)){var vals={'Nama_Santri':st.nama,'Tanggal':d.tanggal,'Jenis_Pelanggaran':normalizeText_(d.jenisPelanggaran,100),'Tingkat_Pelanggaran':normalizeText_(d.tingkatPelanggaran,100),'Deskripsi':normalizeText_(d.deskripsi,2000),'Kronologi':normalizeText_(d.kronologi,3000),'Tindak_Pembinaan':normalizeText_(d.tindakPembinaan,2000),'Tindak_Lanjut':normalizeText_(d.tindakLanjut,2000)};Object.keys(vals).forEach(function(h){if(m[h])sh.getRange(i+1,m[h]).setValue(vals[h]);});if(m['ID_Santri'])sh.getRange(i+1,m['ID_Santri']).setValue(st.id);if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(new Date());if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(a.session.name);auditLog_(a.session,'UPDATE_PELANGGARAN',String(d.id),'Santri='+st.id);return {success:true,message:'Data Pelanggaran berhasil diperbarui.'};}return {success:false,message:'Data Pelanggaran tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}
function deletePelanggaran(id,token){var a=requireCapability_(token,'pelanggaran.delete');if(!a.ok)return a.response;try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Pelanggaran'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Pelanggaran']-1])===String(id)){var rowAccess=assertTransactionRowAccess_(a.session,rows[i],m);if(!rowAccess.ok)return {success:false,message:rowAccess.message};sh.deleteRow(i+1);auditLog_(a.session,'DELETE_PELANGGARAN',String(id),'');return {success:true,message:'Data Pelanggaran berhasil dihapus.'};}return {success:false,message:'Data Pelanggaran tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}


/* ===== BEGIN Perizinan.gs ===== */
/** TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0 — Perizinan */
function _perizinanMonthlyDuplicate_(sh,m,santriId,santriNama,mulai,excludeId){
  var target=new Date(mulai); if(isNaN(target.getTime())) return false;
  var ty=target.getFullYear(), tm=target.getMonth(), rows=sh.getDataRange().getValues();
  for(var i=1;i<rows.length;i++){
    var id=m['ID_Perizinan']?String(rows[i][m['ID_Perizinan']-1]||''):'';
    if(excludeId && id===String(excludeId)) continue;
    var rid=m['ID_Santri']?String(rows[i][m['ID_Santri']-1]||''):'';
    var rn=m['Nama_Santri']?String(rows[i][m['Nama_Santri']-1]||'').trim():'';
    if((santriId && rid===String(santriId)) || (!rid && rn && rn.toLowerCase()===String(santriNama||'').trim().toLowerCase())){
      var status=m['Status']?String(rows[i][m['Status']-1]||'').trim().toLowerCase():'';
      if(status==='ditolak') continue;
      var d=new Date(rows[i][m['Mulai']-1]);
      if(!isNaN(d.getTime()) && d.getFullYear()===ty && d.getMonth()===tm) return true;
    }
  }
  return false;
}

function simpanPerizinan(data, token) {
  var auth = requireCapability_(token, 'perizinan.create');
  if (!auth.ok) return auth.response;

  var d = data || {};
  var required = requireFields_(d, ['santriNama', 'jenis', 'mulai', 'selesai']);
  if (!required.ok) return { success: false, message: required.message };

  var santri = getSantriRecordByName_(d.santriNama);
  if (!santri) return { success: false, message: 'Santri tidak ditemukan.' };
  if (!normalizeDateInput_(d.mulai) || !normalizeDateInput_(d.selesai)) {
    return { success: false, message: 'Tanggal mulai/selesai tidak valid.' };
  }
  if (new Date(d.selesai).getTime() < new Date(d.mulai).getTime()) {
    return { success: false, message: 'Tanggal selesai tidak boleh sebelum tanggal mulai.' };
  }

  var confirmedDuplicate = d.allowMonthlyDuplicate === true;
  var duplicateRequest = {
    santri: santri.id || santri.nama,
    mulai: d.mulai,
    selesai: d.selesai,
    jenis: d.jenis,
    allowMonthlyDuplicate: confirmedDuplicate
  };
  try {
    return withDataLock_(function () {
      var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Perizinan');
      var headers = headerMap(sheet);
      var monthlyDuplicate = _perizinanMonthlyDuplicate_(sheet, headers, santri.id, santri.nama, d.mulai, null);
      if (monthlyDuplicate && !confirmedDuplicate) {
        return {
          success: false,
          code: 'MONTHLY_DUPLICATE_CONFIRMATION_REQUIRED',
          message: 'Santri ini sudah memiliki izin pada bulan yang sama. Apakah Anda ingin tetap menyimpan izin baru?'
        };
      }
      if (!cacheDuplicateGuard_('PERIZINAN', auth.session.id, duplicateRequest)) {
        return { success: false, code: 'DUPLICATE_REQUEST', message: 'Permintaan yang sama baru saja diproses. Hindari klik dua kali.' };
      }

      var now = new Date();
      var id = generateRecordId_('IZN');
      var values = {
        'ID_Perizinan': id,
        'Nama_Santri': santri.nama,
        'Kelas': santri.kelas,
        'Jenis': normalizeText_(d.jenis, 100),
        'Mulai': d.mulai,
        'Selesai': d.selesai,
        'Tujuan': normalizeText_(d.tujuan, 500),
        'Penanggung_Jawab': normalizeText_(d.penanggungJawab, 150),
        'Alasan': normalizeText_(d.alasan, 1000),
        'Status': 'Diajukan',
        'Status_Kembali': 'Belum Kembali',
        'Created_By': auth.session.name,
        'Created_At': now
      };
      var row = new Array(sheet.getLastColumn()).fill('');
      Object.keys(values).forEach(function (name) {
        if (headers[name]) row[headers[name] - 1] = values[name];
      });
      if (headers['ID_Santri']) row[headers['ID_Santri'] - 1] = santri.id;
      if (headers['Updated_At']) row[headers['Updated_At'] - 1] = now;
      if (headers['Updated_By']) row[headers['Updated_By'] - 1] = auth.session.name;

      sheet.appendRow(row);
      auditLog_(auth.session, 'CREATE_PERIZINAN', id, 'Santri=' + santri.id);
      queueNewDataPush_('PERIZINAN', santri, id, 'Approved', auth.session);
      try {
        queueWhatsAppNotification_('PERIZINAN', santri, id, {
          category: d.jenis,
          status: 'Diajukan',
          detail: d.alasan || d.tujuan
        }, auth.session);
      } catch (notificationError) {}

      return {
        success: true,
        idPerizinan: id,
        message: monthlyDuplicate
          ? 'Perizinan berhasil diajukan. Peringatan: santri ini sudah memiliki izin pada bulan yang sama.'
          : 'Perizinan berhasil diajukan.'
      };
    });
  } catch (error) {
    return { success: false, message: error.toString() };
  }
}

function updatePerizinan(data, token) {
  var auth = requireCapability_(token, 'perizinan.edit');
  if (!auth.ok) return auth.response;

  var d = data || {};
  var required = requireFields_(d, ['id', 'santriNama', 'jenis', 'mulai', 'selesai']);
  if (!required.ok) return { success: false, message: required.message };

  var santri = getSantriRecordByName_(d.santriNama);
  if (!santri) return { success: false, message: 'Santri tidak ditemukan.' };
  var targetAccess = assertSantriAccess_(auth.session, santri);
  if (!targetAccess.ok) return { success: false, message: targetAccess.message };
  if (!normalizeDateInput_(d.mulai) || !normalizeDateInput_(d.selesai)) {
    return { success: false, message: 'Tanggal mulai/selesai tidak valid.' };
  }
  if (new Date(d.selesai).getTime() < new Date(d.mulai).getTime()) {
    return { success: false, message: 'Tanggal selesai tidak boleh sebelum tanggal mulai.' };
  }

  try {
    return withDataLock_(function () {
      var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Perizinan');
      if (!sheet) return { success: false, message: 'Sheet Trx_Perizinan tidak ditemukan.' };
      var headers = headerMap(sheet);
      var rows = sheet.getDataRange().getValues();
      for (var i = 1; i < rows.length; i++) {
        if (String(rows[i][headers['ID_Perizinan'] - 1] || '') !== String(d.id)) continue;
        var rowAccess = assertTransactionRowAccess_(auth.session, rows[i], headers);
        if (!rowAccess.ok) return { success: false, message: rowAccess.message };
        if (_perizinanMonthlyDuplicate_(sheet, headers, santri.id, santri.nama, d.mulai, d.id)) {
          return { success: false, code: 'MONTHLY_LIMIT', message: 'Santri ini sudah memiliki izin pada bulan yang sama. Perubahan tidak disimpan.' };
        }

        var values = {
          'Nama_Santri': santri.nama,
          'Kelas': santri.kelas,
          'Jenis': normalizeText_(d.jenis, 100),
          'Mulai': d.mulai,
          'Selesai': d.selesai,
          'Tujuan': normalizeText_(d.tujuan, 500),
          'Penanggung_Jawab': normalizeText_(d.penanggungJawab, 150),
          'Alasan': normalizeText_(d.alasan, 1000)
        };
        Object.keys(values).forEach(function (name) {
          if (headers[name]) sheet.getRange(i + 1, headers[name]).setValue(values[name]);
        });
        if (headers['ID_Santri']) sheet.getRange(i + 1, headers['ID_Santri']).setValue(santri.id);
        if (headers['Updated_At']) sheet.getRange(i + 1, headers['Updated_At']).setValue(new Date());
        if (headers['Updated_By']) sheet.getRange(i + 1, headers['Updated_By']).setValue(auth.session.name);
        auditLog_(auth.session, 'UPDATE_PERIZINAN', String(d.id), 'Santri=' + santri.id);
        return { success: true, message: 'Data Perizinan berhasil diperbarui.' };
      }
      return { success: false, message: 'Data Perizinan tidak ditemukan.' };
    });
  } catch (error) {
    return { success: false, message: error.toString() };
  }
}

function getPerizinanList(role,aksesKelas,token){
  var a=requireCapability_(token,'perizinan.view');
  if(!a.ok)return a.response;
  var s=a.session;
  try{
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Perizinan');
    if(!sh)return {success:false,message:'Sheet Trx_Perizinan tidak ditemukan. Jalankan inisialisasi database terlebih dahulu.'};
    var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[];
    function gv(row,name){return m[name]?row[m[name]-1]:'';}
    for(var i=d.length-1;i>=1;i--){
      var nama=String(gv(d[i],'Nama_Santri')||'').trim();
      if(!nama)continue;
      var k=String(gv(d[i],'Kelas')||'').trim();
      if(s.role==='walikelas' && s.aksesKelas!=='All' && k.toLowerCase()!==String(s.aksesKelas).toLowerCase())continue;
      o.push({
        id:gv(d[i],'ID_Perizinan'),
        santriNama:nama,
        kelas:k,
        jenis:gv(d[i],'Jenis'),
        mulai:formatDateSafe(gv(d[i],'Mulai')),
        selesai:formatDateSafe(gv(d[i],'Selesai')),
        tujuan:gv(d[i],'Tujuan'),
        penanggungJawab:gv(d[i],'Penanggung_Jawab'),
        alasan:gv(d[i],'Alasan'),
        status:gv(d[i],'Status'),
        statusKembali:m['Status_Kembali']?gv(d[i],'Status_Kembali'):'Belum Kembali',
        returnedAt:m['Returned_At']?gv(d[i],'Returned_At'):'',
        returnedBy:m['Returned_By']?gv(d[i],'Returned_By'):'',
        createdBy:m['Created_By']?gv(d[i],'Created_By'):''
      });
    }
    return {success:true,data:o};
  }catch(e){return {success:false,message:'Gagal memuat Data Perizinan: '+e.toString()};}
}

function bulkMarkPerizinanReturned(ids,token){
  var a=requireCapability_(token,'perizinan.edit');if(!a.ok)return a.response;
  ids=Array.isArray(ids)?ids.map(String).filter(Boolean):[];if(!ids.length)return {success:false,message:'Pilih minimal satu data perizinan.'};
  try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Perizinan'),m=headerMap(sh),rows=sh.getDataRange().getValues(),set={};ids.forEach(function(id){set[id]=true;});var count=0,now=new Date();
    for(var i=1;i<rows.length;i++){var id=String(rows[i][m['ID_Perizinan']-1]||'');if(!set[id])continue;
      if(m['Status_Kembali'])sh.getRange(i+1,m['Status_Kembali']).setValue('Sudah Kembali');
      if(m['Returned_At'])sh.getRange(i+1,m['Returned_At']).setValue(now);
      if(m['Returned_By'])sh.getRange(i+1,m['Returned_By']).setValue(a.session.name);
      if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(now);
      if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(a.session.name);count++;
    }
    auditLog_(a.session,'BULK_RETURN_PERIZINAN',ids.join(','),'Jumlah='+count);
    return {success:true,count:count,message:count+' data santri ditandai sudah kembali.'};
  });}catch(e){return {success:false,message:e.toString()};}
}

function deletePerizinan(id,token){var a=requireCapability_(token,'perizinan.delete');if(!a.ok)return a.response;try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Perizinan'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Perizinan']-1])===String(id)){sh.deleteRow(i+1);auditLog_(a.session,'DELETE_PERIZINAN',String(id),'');return {success:true,message:'Data Perizinan berhasil dihapus.'};}return {success:false,message:'Data Perizinan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}


/* ===== BEGIN Prestasi.gs ===== */
/** TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0 — Prestasi */
function simpanPrestasi(formData, fileObj, token) {
  var auth=requireCapability_(token,'prestasi.create'); if(!auth.ok)return auth.response;
  var s=auth.session, data=formData||{};
  var req=requireFields_(data,['santriNama','tanggal','jenisPrestasi','uraian']); if(!req.ok)return {success:false,message:req.message};
  var santri=getSantriRecordByName_(data.santriNama), access=assertSantriAccess_(s,santri); if(!access.ok)return {success:false,message:access.message};
  if(!normalizeDateInput_(data.tanggal))return {success:false,message:'Tanggal prestasi tidak valid.'};
  if(!cacheDuplicateGuard_('PRESTASI',s.id,{santri:santri.id||santri.nama,tanggal:data.tanggal,jenis:data.jenisPrestasi,uraian:data.uraian}))return {success:false,code:'DUPLICATE_REQUEST',message:'Permintaan yang sama baru saja diproses. Hindari klik dua kali.'};
  try{return withDataLock_(function(){
    var sheet=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Prestasi'); if(!sheet)throw new Error('Sheet Trx_Prestasi tidak ditemukan.');
    var fileUrl='';
    if(fileObj&&fileObj.data){var folder=DriveApp.getFolderById(CONFIG.DRIVE_PRESTASI_FOLDER_ID);var blob=Utilities.newBlob(Utilities.base64Decode(fileObj.data),fileObj.mimeType||'application/octet-stream',normalizeText_(fileObj.fileName,150)||('bukti-'+generateRecordId_('PRS')));fileUrl=folder.createFile(blob).getUrl();}
    var id=generateRecordId_('PRS'), status=s.role==='walikelas'?'Pending':'Approved', now=new Date(), m=headerMap(sheet);
    var row=new Array(sheet.getLastColumn()).fill('');
    var values={'ID_Prestasi':id,'Nama_Santri':santri.nama,'Tanggal':data.tanggal,'Jenis_Prestasi':normalizeText_(data.jenisPrestasi,100),'Uraian_Prestasi':normalizeText_(data.uraian,2000),'Tingkat_Penghargaan':normalizeText_(data.tingkatPenghargaan,100),'Tingkat_Juara':normalizeText_(data.tingkatJuara,100),'Tingkat_Lomba':normalizeText_(data.tingkatTempat||data.tingkatLomba,100),'Pembimbing':normalizeText_(data.pembimbing,150),'Link_Bukti':fileUrl,'Status_Approval':status,'Created_By':s.name};
    Object.keys(values).forEach(function(h){if(m[h])row[m[h]-1]=values[h];}); if(m['ID_Santri'])row[m['ID_Santri']-1]=santri.id; if(m['Created_At'])row[m['Created_At']-1]=now; if(m['Updated_At'])row[m['Updated_At']-1]=now; if(m['Updated_By'])row[m['Updated_By']-1]=s.name;
    sheet.appendRow(row); auditLog_(s,'CREATE_PRESTASI',id,'Santri='+santri.id+'; Status='+status);
    queueNewDataPush_('PRESTASI',santri,id,status,s);
    try{sendNotificationEmail('PRESTASI',santri.nama,data.jenisPrestasi+' ('+status+')',data.uraian,token);}catch(e){}
    try{queueWhatsAppNotification_('PRESTASI',santri,id,{category:data.jenisPrestasi,status:status,detail:data.uraian},s);}catch(e){}
    return {success:true,idPrestasi:id,message:status==='Pending'?'Data Prestasi berhasil diajukan dan menunggu persetujuan Admin Prestasi!':'Data Prestasi Berhasil Disimpan & Approved!'};
  });}catch(e){return {success:false,message:'Gagal menyimpan data: '+e.toString()};}
}
function getPendingPrestasiList(token){var a=requireCapability_(token,'prestasi.view');if(!a.ok)return a.response;try{var s=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Prestasi'),d=s.getDataRange().getValues(),o=[];var scopeIndex=buildSantriScopeIndex_();for(var i=1;i<d.length;i++)if(String(d[i][10])==='Pending'){var access=assertTransactionRowAccess_(a.session,d[i],headerMap(s),scopeIndex);if(!access.ok)continue;o.push({idPrestasi:d[i][0],santriNama:d[i][1],tanggal:d[i][2]?Utilities.formatDate(new Date(d[i][2]),Session.getScriptTimeZone(),'dd/MM/yyyy'):'',jenisPrestasi:d[i][3],uraian:d[i][4],createdBy:d[i][11]});}return {success:true,data:o};}catch(e){return {success:false,message:e.toString()};}}
function updatePrestasiApprovalStatus(idPrestasi,newStatus,token){var a=requireCapability_(token,'prestasi.approve');if(!a.ok)return a.response;if(['Approved','Rejected'].indexOf(newStatus)<0)return {success:false,message:'Status approval tidak valid.'};try{return withDataLock_(function(){var s=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Prestasi'),m=headerMap(s),d=s.getDataRange().getValues();for(var i=1;i<d.length;i++)if(String(d[i][m['ID_Prestasi']-1])===String(idPrestasi)){var previousStatus=String(d[i][m['Status_Approval']-1]||'');s.getRange(i+1,m['Status_Approval']).setValue(newStatus);if(m['Updated_At'])s.getRange(i+1,m['Updated_At']).setValue(new Date());if(m['Updated_By'])s.getRange(i+1,m['Updated_By']).setValue(a.session.name);auditLog_(a.session,'UPDATE_PRESTASI_APPROVAL',String(idPrestasi),'Status='+newStatus);
        try{var st=getSantriRecordByName_(d[i][m['Nama_Santri']-1]); if(newStatus==='Approved' && previousStatus!=='Approved')queueNewDataPush_('PRESTASI',st,String(idPrestasi),'Approved',a.session); else if(newStatus==='Rejected' && previousStatus!=='Rejected')queueNewDataPush_('PRESTASI',st,String(idPrestasi),'Rejected',a.session); queueWhatsAppNotification_('PRESTASI_APPROVAL',st,String(idPrestasi),{category:'Persetujuan Prestasi',status:newStatus,detail:'Status prestasi diperbarui.'},a.session);}catch(e){}
        return {success:true,message:'Status persetujuan prestasi berhasil diperbarui menjadi: '+newStatus};}return {success:false,message:'ID Prestasi tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}}

function getPrestasiList(token){
  var a=requireCapability_(token,'prestasi.view'); if(!a.ok)return a.response;
  try{
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Prestasi'); if(!sh)return {success:true,data:[]};
    var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[],scopeIndex=buildSantriScopeIndex_();
    for(var i=d.length-1;i>=1;i--){ var access=assertTransactionRowAccess_(a.session,d[i],m,scopeIndex); if(!access.ok) continue; o.push({
      id:d[i][m['ID_Prestasi']-1],santriNama:d[i][m['Nama_Santri']-1],
      tanggal:d[i][m['Tanggal']-1]?Utilities.formatDate(new Date(d[i][m['Tanggal']-1]),Session.getScriptTimeZone(),'yyyy-MM-dd'):'',
      jenisPrestasi:d[i][m['Jenis_Prestasi']-1],uraian:d[i][m['Uraian_Prestasi']-1],
      tingkatPenghargaan:d[i][m['Tingkat_Penghargaan']-1],tingkatJuara:d[i][m['Tingkat_Juara']-1],
      tingkatTempat:d[i][m['Tingkat_Lomba']-1],pembimbing:d[i][m['Pembimbing']-1],status:d[i][m['Status_Approval']-1]
    }); }
    return {success:true,data:o};
  }catch(e){return {success:false,message:e.toString()};}
}
function updatePrestasi(data,token){
  var a=requireCapability_(token,'prestasi.edit'); if(!a.ok)return a.response;
  var d=data||{}, req=requireFields_(d,['id','santriNama','tanggal','jenisPrestasi','uraian']); if(!req.ok)return {success:false,message:req.message};
  var st=getSantriRecordByName_(d.santriNama); if(!st)return {success:false,message:'Santri tidak ditemukan.'};
  var targetAccess=assertSantriAccess_(a.session,st); if(!targetAccess.ok)return {success:false,message:targetAccess.message};
  if(!normalizeDateInput_(d.tanggal))return {success:false,message:'Tanggal tidak valid.'};
  try{return withDataLock_(function(){
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Prestasi'),m=headerMap(sh),rows=sh.getDataRange().getValues();
    for(var i=1;i<rows.length;i++) if(String(rows[i][m['ID_Prestasi']-1])===String(d.id)){
      var vals={'Nama_Santri':st.nama,'Tanggal':d.tanggal,'Jenis_Prestasi':normalizeText_(d.jenisPrestasi,100),'Uraian_Prestasi':normalizeText_(d.uraian,2000),'Tingkat_Penghargaan':normalizeText_(d.tingkatPenghargaan,100),'Tingkat_Juara':normalizeText_(d.tingkatJuara,100),'Tingkat_Lomba':normalizeText_(d.tingkatTempat,100),'Pembimbing':normalizeText_(d.pembimbing,150)};
      Object.keys(vals).forEach(function(h){if(m[h])sh.getRange(i+1,m[h]).setValue(vals[h]);});
      if(m['ID_Santri'])sh.getRange(i+1,m['ID_Santri']).setValue(st.id); if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(new Date()); if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(a.session.name);
      auditLog_(a.session,'UPDATE_PRESTASI',String(d.id),'Santri='+st.id); return {success:true,message:'Data Prestasi berhasil diperbarui.'};
    }
    return {success:false,message:'Data Prestasi tidak ditemukan.'};
  });}catch(e){return {success:false,message:e.toString()};}
}
function deletePrestasi(id,token){
  var a=requireCapability_(token,'prestasi.delete'); if(!a.ok)return a.response;
  try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Prestasi'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Prestasi']-1])===String(id)){var rowAccess=assertTransactionRowAccess_(a.session,rows[i],m);if(!rowAccess.ok)return {success:false,message:rowAccess.message};sh.deleteRow(i+1);auditLog_(a.session,'DELETE_PRESTASI',String(id),'');return {success:true,message:'Data Prestasi berhasil dihapus.'};}return {success:false,message:'Data Prestasi tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}


/* ===== BEGIN ProductionHardening.gs ===== */
/**
 * TAICIMASTER FM — Stage 11 Production Hardening FINAL v11.0
 * Production preflight, health checks, configuration validation and safe maintenance utilities.
 *
 * Prinsip:
 * - Tidak menghapus data bisnis.
 * - Semua operasi administrasi dibatasi server-side.
 * - Menggunakan LockService untuk operasi maintenance.
 * - Tidak menyimpan secret ke Spreadsheet.
 */
var PRODUCTION = {
  VERSION: '11.0',
  REQUIRED_SHEETS: [
    'Data_Santri','Data_Users','Trx_Prestasi','Trx_Pelanggaran',
    'Trx_Catatan_Wali','Trx_Perizinan','Trx_Kesehatan','Audit_Log',
    'Backup_Log','Notification_Queue','Notification_Log'
  ],
  REQUIRED_USER_HEADERS: ['ID_User','Nama','Email','Password','Role','Status','Akses_Kelas','ID_Santri_Wali'],
  REQUIRED_SANTRI_HEADERS: ['ID_Santri','Nama_Santri','Kelas','Wali_Kelas','Status','No_HP_Ortu'],
};

function getProductionStatus(token) {
  var auth = requireCapability_(token, 'settings.manage');
  if (!auth.ok) return auth.response;
  return buildProductionStatus_();
}

function runProductionPreflight(token) {
  var auth = requireCapability_(token, 'settings.manage');
  if (!auth.ok) return auth.response;
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return {success:false, code:'BUSY', message:'Pemeriksaan sistem sedang berjalan. Coba lagi.'};
  try {
    var result = buildProductionStatus_();
    auditLog_(auth.session, 'PRODUCTION_PREFLIGHT', 'SYSTEM', result.data.summary.status + ' | ' + result.data.summary.failed + ' gagal | ' + result.data.summary.warning + ' peringatan');
    return result;
  } finally { lock.releaseLock(); }
}

function cleanupExpiredSessions(token) {
  var auth = requireCapability_(token, 'settings.manage');
  if (!auth.ok) return auth.response;
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return {success:false, code:'BUSY', message:'Pembersihan session sedang berjalan.'};
  try {
    var props = PropertiesService.getScriptProperties();
    var all = props.getProperties();
    var removed = 0, now = Date.now();
    Object.keys(all).forEach(function(key) {
      if (key.indexOf(SECURITY.SESSION_PREFIX) !== 0) return;
      try {
        var s = JSON.parse(all[key]);
        var expiresAt = s && s.expiresAt != null && s.expiresAt !== '' ? Number(s.expiresAt) : NaN;
        if (!isFinite(expiresAt) || expiresAt <= now) { props.deleteProperty(key); removed++; }
      } catch (e) { props.deleteProperty(key); removed++; }
    });
    auditLog_(auth.session, 'CLEANUP_EXPIRED_SESSIONS', 'SECURITY', 'Removed=' + removed);
    return {success:true, removed:removed, message:removed + ' session kedaluwarsa dibersihkan.'};
  } finally { lock.releaseLock(); }
}

function setProductionMaintenanceMode(enabled, token) {
  var auth = requireCapability_(token, 'settings.manage');
  if (!auth.ok) return auth.response;
  var value = !!enabled;
  var config = getSystemConfig();
  config.maintenanceMode = value;
  PropertiesService.getScriptProperties().setProperty('GLOBAL_SYSTEM_CONFIG', JSON.stringify(config));
  auditLog_(auth.session, 'UPDATE_MAINTENANCE_MODE', 'SYSTEM', String(value));
  return {success:true, maintenanceMode:value, message:value ? 'Mode maintenance aktif.' : 'Mode maintenance dinonaktifkan.'};
}

function getGoLiveChecklist(token) {
  var auth = requireCapability_(token, 'settings.manage');
  if (!auth.ok) return auth.response;
  var status = buildProductionStatus_();
  var checks = status.data.checks.map(function(c){ return {id:c.id, title:c.title, status:c.status, detail:c.detail, critical:!!c.critical}; });
  return {success:true, version:PRODUCTION.VERSION, checks:checks, ready:status.data.summary.failed===0 && status.data.summary.criticalFailed===0};
}

function buildProductionStatus_() {
  var checks = [];
  function add(id,title,status,detail,critical){ checks.push({id:id,title:title,status:status,detail:detail||'',critical:!!critical}); }
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  add('SPREADSHEET','Spreadsheet aktif','PASS',ss ? ss.getName() : 'Tidak ditemukan',true);

  var sheetMap = {};
  if (ss) ss.getSheets().forEach(function(s){sheetMap[s.getName()]=s;});
  PRODUCTION.REQUIRED_SHEETS.forEach(function(name){
    add('SHEET_'+name,'Sheet '+name,sheetMap[name]?'PASS':'FAIL',sheetMap[name]?'Tersedia':'Tidak ditemukan',true);
  });

  var user = sheetMap['Data_Users'];
  var santri = sheetMap['Data_Santri'];
  if (user) {
    var um = headerMap(user);
    var missingU = PRODUCTION.REQUIRED_USER_HEADERS.filter(function(h){return !um[h];});
    add('USER_HEADERS','Header Data_Users',missingU.length?'FAIL':'PASS',missingU.length?'Kurang: '+missingU.join(', '):'Lengkap',true);
    var rows = user.getLastRow()>1 ? user.getLastRow()-1 : 0;
    add('USER_DATA','Akun pengguna',rows>0?'PASS':'WARN',rows>0?rows+' akun':'Belum ada akun',true);
    var activeSuper = 0;
    if (rows>0) user.getRange(2,1,rows,user.getLastColumn()).getValues().forEach(function(r){if(String(r[4]).toLowerCase()==='superadmin' && String(r[5]).toLowerCase()==='aktif')activeSuper++;});
    add('SUPERADMIN','Superadmin aktif',activeSuper>0?'PASS':'FAIL',activeSuper>0?activeSuper+' akun superadmin aktif':'Tidak ada superadmin aktif',true);
  }
  if (santri) {
    var sm = headerMap(santri);
    var missingS = PRODUCTION.REQUIRED_SANTRI_HEADERS.filter(function(h){return !sm[h];});
    add('SANTRI_HEADERS','Header Data_Santri',missingS.length?'FAIL':'PASS',missingS.length?'Kurang: '+missingS.join(', '):'Lengkap',true);
    add('SANTRI_DATA','Data santri',santri.getLastRow()>1?'PASS':'WARN',Math.max(0,santri.getLastRow()-1)+' baris data',false);
  }

  var props = PropertiesService.getScriptProperties();
  var roleVersion = props.getProperty('ROLE_PERMISSION_VERSION');
  add('ROLE_VERSION','Role permission contract',roleVersion?'PASS':'WARN',roleVersion||'Belum tersimpan; jalankan getSystemConfig()',true);
  var configRaw = props.getProperty('GLOBAL_SYSTEM_CONFIG');
  var configOk = false;
  try { var cfg = JSON.parse(configRaw||''); configOk = !!cfg && typeof cfg==='object' && !!cfg.features; } catch(e) {}
  add('GLOBAL_CONFIG','Global configuration',configOk?'PASS':'FAIL',configOk?'Valid':'Konfigurasi tidak valid',true);

  var waEnabled = props.getProperty(WA8.PREFIX+'ENABLED') === 'true';
  if (waEnabled) {
    var endpoint = props.getProperty(WA8.PREFIX+'ENDPOINT')||'';
    var provider = props.getProperty(WA8.PREFIX+'PROVIDER')||'';
    var secret = props.getProperty(WA8.PREFIX+'TOKEN')||'';
    add('WA_CONFIG','WhatsApp configuration',(endpoint && provider && secret)?'PASS':'WARN',(endpoint && provider && secret)?'Gateway configured':'Gateway belum lengkap',false);
  } else add('WA_CONFIG','WhatsApp configuration','PASS','Notifikasi WhatsApp nonaktif',false);

  var backupFolder = props.getProperty(STAGE7_BACKUP_FOLDER_PROPERTY) || '';
  if (typeof ensureBackupDatabase_ === 'function') { try { ensureBackupDatabase_(); } catch(e) {} }
  add('BACKUP_CONFIG','Backup configuration',backupFolder?'PASS':'WARN',backupFolder?'Backup folder terkonfigurasi':'Backup folder belum terdeteksi; cek Pengaturan Backup',false);

  var maintenance = false;
  try { maintenance = !!JSON.parse(configRaw||'{}').maintenanceMode; } catch(e) {}
  add('MAINTENANCE','Maintenance mode',maintenance?'WARN':'PASS',maintenance?'Mode maintenance sedang aktif':'Sistem mode normal',false);

  var failed = checks.filter(function(c){return c.status==='FAIL';}).length;
  var warning = checks.filter(function(c){return c.status==='WARN';}).length;
  var criticalFailed = checks.filter(function(c){return c.status==='FAIL' && c.critical;}).length;
  var status = failed===0 ? (warning===0?'READY':'READY_WITH_WARNINGS') : 'NOT_READY';
  return {success:true,version:PRODUCTION.VERSION,data:{checks:checks,summary:{status:status,total:checks.length,failed:failed,warning:warning,criticalFailed:criticalFailed}}};
}


/* ===== BEGIN Rekap.gs ===== */
/**\n * TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0\n * Rekap
 */

function getRekapClassList(role, aksesKelas, token) {
  var auth=requireCapability_(token,'rekap.view'); if(!auth.ok)return auth.response;
  var session=auth.session;
  try {
    var ss=SpreadsheetApp.getActiveSpreadsheet(), sh=ss.getSheetByName('Data_Santri');
    if(!sh || sh.getLastRow()<=1)return {success:true,data:[]};
    var rows=sh.getDataRange().getValues(), m=headerMap(sh), idxK=m['Kelas']-1;
    if(idxK<0)return {success:false,message:'Kolom Kelas pada Data_Santri tidak ditemukan.'};
    var map={};
    for(var i=1;i<rows.length;i++){
      var k=String(rows[i][idxK]||'').trim(); if(!k)continue;
      if(session.role==='walikelas' && session.aksesKelas!=='All' && k.toLowerCase()!==String(session.aksesKelas||'').trim().toLowerCase())continue;
      map[k]=true;
    }
    return {success:true,data:Object.keys(map).sort()};
  }catch(e){return {success:false,message:'Gagal memuat daftar kelas rekap: '+e.toString()};}
}

function getRekapPerAnak(role, aksesKelas, kelasFilter, token) {
  var auth=requireCapability_(token,'rekap.view'); if(!auth.ok)return auth.response;
  var session=auth.session;
  try{
    var ss=SpreadsheetApp.getActiveSpreadsheet(), sh=ss.getSheetByName('Data_Santri');
    if(!sh)return {success:false,message:'Sheet Data_Santri tidak ditemukan.'};
    var rows=sh.getDataRange().getValues(), sm=headerMap(sh), ni=(sm['Nama_Santri']||0)-1, ki=(sm['Kelas']||0)-1;
    if(ni<0||ki<0)return {success:false,message:'Kolom Nama_Santri/Kelas pada Data_Santri tidak ditemukan.'};
    var wanted=String(kelasFilter||'ALL').trim().toLowerCase(), siswa=[];
    for(var i=1;i<rows.length;i++){
      var nama=String(rows[i][ni]||'').trim(), kelas=String(rows[i][ki]||'').trim(); if(!nama)continue;
      if(session.role==='walikelas'&&session.aksesKelas!=='All'&&kelas.toLowerCase()!==String(session.aksesKelas||'').trim().toLowerCase())continue;
      if(wanted!=='all'&&kelas.toLowerCase()!==wanted)continue;
      siswa.push({nama:nama,kelas:kelas,prestasi:[],pelanggaran:[],catatanWali:[],perizinan:[],kesehatan:[]});
    }
    var byName={};siswa.forEach(function(x){byName[x.nama.toLowerCase()]=x;});
    function readSheet(name,fields,cb){
      var sh=ss.getSheetByName(name);if(!sh||sh.getLastRow()<=1)return;
      var data=sh.getDataRange().getValues(),m=headerMap(sh), nameIdx=(m['Nama_Santri']||0)-1;if(nameIdx<0)return;
      for(var j=1;j<data.length;j++){var key=String(data[j][nameIdx]||'').trim().toLowerCase(),x=byName[key];if(x)cb(data[j],m,x);}
    }
    readSheet('Trx_Prestasi',null,function(r,m,x){var st=m['Status_Approval']?String(r[m['Status_Approval']-1]||''):'';if(st==='Approved'||st==='Disetujui')x.prestasi.push({tanggal:formatDateSafe(m['Tanggal']?r[m['Tanggal']-1]:''),judul:(m['Jenis_Prestasi']?r[m['Jenis_Prestasi']-1]:'')||(m['Uraian_Prestasi']?r[m['Uraian_Prestasi']-1]:''),detail:m['Uraian_Prestasi']?r[m['Uraian_Prestasi']-1]:'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    readSheet('Trx_Pelanggaran',null,function(r,m,x){x.pelanggaran.push({tanggal:formatDateSafe(m['Tanggal']?r[m['Tanggal']-1]:''),judul:(m['Jenis_Pelanggaran']?r[m['Jenis_Pelanggaran']-1]:'')+' - Tingkat '+(m['Tingkat_Pelanggaran']?r[m['Tingkat_Pelanggaran']-1]:''),detail:m['Deskripsi']?r[m['Deskripsi']-1]:(m['Kronologi']?r[m['Kronologi']-1]:''),tindakLanjut:m['Tindak_Lanjut']?r[m['Tindak_Lanjut']-1]:'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    readSheet('Trx_Catatan_Wali',null,function(r,m,x){x.catatanWali.push({tanggal:formatDateSafe(m['Tanggal']?r[m['Tanggal']-1]:''),kategori:m['Kategori']?r[m['Kategori']-1]:'',detail:m['Catatan']?r[m['Catatan']-1]:'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    readSheet('Trx_Perizinan',null,function(r,m,x){x.perizinan.push({tanggal:formatDateSafe(m['Mulai']?r[m['Mulai']-1]:''),judul:m['Jenis']?r[m['Jenis']-1]:'',detail:(m['Alasan']?r[m['Alasan']-1]:'')+' · '+(m['Tujuan']?r[m['Tujuan']-1]:''),status:m['Status']?r[m['Status']-1]:'',tindakLanjut:m['Selesai']?formatDateSafe(r[m['Selesai']-1]):'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    readSheet('Trx_Kesehatan',null,function(r,m,x){x.kesehatan.push({tanggal:formatDateSafe(m['Tanggal']?r[m['Tanggal']-1]:''),judul:m['Diagnosa']?r[m['Diagnosa']-1]:'Pemeriksaan Kesehatan',detail:(m['Keluhan']?r[m['Keluhan']-1]:'')+' · '+(m['Obat']?r[m['Obat']-1]:''),status:m['Status']?r[m['Status']-1]:'',tindakLanjut:m['Tindak_Lanjut']?r[m['Tindak_Lanjut']-1]:'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    var totals={totalSantri:siswa.length,totalPrestasi:0,totalPelanggaran:0,totalCatatanWali:0,totalPerizinan:0,totalKesehatan:0};siswa.forEach(function(x){totals.totalPrestasi+=x.prestasi.length;totals.totalPelanggaran+=x.pelanggaran.length;totals.totalCatatanWali+=x.catatanWali.length;totals.totalPerizinan+=x.perizinan.length;totals.totalKesehatan+=x.kesehatan.length;});
    siswa.sort(function(a,b){return a.nama.localeCompare(b.nama);});return {success:true,data:siswa,totals:totals};
  }catch(e){return {success:false,message:'Gagal memuat rekap per anak: '+e.toString()};}
}

function getRekapPerKelas(role, aksesKelas, token) {
  var auth=requireCapability_(token,'rekap.view'); if(!auth.ok)return auth.response;
  var session=auth.session;
  try{
    var ss=SpreadsheetApp.getActiveSpreadsheet(), sh=ss.getSheetByName('Data_Santri');if(!sh)return {success:false,message:'Sheet Data_Santri tidak ditemukan.'};
    var rows=sh.getDataRange().getValues(), sm=headerMap(sh), ni=(sm['Nama_Santri']||0)-1,ki=(sm['Kelas']||0)-1;if(ni<0||ki<0)return {success:false,message:'Kolom Nama_Santri/Kelas pada Data_Santri tidak ditemukan.'};
    var classes={},nameToClass={};
    for(var i=1;i<rows.length;i++){var nama=String(rows[i][ni]||'').trim(),kelas=String(rows[i][ki]||'').trim();if(!kelas)continue;if(session.role==='walikelas'&&session.aksesKelas!=='All'&&kelas.toLowerCase()!==String(session.aksesKelas||'').trim().toLowerCase())continue;if(!classes[kelas])classes[kelas]={kelas:kelas,santri:0,prestasi:[],pelanggaran:[],catatanWali:[],perizinan:[],kesehatan:[]};classes[kelas].santri++;if(nama)nameToClass[nama.toLowerCase()]=kelas;}
    function read(name,cb){var sh=ss.getSheetByName(name);if(!sh||sh.getLastRow()<=1)return;var data=sh.getDataRange().getValues(),m=headerMap(sh),ni2=(m['Nama_Santri']||0)-1;if(ni2<0)return;for(var j=1;j<data.length;j++){var k=nameToClass[String(data[j][ni2]||'').trim().toLowerCase()];if(k&&classes[k])cb(data[j],m,classes[k]);}}
    read('Trx_Prestasi',function(r,m,c){var st=m['Status_Approval']?String(r[m['Status_Approval']-1]||''):'';if(st==='Approved'||st==='Disetujui')c.prestasi.push({santriNama:m['Nama_Santri']?r[m['Nama_Santri']-1]:'',tanggal:formatDateSafe(m['Tanggal']?r[m['Tanggal']-1]:''),judul:(m['Jenis_Prestasi']?r[m['Jenis_Prestasi']-1]:'')||(m['Uraian_Prestasi']?r[m['Uraian_Prestasi']-1]:''),detail:m['Uraian_Prestasi']?r[m['Uraian_Prestasi']-1]:'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    read('Trx_Pelanggaran',function(r,m,c){c.pelanggaran.push({santriNama:m['Nama_Santri']?r[m['Nama_Santri']-1]:'',tanggal:formatDateSafe(m['Tanggal']?r[m['Tanggal']-1]:''),judul:(m['Jenis_Pelanggaran']?r[m['Jenis_Pelanggaran']-1]:'')+' - Tingkat '+(m['Tingkat_Pelanggaran']?r[m['Tingkat_Pelanggaran']-1]:''),detail:m['Deskripsi']?r[m['Deskripsi']-1]:'',tindakLanjut:m['Tindak_Lanjut']?r[m['Tindak_Lanjut']-1]:'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    read('Trx_Catatan_Wali',function(r,m,c){c.catatanWali.push({santriNama:m['Nama_Santri']?r[m['Nama_Santri']-1]:'',tanggal:formatDateSafe(m['Tanggal']?r[m['Tanggal']-1]:''),kategori:m['Kategori']?r[m['Kategori']-1]:'',detail:m['Catatan']?r[m['Catatan']-1]:'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    read('Trx_Perizinan',function(r,m,c){c.perizinan.push({santriNama:m['Nama_Santri']?r[m['Nama_Santri']-1]:'',tanggal:formatDateSafe(m['Mulai']?r[m['Mulai']-1]:''),judul:m['Jenis']?r[m['Jenis']-1]:'',detail:(m['Alasan']?r[m['Alasan']-1]:'')+' · '+(m['Tujuan']?r[m['Tujuan']-1]:''),status:m['Status']?r[m['Status']-1]:'',tindakLanjut:m['Selesai']?formatDateSafe(r[m['Selesai']-1]):'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    read('Trx_Kesehatan',function(r,m,c){c.kesehatan.push({santriNama:m['Nama_Santri']?r[m['Nama_Santri']-1]:'',tanggal:formatDateSafe(m['Tanggal']?r[m['Tanggal']-1]:''),judul:m['Diagnosa']?r[m['Diagnosa']-1]:'Pemeriksaan Kesehatan',detail:(m['Keluhan']?r[m['Keluhan']-1]:'')+' · '+(m['Obat']?r[m['Obat']-1]:''),status:m['Status']?r[m['Status']-1]:'',tindakLanjut:m['Tindak_Lanjut']?r[m['Tindak_Lanjut']-1]:'',createdBy:m['Created_By']?r[m['Created_By']-1]:''});});
    var data=Object.keys(classes).map(function(k){return classes[k];}).sort(function(a,b){return a.kelas.localeCompare(b.kelas);}),totals={totalSantri:0,totalPrestasi:0,totalPelanggaran:0,totalCatatanWali:0,totalPerizinan:0,totalKesehatan:0};data.forEach(function(x){totals.totalSantri+=x.santri;totals.totalPrestasi+=x.prestasi.length;totals.totalPelanggaran+=x.pelanggaran.length;totals.totalCatatanWali+=x.catatanWali.length;totals.totalPerizinan+=x.perizinan.length;totals.totalKesehatan+=x.kesehatan.length;});return {success:true,data:data,totals:totals};
  }catch(e){return {success:false,message:'Gagal memuat rekap per kelas: '+e.toString()};}
}


/* ===== BEGIN Reporting.gs ===== */
/**
 * TAICIMASTER FM — Stage 5 Dashboard, Rekapan & Reporting FINAL v5.0
 * Analytics, reporting summaries and CSV export payloads.
 */

function getDashboardAnalytics(token, monthsBack) {
  var auth = requireCapability_(token, 'dashboard.view'); if (!auth.ok) return auth.response;
  var s = auth.session;
  monthsBack = Math.max(3, Math.min(12, Number(monthsBack || 6)));
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var now = new Date();
    var tz = Session.getScriptTimeZone();
    var months = [];
    for (var i = monthsBack - 1; i >= 0; i--) {
      var d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      months.push({key: Utilities.formatDate(d, tz, 'yyyy-MM'), label: Utilities.formatDate(d, tz, 'MMM yyyy'), prestasi:0, pelanggaran:0, catatan:0, perizinan:0, kesehatan:0});
    }
    var idx = {}; months.forEach(function(m){ idx[m.key] = m; });
    var classMap = getVisibleStudentClassMap_(s);

    function add(sheetName, dateCol, nameCol, type, approvedCol) {
      var sh=ss.getSheetByName(sheetName); if(!sh || sh.getLastRow()<=1) return;
      var vals=sh.getDataRange().getValues();
      for(var r=1;r<vals.length;r++){
        var name=String(vals[r][nameCol]||'').trim().toLowerCase();
        if(!classMap[name]) continue;
        if(approvedCol !== null && approvedCol !== undefined && String(vals[r][approvedCol]||'') !== 'Approved') continue;
        var dt=vals[r][dateCol]; if(!dt) continue;
        var date=new Date(dt); if(isNaN(date.getTime())) continue;
        var key=Utilities.formatDate(date,tz,'yyyy-MM');
        if(idx[key]) idx[key][type]++;
      }
    }

    add('Trx_Prestasi',2,1,'prestasi',10);
    add('Trx_Pelanggaran',2,1,'pelanggaran',null);
    add('Trx_Catatan_Wali',3,1,'catatan',null);
    add('Trx_Perizinan',4,1,'perizinan',null);
    add('Trx_Kesehatan',3,1,'kesehatan',null);

    var trend=months.map(function(m){
      return {
        label:m.label,
        prestasi:m.prestasi,
        pelanggaran:m.pelanggaran,
        catatan:m.catatan,
        perizinan:m.perizinan,
        kesehatan:m.kesehatan,
        total:m.prestasi+m.pelanggaran+m.catatan+m.perizinan+m.kesehatan
      };
    });
    return {success:true,data:{trend:trend,generatedAt:Utilities.formatDate(new Date(),tz,'dd/MM/yyyy HH:mm:ss')}};
  } catch(e){ return {success:false,message:e.toString()}; }
}

function getVisibleStudentClassMap_(session) {
  var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri');
  var map={}; if(!sh || sh.getLastRow()<=1) return map;
  var rows=sh.getDataRange().getValues();
  for(var i=1;i<rows.length;i++){
    var name=String(rows[i][2]||'').trim(), kelas=String(rows[i][3]||'').trim();
    if(!name) continue;
    if(session.role==='walikelas' && session.aksesKelas!=='All' && String(session.aksesKelas||'').trim() && kelas.toLowerCase()!==String(session.aksesKelas).trim().toLowerCase()) continue;
    map[name.toLowerCase()]=kelas;
  }
  return map;
}

function getReportingSummary(token, kelasFilter) {
  var auth=requireCapability_(token,'rekap.view'); if(!auth.ok) return auth.response;
  try {
    var r=getRekapPerAnak('', '', kelasFilter || 'ALL', token); if(!r.success) return r;
    var data=r.data||[];
    var summary={totalSantri:data.length,totalPrestasi:0,totalPelanggaran:0,totalCatatanWali:0,totalPerizinan:0,totalKesehatan:0,aktifitasPerSantri:0};
    data.forEach(function(x){summary.totalPrestasi+=x.prestasi.length;summary.totalPelanggaran+=x.pelanggaran.length;summary.totalCatatanWali+=x.catatanWali.length;summary.totalPerizinan+=x.perizinan.length;summary.totalKesehatan+=x.kesehatan.length;});
    summary.aktifitasPerSantri=summary.totalSantri?Math.round(((summary.totalPrestasi+summary.totalPelanggaran+summary.totalCatatanWali+summary.totalPerizinan+summary.totalKesehatan)/summary.totalSantri)*100)/100:0;
    return {success:true,summary:summary};
  } catch(e){return {success:false,message:e.toString()};}
}

function exportRekapCsv(token, mode, kelasFilter) {
  var auth=requireCapability_(token,'rekap.view'); if(!auth.ok) return auth.response;
  try {
    var modeU=String(mode||'ANAK').toUpperCase(), result;
    if(modeU==='KELAS') result=getRekapPerKelas('', '', token); else result=getRekapPerAnak('', '', kelasFilter||'ALL', token);
    if(!result.success) return result;
    var tz=Session.getScriptTimeZone() || 'Asia/Jakarta';
    var stamp=Utilities.formatDate(new Date(),tz,'dd/MM/yyyy HH:mm:ss');
    var lines=[];
    lines.push(['TAICIMASTER FM','REKAPAN '+modeU].map(csvCell_).join(','));
    lines.push(['Dicetak',stamp].map(csvCell_).join(','));
    lines.push(['Filter Kelas', (kelasFilter && String(kelasFilter).toUpperCase() !== 'ALL') ? kelasFilter : 'Semua Kelas'].map(csvCell_).join(','));
    lines.push(['Catatan','File CSV ini menggunakan UTF-8 dan dapat dibuka langsung di Microsoft Excel/Google Sheets.'].map(csvCell_).join(','));
    lines.push([]);
    if(modeU==='KELAS') {
      lines.push(['No','Kelas','Jumlah Santri','Prestasi','Disiplin','Catatan Wali','Perizinan','Kesehatan'].map(csvCell_).join(','));
      (result.data||[]).forEach(function(x,i){lines.push([i+1,x.kelas,x.santri,(x.prestasi||[]).length,(x.pelanggaran||[]).length,(x.catatanWali||[]).length,(x.perizinan||[]).length,(x.kesehatan||[]).length].map(csvCell_).join(','));});
    } else {
      lines.push(['No','Nama Santri','Kelas','Prestasi','Disiplin','Catatan Wali','Perizinan','Kesehatan'].map(csvCell_).join(','));
      (result.data||[]).forEach(function(x,i){lines.push([i+1,x.nama,x.kelas,(x.prestasi||[]).length,(x.pelanggaran||[]).length,(x.catatanWali||[]).length,(x.perizinan||[]).length,(x.kesehatan||[]).length].map(csvCell_).join(','));});
    }
    var totalRows = result.data || [];
    if (modeU === 'KELAS') {
      var totalSantri = 0, totalPrestasi = 0, totalDisiplin = 0, totalCatatan = 0, totalIzin = 0, totalKesehatan = 0;
      totalRows.forEach(function(x){
        totalSantri += Number(x.santri || 0);
        totalPrestasi += (x.prestasi || []).length;
        totalDisiplin += (x.pelanggaran || []).length;
        totalCatatan += (x.catatanWali || []).length;
        totalIzin += (x.perizinan || []).length;
        totalKesehatan += (x.kesehatan || []).length;
      });
      lines.push([]);
      lines.push(['TOTAL','',totalSantri,totalPrestasi,totalDisiplin,totalCatatan,totalIzin,totalKesehatan].map(csvCell_).join(','));
    } else {
      var totalPrestasiA = 0, totalDisiplinA = 0, totalCatatanA = 0, totalIzinA = 0, totalKesehatanA = 0;
      totalRows.forEach(function(x){
        totalPrestasiA += (x.prestasi || []).length;
        totalDisiplinA += (x.pelanggaran || []).length;
        totalCatatanA += (x.catatanWali || []).length;
        totalIzinA += (x.perizinan || []).length;
        totalKesehatanA += (x.kesehatan || []).length;
      });
      lines.push([]);
      lines.push(['TOTAL','',totalPrestasiA,totalDisiplinA,totalCatatanA,totalIzinA,totalKesehatanA].map(csvCell_).join(','));
    }
    return {success:true,filename:'TAICIMASTER_Rekap_'+modeU+'_'+Utilities.formatDate(new Date(),tz,'yyyyMMdd_HHmmss')+'.csv',csv:'\ufeff'+lines.join('\r\n')};
  } catch(e){return {success:false,message:e.toString()};}
}
function csvCell_(v){var s=String(v==null?'':v); if(/^[=+\-@]/.test(s)) s="'"+s; return '"'+s.replace(/"/g,'""')+'"';}


/* ===== BEGIN RolePermission.gs ===== */
/**
 * TAICIMASTER FM — Stage 4 Core Modules & Role Permission FINAL v4.0
 * Central server-side authorization contract.
 * Frontend visibility is convenience only; this file is authoritative.
 */
var ROLE_PERMISSION_VERSION = '4.1';

var ROLE_PERMISSIONS = {
  superadmin: {
    label: 'Superadmin',
    capabilities: ['*'],
    scope: 'ALL'
  },
  wali_santri: {
    label: 'Wali Santri',
    capabilities: ['portal_wali.view'],
    scope: 'OWN_CHILDREN'
  },
  supervisor: {
    label: 'Supervisor',
    capabilities: ['dashboard.view','santri.view','prestasi.view','pelanggaran.view','perizinan.view','kesehatan.view','biodata.view','catatan_wali.view','rekap.view'],
    scope: 'ALL'
  },
  walikelas: {
    label: 'Wali Kelas',
    capabilities: ['dashboard.view','santri.view','prestasi.view','prestasi.create','pelanggaran.view','pelanggaran.create','catatan_wali.view','catatan_wali.create','catatan_wali.edit','catatan_wali.delete','perizinan.view','kesehatan.view','biodata.view','biodata.edit','rekap.view'],
    scope: 'CLASS'
  },
  admin_prestasi: {
    label: 'Admin Prestasi',
    capabilities: ['dashboard.view','santri.view','prestasi.view','prestasi.create','prestasi.edit','prestasi.delete','prestasi.approve','pelanggaran.view','perizinan.view','kesehatan.view','biodata.view','rekap.view','notification.send'],
    scope: 'ALL'
  },
  admin_pelanggaran: {
    label: 'Admin Pelanggaran',
    capabilities: ['dashboard.view','santri.view','pelanggaran.view','pelanggaran.create','pelanggaran.edit','pelanggaran.delete','prestasi.view','perizinan.view','perizinan.create','perizinan.edit','perizinan.delete','perizinan.approve','kesehatan.view','biodata.view','rekap.view','notification.send'],
    scope: 'ALL'
  },
  admin_perizinan: {
    label: 'Admin Perizinan',
    capabilities: ['dashboard.view','santri.view','pelanggaran.view','pelanggaran.create','pelanggaran.edit','pelanggaran.delete','prestasi.view','perizinan.view','perizinan.create','perizinan.edit','perizinan.delete','perizinan.approve','kesehatan.view','biodata.view','rekap.view'],
    scope: 'ALL'
  },
  admin_kesehatan: {
    label: 'Admin Kesehatan',
    capabilities: ['dashboard.view','santri.view','pelanggaran.view','prestasi.view','perizinan.view','kesehatan.view','kesehatan.create','kesehatan.edit','kesehatan.delete','biodata.view','rekap.view'],
    scope: 'ALL'
  }
};

function normalizeRole_(role) {
  var r = String(role || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  return ROLE_PERMISSIONS[r] ? r : '';
}

function hasCapability_(role, capability) {
  var r = normalizeRole_(role);
  if (!r) return false;
  var p = ROLE_PERMISSIONS[r];
  return p.capabilities.indexOf('*') >= 0 || p.capabilities.indexOf(String(capability)) >= 0;
}

function requireCapability_(token, capability) {
  var auth = requireSessionResult_(token);
  if (!auth.ok) return auth;
  if (!hasCapability_(auth.session.role, capability)) {
    return {ok:false, response:{success:false, code:'FORBIDDEN', message:'Akses ditolak. Role Anda tidak memiliki izin untuk operasi ini.'}};
  }
  return auth;
}

function requireAnyCapability_(token, capabilities) {
  var auth = requireSessionResult_(token);
  if (!auth.ok) return auth;
  var allowed = (capabilities || []).some(function(c){ return hasCapability_(auth.session.role, c); });
  if (!allowed) return {ok:false, response:{success:false, code:'FORBIDDEN', message:'Akses ditolak untuk role Anda.'}};
  return auth;
}

function assertRoleScope_(session, santri) {
  if (!session) return {ok:false,message:'Sesi tidak valid.'};
  var role = normalizeRole_(session.role);
  if (!ROLE_PERMISSIONS[role]) return {ok:false,message:'Role tidak dikenali.'};
  if (ROLE_PERMISSIONS[role].scope === 'ALL') return {ok:true};
  return assertSantriAccess_(session, santri);
}

function getRolePermissionMatrix(token) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  var matrix = {};
  Object.keys(ROLE_PERMISSIONS).forEach(function(role){
    matrix[role] = {
      label: ROLE_PERMISSIONS[role].label,
      scope: ROLE_PERMISSIONS[role].scope,
      capabilities: ROLE_PERMISSIONS[role].capabilities.slice()
    };
  });
  return {success:true,version:ROLE_PERMISSION_VERSION,data:matrix};
}

function getMyPermissions(token) {
  var auth = requireSessionResult_(token);
  if (!auth.ok) return auth.response;
  var role = normalizeRole_(auth.session.role);
  if (!ROLE_PERMISSIONS[role]) return {success:false,code:'INVALID_ROLE',message:'Role pengguna tidak dikenali.'};
  return {success:true,version:ROLE_PERMISSION_VERSION,role:role,label:ROLE_PERMISSIONS[role].label,scope:ROLE_PERMISSIONS[role].scope,capabilities:ROLE_PERMISSIONS[role].capabilities.slice()};
}

function validateUserRole_(role) {
  return !!normalizeRole_(role);
}


/* ===== BEGIN Santri.gs ===== */
/** TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0 — Santri */
function getSantriList(role,aksesKelas,token){var a=requireCapability_(token,'santri.view');if(!a.ok)return a.response;var s=a.session;try{var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri');if(!sh)return {success:false,message:'Sheet Data_Santri tidak ditemukan.'};var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[];for(var i=1;i<d.length;i++){var k=normalizeText_(d[i][m['Kelas']-1]);if(s.role==='walikelas'&&s.aksesKelas!=='All'&&k.toLowerCase()!==normalizeText_(s.aksesKelas).toLowerCase())continue;o.push({id:d[i][m['ID_Santri']-1],nisn:d[i][m['NISN']-1],nama:d[i][m['Nama_Santri']-1],kelas:k,waliKelas:d[i][m['Wali_Kelas']-1]});}return {success:true,data:o};}catch(e){return {success:false,message:e.toString()};}}
function getStudentClass(nama,token){var a=requireCapability_(token,'santri.view');if(!a.ok)return '';var s=getSantriRecordByName_(nama);if(!s)return '';if(a.session.role==='walikelas'&&a.session.aksesKelas!=='All'&&String(s.kelas).toLowerCase()!==String(a.session.aksesKelas).toLowerCase())return '';return s.kelas||'';}


/* ===== BEGIN Security.gs ===== */
/**
 * TAICIMASTER FM — Stage 2 Security FINAL v2.0
 * Server-side authentication, sessions, authorization, rate limiting and audit.
 */
var SECURITY = {
  SESSION_TTL_SECONDS: 8 * 60 * 60,
  LOGIN_WINDOW_SECONDS: 15 * 60,
  MAX_LOGIN_ATTEMPTS: 5,
  SESSION_PREFIX: 'TAI_SESSION_',
  LOGIN_PREFIX: 'TAI_LOGIN_',
  REMEMBER_PREFIX: 'TAI_REMEMBER_',
  REMEMBER_ME_TTL_SECONDS: 30 * 24 * 60 * 60
};

function sha256Hex_(value) {
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(value), Utilities.Charset.UTF_8);
  return bytes.map(function(b){ var n=b<0?b+256:b; return ('0'+n.toString(16)).slice(-2); }).join('');
}

function makePasswordHash_(password) { return 'v1$sha256$' + sha256Hex_(password); }
function verifyPassword_(password, stored) {
  stored = String(stored || '');
  if (stored.indexOf('v1$sha256$') === 0) return makePasswordHash_(password) === stored;
  return String(password) === stored; // legacy migration path only
}

function createSession_(user) {
  var token = Utilities.getUuid().replace(/-/g,'') + Utilities.getUuid().replace(/-/g,'');
  var canonicalRole = (typeof normalizeRole_ === 'function' ? normalizeRole_(user.role) : String(user.role || '').trim().toLowerCase().replace(/[\s-]+/g,'_'));
  var payload = { id:String(user.id), name:String(user.name), email:String(user.email), role:canonicalRole, aksesKelas:String(user.aksesKelas || 'All'), waliSantriIds:String(user.waliSantriIds || ''), createdAt:Date.now(), expiresAt:Date.now()+SECURITY.SESSION_TTL_SECONDS*1000 };
  PropertiesService.getScriptProperties().setProperty(SECURITY.SESSION_PREFIX + token, JSON.stringify(payload));
  return token;
}


/**
 * Persistent "Remember Me" token.
 * The browser keeps only the raw random token. The server stores only its SHA-256 hash.
 * Token lifetime is fixed at 30 days and can be revoked independently of the 8-hour session.
 */
function createRememberToken_(user) {
  var raw = Utilities.getUuid().replace(/-/g,'') + Utilities.getUuid().replace(/-/g,'');
  var hash = sha256Hex_(raw);
  var now = Date.now();
  var payload = {
    id:String(user.id),
    createdAt:now,
    expiresAt:now + SECURITY.REMEMBER_ME_TTL_SECONDS * 1000,
    userAgent:''
  };
  PropertiesService.getScriptProperties().setProperty(
    SECURITY.REMEMBER_PREFIX + hash, JSON.stringify(payload)
  );
  return raw;
}

function restoreRememberedSession(rememberToken) {
  try {
    rememberToken = String(rememberToken || '').trim();
    if (rememberToken.length < 32) return {success:false,code:'REMEMBER_INVALID',message:'Token login tidak valid.'};

    var props = PropertiesService.getScriptProperties();
    var hash = sha256Hex_(rememberToken);
    var key = SECURITY.REMEMBER_PREFIX + hash;
    var raw = props.getProperty(key);
    if (!raw) return {success:false,code:'REMEMBER_INVALID',message:'Token login tidak ditemukan atau sudah dicabut.'};

    var saved;
    try { saved = JSON.parse(raw); } catch(e) {
      props.deleteProperty(key);
      return {success:false,code:'REMEMBER_INVALID',message:'Token login rusak.'};
    }

    if (!saved.expiresAt || Date.now() > Number(saved.expiresAt)) {
      props.deleteProperty(key);
      return {success:false,code:'REMEMBER_EXPIRED',message:'Token login sudah kedaluwarsa.'};
    }

    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Users');
    if (!sheet) return {success:false,code:'USER_DB_MISSING',message:'Sheet Data_Users tidak ditemukan.'};
    var data = sheet.getDataRange().getValues(), um = headerMap(sheet), found = null;

    for (var i=1;i<data.length;i++) {
      if (String(data[i][0]||'') === String(saved.id)) {
        found = {row:i+1, values:data[i]};
        break;
      }
    }
    if (!found) {
      props.deleteProperty(key);
      return {success:false,code:'REMEMBER_INVALID',message:'Akun tidak ditemukan.'};
    }

    var row = found.values;
    if (String(row[5]||'') !== 'Aktif') {
      props.deleteProperty(key);
      return {success:false,code:'ACCOUNT_INACTIVE',message:'Akun tidak aktif.'};
    }

    var canonicalRole = (typeof normalizeRole_ === 'function'
      ? normalizeRole_(row[4])
      : String(row[4]||'').trim().toLowerCase().replace(/[\s-]+/g,'_'));

    var user = {
      id:row[0],
      name:row[1],
      email:row[2],
      role:canonicalRole,
      aksesKelas:row[6]||'All',
      waliSantriIds:um['ID_Santri_Wali'] ? String(row[um['ID_Santri_Wali']-1]||'') : ''
    };

    // Rotate the persistent token after successful restoration.
    props.deleteProperty(key);
    var newRememberToken = createRememberToken_(user);
    var sessionToken = createSession_(user);
    auditLog_({id:user.id,name:user.name,role:user.role},'REMEMBER_LOGIN','SESSION','Persistent login 30 hari');

    var systemConfig=null;
    try { systemConfig=getSystemConfig(); } catch(configError) { Logger.log('Konfigurasi login pulih tidak dapat disertakan: '+String(configError)); }

    return {
      success:true,
      user:user,
      sessionToken:sessionToken,
      expiresIn:SECURITY.SESSION_TTL_SECONDS,
      rememberToken:newRememberToken,
      rememberExpiresIn:SECURITY.REMEMBER_ME_TTL_SECONDS,
      systemConfig:systemConfig
    };
  } catch(e) {
    return {success:false,code:'REMEMBER_ERROR',message:'Gagal memulihkan login: '+e.toString()};
  }
}


function revokeRememberTokensForUser_(userId) {
  try {
    var props = PropertiesService.getScriptProperties();
    var all = props.getProperties();
    Object.keys(all).forEach(function(key) {
      if (key.indexOf(SECURITY.REMEMBER_PREFIX) !== 0) return;
      try {
        var p = JSON.parse(all[key]);
        if (String(p.id) === String(userId)) props.deleteProperty(key);
      } catch(e) {}
    });
  } catch(e) { Logger.log('Revoke remember tokens failed: '+e); }
}

function revokeRememberToken(rememberToken) {
  try {
    rememberToken = String(rememberToken || '').trim();
    if (rememberToken) {
      PropertiesService.getScriptProperties().deleteProperty(
        SECURITY.REMEMBER_PREFIX + sha256Hex_(rememberToken)
      );
    }
    return {success:true};
  } catch(e) {
    return {success:false,message:e.toString()};
  }
}

function getSession_(token) {
  if (!token || typeof token !== 'string' || token.length < 32) return null;
  var props = PropertiesService.getScriptProperties();
  var raw = props.getProperty(SECURITY.SESSION_PREFIX + token);
  if (!raw) return null;
  try {
    var session = JSON.parse(raw);
    if (typeof normalizeRole_ === 'function') session.role = normalizeRole_(session.role) || session.role;
    else session.role = String(session.role || '').trim().toLowerCase().replace(/[\s-]+/g,'_');
    var expiresAt = session && session.expiresAt != null && session.expiresAt !== ''
      ? Number(session.expiresAt)
      : NaN;
    if (!isFinite(expiresAt) || Date.now() >= expiresAt) {
      props.deleteProperty(SECURITY.SESSION_PREFIX + token);
      return null;
    }
    // Sliding expiration, capped by activity.
    session.expiresAt = Date.now() + SECURITY.SESSION_TTL_SECONDS*1000;
    props.setProperty(SECURITY.SESSION_PREFIX + token, JSON.stringify(session));
    return session;
  } catch(e) { props.deleteProperty(SECURITY.SESSION_PREFIX + token); return null; }
}

function requireSession_(token, allowedRoles) {
  var session = getSession_(token);
  if (!session) throw new Error('Sesi tidak valid atau telah berakhir. Silakan login kembali.');
  if (allowedRoles && allowedRoles.length && allowedRoles.indexOf(session.role) < 0) throw new Error('Akses ditolak untuk role Anda.');
  return session;
}

function requireSessionResult_(token, allowedRoles) {
  try { return {ok:true, session:requireSession_(token, allowedRoles)}; }
  catch(e) { return {ok:false, response:{success:false, code:'AUTH_REQUIRED', message:e.message}}; }
}

function auditLog_(session, action, target, detail) {
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Audit_Log');
    if (!sheet) {
      sheet = ss.insertSheet('Audit_Log');
      sheet.appendRow(['ID_Audit','Timestamp','User_ID','User_Name','Role','Action','Target','Detail']);
      sheet.getRange(1,1,1,8).setFontWeight('bold').setBackground('#7E22CE').setFontColor('#FFFFFF');
    }
    sheet.appendRow(['AUD-'+Utilities.formatDate(new Date(),'GMT+7','yyyyMMddHHmmssSSS'),new Date(),session?session.id:'',session?session.name:'',session?session.role:'',action||'',target||'',detail||'']);
  } catch(e) { Logger.log('Audit log failed: '+e); }
}


/**
 * Stage 11.23 — Read-only Audit Trail for Superadmin.
 * Never exposes password/token/session secrets. Returns newest entries first.
 */
function getAuditLog(token, options) {
  var auth = requireSessionResult_(token, ['superadmin']);
  if (!auth.ok) return auth.response;
  options = options || {};
  var limit = Math.max(1, Math.min(Number(options.limit || 100), 250));
  var action = String(options.action || '').trim().toUpperCase();
  var search = String(options.search || '').trim().toLowerCase();
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Audit_Log');
  if (!sheet || sheet.getLastRow() < 2) return {success:true,data:[],total:0};
  var values = sheet.getDataRange().getValues();
  var out = [];
  for (var i = values.length - 1; i >= 1 && out.length < limit; i--) {
    var r = values[i];
    var item = {
      id: String(r[0] || ''),
      timestamp: r[1] instanceof Date ? Utilities.formatDate(r[1], Session.getScriptTimeZone() || 'Asia/Jakarta', 'dd/MM/yyyy HH:mm:ss') : String(r[1] || ''),
      userId: String(r[2] || ''),
      userName: String(r[3] || ''),
      role: String(r[4] || ''),
      action: String(r[5] || ''),
      target: String(r[6] || ''),
      detail: String(r[7] || '')
    };
    if (action && !(item.action.toUpperCase() === action || item.action.toUpperCase().indexOf(action + '_') === 0)) continue;
    if (search) {
      var hay = [item.id,item.userId,item.userName,item.role,item.action,item.target,item.detail].join(' ').toLowerCase();
      if (hay.indexOf(search) === -1) continue;
    }
    out.push(item);
  }
  return {success:true,data:out,total:out.length};
}

function loginGuard_(identity) {
  var key = SECURITY.LOGIN_PREFIX + sha256Hex_(String(identity||'').trim().toLowerCase());
  var props = PropertiesService.getScriptProperties();
  var raw = props.getProperty(key), now=Date.now();
  var state = raw ? JSON.parse(raw) : {count:0,firstAt:now};
  if (now - Number(state.firstAt) > SECURITY.LOGIN_WINDOW_SECONDS*1000) state={count:0,firstAt:now};
  if (Number(state.count) >= SECURITY.MAX_LOGIN_ATTEMPTS) return {blocked:true,key:key,remainingMs:SECURITY.LOGIN_WINDOW_SECONDS*1000-(now-Number(state.firstAt))};
  return {blocked:false,key:key,state:state};
}
function recordLoginFailure_(guard) { guard.state.count=Number(guard.state.count||0)+1; PropertiesService.getScriptProperties().setProperty(guard.key,JSON.stringify(guard.state)); }
function clearLoginGuard_(guard) { PropertiesService.getScriptProperties().deleteProperty(guard.key); }
function migrateLegacyPassword_(sheet,rowNumber,password) { sheet.getRange(rowNumber,4).setValue(makePasswordHash_(password)); }

function logoutUser(token) {
  var session = getSession_(token);
  if (session) auditLog_(session,'LOGOUT','SESSION','User logout');
  if (token) PropertiesService.getScriptProperties().deleteProperty(SECURITY.SESSION_PREFIX + token);
  return {success:true};
}

function getCurrentSession(token) {
  var r=requireSessionResult_(token);
  if (!r.ok) return r.response;
  return {success:true,user:{id:r.session.id,name:r.session.name,email:r.session.email,role:r.session.role,aksesKelas:r.session.aksesKelas}};
}

function initializeSecurityDatabase_() {
  var ss=SpreadsheetApp.getActiveSpreadsheet();
  var user=ss.getSheetByName('Data_Users');
  if (user) ['Password_Salt','Failed_Login_Count','Locked_Until','Last_Login_At'].forEach(function(h){ensureColumn(user,h);});
  var audit=ss.getSheetByName('Audit_Log');
  if (!audit) { audit=ss.insertSheet('Audit_Log'); audit.appendRow(['ID_Audit','Timestamp','User_ID','User_Name','Role','Action','Target','Detail']); audit.getRange(1,1,1,8).setFontWeight('bold').setBackground('#7E22CE').setFontColor('#FFFFFF'); }
  return {success:true,message:'Security database siap.'};
}


/* ===== BEGIN Users.gs ===== */
/** TAICIMASTER FM — Stage 2 Security FINAL v2.0 — User Management */
function getUserList(token) {
  try { var auth=requireCapability_(token,'user.manage'); if(!auth.ok)return auth.response;
    var sheet=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Users'),data=sheet.getDataRange().getValues(),users=[];
    for(var i=1;i<data.length;i++)users.push({id:data[i][0],nama:data[i][1],email:data[i][2],role:data[i][4],status:data[i][5],aksesKelas:data[i][6]});
    return {success:true,data:users};
  }catch(e){return {success:false,message:e.toString()};}
}
function addNewUser(userData,token) {
  try { var auth=requireCapability_(token,'user.manage'); if(!auth.ok)return auth.response;
    userData=userData||{}; if(!validateUserRole_(userData.role||'walikelas'))return {success:false,message:'Role pengguna tidak valid.'}; var email=String(userData.email||'').trim().toLowerCase(), pass=String(userData.password||'');
    if(!userData.nama||!email||pass.length<8)return {success:false,message:'Nama, email dan password minimal 8 karakter wajib diisi.'};
    if(!/[A-Za-z]/.test(pass)||!/[0-9]/.test(pass))return {success:false,message:'Password harus mengandung huruf dan angka.'};
    var sheet=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Users'),data=sheet.getDataRange().getValues();
    for(var i=1;i<data.length;i++)if(String(data[i][2]).toLowerCase()===email)return {success:false,message:'Email sudah terdaftar.'};
    var idUser=generateRecordId_('USR');
    withDataLock_(function(){ var m=headerMap(sheet), row=new Array(sheet.getLastColumn()).fill(''); var vals={'ID_User':idUser,'Nama':normalizeText_(userData.nama,150),'Email':email,'Password':makePasswordHash_(pass),'Role':userData.role||'walikelas','Status':'Aktif','Akses_Kelas':userData.aksesKelas||'All','Password_Salt':'','Failed_Login_Count':0,'Locked_Until':'','Last_Login_At':'','ID_Santri_Wali':String(userData.idSantriWali||'').trim(),'Updated_At':new Date(),'Updated_By':auth.session.name}; Object.keys(vals).forEach(function(h){if(m[h])row[m[h]-1]=vals[h];}); sheet.appendRow(row); });
    auditLog_(auth.session,'CREATE_USER','USER',email); return {success:true,message:'Pengguna baru berhasil ditambahkan!'};
  }catch(e){return {success:false,message:'Gagal menambahkan user: '+e.toString()};}
}


/* ===== BEGIN Utils.gs ===== */
/**\n * TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0\n * Utilities
 */

function formatDateSafe(v){if(!v)return '';try{return Utilities.formatDate(new Date(v),Session.getScriptTimeZone(),'dd/MM/yyyy');}catch(e){return String(v);}}



/* ===== BEGIN WaliKelas.gs ===== */
/** TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0 — Wali Kelas */
function simpanCatatanWaliKelas(data,token){var a=requireCapability_(token,'catatan_wali.create');if(!a.ok)return a.response;var d=data||{},req=requireFields_(d,['santriNama','tanggal','kategori','catatan']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama),ac=assertSantriAccess_(a.session,st);if(!ac.ok)return {success:false,message:ac.message};if(!normalizeDateInput_(d.tanggal))return {success:false,message:'Tanggal catatan tidak valid.'};if(!cacheDuplicateGuard_('CATATAN_WALI',a.session.id,{santri:st.id||st.nama,tanggal:d.tanggal,kategori:d.kategori,catatan:d.catatan}))return {success:false,code:'DUPLICATE_REQUEST',message:'Permintaan yang sama baru saja diproses. Hindari klik dua kali.'};try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Catatan_Wali');if(!sh){sh=SpreadsheetApp.getActiveSpreadsheet().insertSheet('Trx_Catatan_Wali');sh.appendRow(['ID_Catatan','Nama_Santri','Kelas','Tanggal','Kategori','Catatan','Created_By']);}ensureColumn(sh,'ID_Santri');ensureColumn(sh,'Created_At');ensureColumn(sh,'Updated_At');ensureColumn(sh,'Updated_By');var m=headerMap(sh),id=generateRecordId_('CWK'),now=new Date(),row=new Array(sh.getLastColumn()).fill(''),vals={'ID_Catatan':id,'Nama_Santri':st.nama,'Kelas':st.kelas,'Tanggal':d.tanggal,'Kategori':normalizeText_(d.kategori,100),'Catatan':normalizeText_(d.catatan,3000),'Created_By':a.session.name};Object.keys(vals).forEach(function(h){if(m[h])row[m[h]-1]=vals[h];});row[m['ID_Santri']-1]=st.id;row[m['Created_At']-1]=now;row[m['Updated_At']-1]=now;row[m['Updated_By']-1]=a.session.name;sh.appendRow(row);auditLog_(a.session,'CREATE_CATATAN_WALI',id,'Santri='+st.id);queueNewDataPush_('CATATAN_WALI',st,id,'Approved',a.session);return {success:true,idCatatan:id,message:'Catatan Wali Kelas Berhasil Disimpan!'};});}catch(e){return {success:false,message:'Gagal menyimpan catatan: '+e.toString()};}}
function getRiwayatCatatanWaliKelas(aksesKelas,token){var a=requireCapability_(token,'catatan_wali.view');if(!a.ok)return a.response;var s=a.session;try{var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Catatan_Wali');if(!sh)return {success:true,data:[]};var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[];for(var i=d.length-1;i>=1;i--){var k=String(d[i][m['Kelas']-1]||'');if(s.role==='walikelas'&&s.aksesKelas!=='All'&&k.toLowerCase()!==String(s.aksesKelas).toLowerCase())continue;o.push({idCatatan:d[i][m['ID_Catatan']-1],santriNama:d[i][m['Nama_Santri']-1],tanggal:d[i][m['Tanggal']-1]?Utilities.formatDate(new Date(d[i][m['Tanggal']-1]),Session.getScriptTimeZone(),'dd/MM/yyyy'):'',kategori:d[i][m['Kategori']-1],catatan:d[i][m['Catatan']-1],createdBy:d[i][m['Created_By']-1]});}return {success:true,data:o};}catch(e){return {success:false,message:e.toString()};}}

function getWaliKelasClassSummary(aksesKelas, token) {
  var a = requireCapability_(token, 'catatan_wali.view');
  if (!a.ok) return a.response;
  var kelas = String(aksesKelas || a.session.aksesKelas || '').trim();
  if (!kelas) return {success:false,message:'Akses kelas Wali Kelas belum ditentukan.'};
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sh = ss.getSheetByName('Data_Santri');
    if (!sh) return {success:true,data:{kelas:kelas,totalSantri:0,totalPrestasi:0,totalPelanggaran:0}};
    var d=sh.getDataRange().getValues(), m=headerMap(sh), total=0;
    for(var i=1;i<d.length;i++){
      var k=String(m['Kelas']?d[i][m['Kelas']-1]:'').trim();
      if(kelas==='All'||k.toLowerCase()===kelas.toLowerCase()) total++;
    }
    function countSheet(name){
      var x=ss.getSheetByName(name); if(!x)return 0;
      var xd=x.getDataRange().getValues(), xm=headerMap(x), c=0;
      for(var j=1;j<xd.length;j++){
        var k=xm['Kelas']?String(xd[j][xm['Kelas']-1]||'').trim():'';
        if(kelas==='All'||k.toLowerCase()===kelas.toLowerCase())c++;
      }
      return c;
    }
    return {success:true,data:{kelas:kelas,totalSantri:total,totalPrestasi:countSheet('Trx_Prestasi'),totalPelanggaran:countSheet('Trx_Pelanggaran')}};
  }catch(e){return {success:false,message:'Gagal memuat ringkasan Wali Kelas: '+e.toString()};}
}

function updateCatatanWaliKelas(data,token){
  var a=requireCapability_(token,'catatan_wali.edit');if(!a.ok)return a.response;var d=data||{},req=requireFields_(d,['idCatatan','santriNama','tanggal','kategori','catatan']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama);if(!st)return {success:false,message:'Santri tidak ditemukan.'};var ac=assertSantriAccess_(a.session,st);if(!ac.ok)return {success:false,message:ac.message};
  try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Catatan_Wali'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Catatan']-1])===String(d.idCatatan)){var vals={'Nama_Santri':st.nama,'Kelas':st.kelas,'Tanggal':d.tanggal,'Kategori':normalizeText_(d.kategori,100),'Catatan':normalizeText_(d.catatan,3000)};Object.keys(vals).forEach(function(h){if(m[h])sh.getRange(i+1,m[h]).setValue(vals[h]);});if(m['ID_Santri'])sh.getRange(i+1,m['ID_Santri']).setValue(st.id);if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(new Date());if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(a.session.name);auditLog_(a.session,'UPDATE_CATATAN_WALI',String(d.idCatatan),'Santri='+st.id);return {success:true,message:'Catatan Wali Kelas berhasil diperbarui.'};}return {success:false,message:'Catatan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}
function deleteCatatanWaliKelas(id,token){var a=requireCapability_(token,'catatan_wali.delete');if(!a.ok)return a.response;try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Catatan_Wali'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Catatan']-1])===String(id)){sh.deleteRow(i+1);auditLog_(a.session,'DELETE_CATATAN_WALI',String(id),'');return {success:true,message:'Catatan Wali Kelas berhasil dihapus.'};}return {success:false,message:'Catatan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}


/* ===== BEGIN WaliPortal.gs ===== */
/**
 * TAICIMASTER FM — Stage 9 FINAL v9.0
 * Portal Wali Santri — server-side, scoped strictly to linked children.
 */
var WALI_PORTAL_VERSION = '9.0';
var WALI_PORTAL_CAPABILITY = 'portal_wali.view';

function ensureWaliPortalDatabase_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  ensureColumn(ss.getSheetByName('Data_Users'), 'ID_Santri_Wali');
  ensureSheetHeaders(ss, 'Portal_Notification_Log', ['ID_Notification','Timestamp','User_ID','Santri_ID','Type','Title','Message','Read_At']);
  var props = PropertiesService.getScriptProperties();
  if (!props.getProperty('WALI_PORTAL_VERSION')) props.setProperty('WALI_PORTAL_VERSION', WALI_PORTAL_VERSION);
}

function getWaliLinkedSantriIds_(session) {
  if (!session || normalizeRole_(session.role) !== 'wali_santri') return [];
  var sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Users');
  if (!sh) return [];
  var m = headerMap(sh), d = sh.getDataRange().getValues();
  for (var i=1;i<d.length;i++) {
    if (String(d[i][m['ID_User']-1]||'') === String(session.id||'')) {
      var raw = m['ID_Santri_Wali'] ? String(d[i][m['ID_Santri_Wali']-1]||'') : '';
      return raw.split(/[,;\n]+/).map(function(x){return x.trim();}).filter(Boolean);
    }
  }
  return [];
}

function getWaliChildren_(session) {
  var ids = getWaliLinkedSantriIds_(session), byId = {}, byName = {};
  var sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri');
  if (!sh) return [];
  var m=headerMap(sh), d=sh.getDataRange().getValues();
  for(var i=1;i<d.length;i++){
    var id=String(m['ID_Santri']?d[i][m['ID_Santri']-1]:'').trim(), name=String(m['Nama_Santri']?d[i][m['Nama_Santri']-1]:'').trim();
    if(!id || !name) continue;
    var linked=ids.indexOf(id)>=0;
    if(linked){
      var c={id:id,nisn:m['NISN']?d[i][m['NISN']-1]:'',nama:name,kelas:m['Kelas']?d[i][m['Kelas']-1]:'',waliKelas:m['Wali_Kelas']?d[i][m['Wali_Kelas']-1]:'',status:m['Status']?d[i][m['Status']-1]:'',fotoUrl:m['Foto_URL']?d[i][m['Foto_URL']-1]:'',statusAsrama:m['Status_Asrama']?d[i][m['Status_Asrama']-1]:'',kamar:m['Kamar']?d[i][m['Kamar']-1]:''};
      byId[id]=c; byName[name.toLowerCase()]=c;
    }
  }
  return ids.map(function(id){return byId[id];}).filter(Boolean);
}

function assertWaliOwnsSantri_(session, santriId) {
  var ids=getWaliLinkedSantriIds_(session);
  return ids.indexOf(String(santriId||''))>=0;
}

function getWaliPortalBootstrap(token) {
  var a=requireCapability_(token,WALI_PORTAL_CAPABILITY); if(!a.ok)return a.response;
  if(a.session.role!=='wali_santri')return {success:false,code:'FORBIDDEN',message:'Portal ini khusus Wali Santri.'};
  ensureWaliPortalDatabase_();
  var children=getWaliChildren_(a.session);
  if(!children.length)return {success:false,code:'NO_CHILDREN',message:'Akun Wali Santri belum terhubung dengan data santri. Hubungi Superadmin.'};
  return {success:true,version:WALI_PORTAL_VERSION,user:{id:a.session.id,name:a.session.name,email:a.session.email},children:children,summary:getWaliSummary_(children)};
}


function getWaliSummary_(children){
  var out={totalChildren:children.length,prestasi:0,pelanggaran:0,perizinan:0,kesehatan:0,catatan:0};
  var ids={}; children.forEach(function(c){ids[c.id]=true;});
  var ss=SpreadsheetApp.getActiveSpreadsheet();
  function countSheet(name,idHeader,nameHeader){var sh=ss.getSheetByName(name);if(!sh||sh.getLastRow()<2)return 0;var m=headerMap(sh),d=sh.getDataRange().getValues(),n=0;for(var i=1;i<d.length;i++){var id=m[idHeader]?String(d[i][m[idHeader]-1]||''):'';var nm=m[nameHeader]?String(d[i][m[nameHeader]-1]||''):'';if((id&&ids[id])||(!id&&nm&&children.some(function(c){return c.nama.toLowerCase()===nm.trim().toLowerCase();})))n++;}return n;}
  out.prestasi=countSheet('Trx_Prestasi','ID_Santri','Nama_Santri');
  out.pelanggaran=countSheet('Trx_Pelanggaran','ID_Santri','Nama_Santri');
  out.perizinan=countSheet('Trx_Perizinan','ID_Santri','Nama_Santri');
  out.kesehatan=countSheet('Trx_Kesehatan','ID_Santri','Nama_Santri');
  out.catatan=countSheet('Trx_Catatan_Wali','ID_Santri','Nama_Santri');
  return out;
}

function getWaliChildTimeline(token,santriId,limit){
  var a=requireCapability_(token,WALI_PORTAL_CAPABILITY);if(!a.ok)return a.response;if(!assertWaliOwnsSantri_(a.session,santriId))return {success:false,code:'FORBIDDEN',message:'Anda tidak memiliki akses ke santri tersebut.'};
  var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri'),m=headerMap(sh),d=sh.getDataRange().getValues(),child=null;
  for(var i=1;i<d.length;i++)if(String(d[i][m['ID_Santri']-1]||'')===String(santriId)){child={id:santriId,nama:d[i][m['Nama_Santri']-1],kelas:d[i][m['Kelas']-1],waliKelas:d[i][m['Wali_Kelas']-1]};break;}
  if(!child)return {success:false,message:'Santri tidak ditemukan.'};
  var events=[]; var ss=SpreadsheetApp.getActiveSpreadsheet();
  function add(name,dateCol,typeCol,detailCols,extra){var s=ss.getSheetByName(name);if(!s||s.getLastRow()<2)return;var hm=headerMap(s),rows=s.getDataRange().getValues();for(var j=1;j<rows.length;j++){var rid=hm['ID_Santri']?String(rows[j][hm['ID_Santri']-1]||''):'';var nm=hm['Nama_Santri']?String(rows[j][hm['Nama_Santri']-1]||''):'';if(rid!==String(santriId)&&nm.trim().toLowerCase()!==String(child.nama).trim().toLowerCase())continue;var detail=detailCols.map(function(h){return hm[h]?String(rows[j][hm[h]-1]||''):'';}).filter(Boolean).join(' · ');events.push({date:formatDateSafe(hm[dateCol]?rows[j][hm[dateCol]-1]:''),type:typeCol,title:extra?extra(rows[j],hm):detail,detail:detail});}}
  add('Trx_Prestasi','Tanggal','Prestasi',['Jenis_Prestasi','Uraian_Prestasi','Tingkat_Penghargaan']);
  add('Trx_Pelanggaran','Tanggal','Pelanggaran',['Jenis_Pelanggaran','Deskripsi','Tindak_Pembinaan']);
  add('Trx_Catatan_Wali','Tanggal','Catatan Wali',['Kategori','Catatan']);
  add('Trx_Perizinan','Mulai','Perizinan',['Jenis','Tujuan','Alasan'],function(r,h){return (h['Jenis']?r[h['Jenis']-1]:'')+' · '+(h['Status']?r[h['Status']-1]:'');});
  add('Trx_Kesehatan','Tanggal','Kesehatan',['Keluhan','Diagnosa','Tindakan']);
  events.sort(function(x,y){return String(y.date).localeCompare(String(x.date));});
  return {success:true,data:events.slice(0,Math.min(100,Number(limit||50))),child:child};
}

function getWaliChildProfile(token,santriId){
  var a=requireCapability_(token,WALI_PORTAL_CAPABILITY);if(!a.ok)return a.response;if(!assertWaliOwnsSantri_(a.session,santriId))return {success:false,code:'FORBIDDEN',message:'Akses ditolak.'};
  var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri'),m=headerMap(sh),d=sh.getDataRange().getValues();
  for(var i=1;i<d.length;i++)if(String(d[i][m['ID_Santri']-1]||'')===String(santriId)){
    var map={'NISN':'nisn','Kelas':'kelas','Wali_Kelas':'waliKelas','Status':'status','Foto_URL':'fotoUrl','Status_Asrama':'statusAsrama','Kamar':'kamar','Jenis_Kelamin':'jenisKelamin','Tempat_Lahir':'tempatLahir','Tanggal_Lahir':'tanggalLahir','Nama_Ayah':'namaAyah','Nama_Ibu':'namaIbu','Alamat_Santri':'alamatSantri'};var o={id:santriId,nama:d[i][m['Nama_Santri']-1]};Object.keys(map).forEach(function(h){if(m[h])o[map[h]]=d[i][m[h]-1]||'';});return {success:true,data:o};
  }
  return {success:false,message:'Santri tidak ditemukan.'};
}

function getWaliPortalNotifications(token,limit){
  var a=requireCapability_(token,WALI_PORTAL_CAPABILITY);if(!a.ok)return a.response;
  if(a.session.role!=='wali_santri')return {success:false,code:'FORBIDDEN',message:'Portal ini khusus Wali Santri.'};
  return getUserNotifications(token,limit||30);
}

function markWaliNotificationRead(token,notificationId){
  var a=requireCapability_(token,WALI_PORTAL_CAPABILITY);if(!a.ok)return a.response;return {success:true,message:'Notifikasi ditandai telah dibaca.'};
}


/* ===== BEGIN WhatsAppNotification.gs ===== */
/**
 * TAICIMASTER FM — Stage 8 WhatsApp & Notification Service FINAL v8.0
 * Gateway-agnostic WhatsApp queue, templates, retries, audit and admin settings.
 * Secrets are stored in Script Properties, never in Spreadsheet cells.
 */
var WA8 = {
  VERSION: '8.0',
  SHEET: 'Notification_Queue',
  LOG_SHEET: 'Notification_Log',
  PREFIX: 'TAI_WA_',
  MAX_RETRIES: 3,
  TRIGGER_EVERY_MINUTES: 5,
  STATUS: {QUEUED:'QUEUED',PROCESSING:'PROCESSING',SENT:'SENT',FAILED:'FAILED',SKIPPED:'SKIPPED'}
};

function ensureNotificationDatabase_(){
  var ss=SpreadsheetApp.getActiveSpreadsheet();
  ensureSheetHeaders(ss,WA8.SHEET,['ID_Notification','Created_At','Scheduled_At','Type','Event_ID','Santri_ID','Santri_Name','Recipient','Message','Status','Attempts','Last_Attempt_At','Sent_At','Error','Created_By']);
  ensureSheetHeaders(ss,WA8.LOG_SHEET,['ID_Log','Timestamp','Notification_ID','Action','Recipient','Status','Detail','User_ID','User_Name']);
}

function getWhatsAppSettings_(includeSecret){
  var p=PropertiesService.getScriptProperties();
  var s={enabled:p.getProperty(WA8.PREFIX+'ENABLED')==='true',endpoint:p.getProperty(WA8.PREFIX+'ENDPOINT')||'',provider:p.getProperty(WA8.PREFIX+'PROVIDER')||'GENERIC_JSON',sender:p.getProperty(WA8.PREFIX+'SENDER')||'',autoQueue:p.getProperty(WA8.PREFIX+'AUTO_QUEUE')!=='false',maxRetries:Number(p.getProperty(WA8.PREFIX+'MAX_RETRIES')||WA8.MAX_RETRIES),triggerEnabled:p.getProperty(WA8.PREFIX+'TRIGGER_ENABLED')==='true'};
  if(includeSecret)s.token=p.getProperty(WA8.PREFIX+'TOKEN')||'';
  return s;
}
function getWhatsAppSettings(token){var a=requireSessionResult_(token,['superadmin']);if(!a.ok)return a.response;var s=getWhatsAppSettings_(false);s.tokenConfigured=!!PropertiesService.getScriptProperties().getProperty(WA8.PREFIX+'TOKEN');return {success:true,version:WA8.VERSION,data:s};}
function saveWhatsAppSettings(settings,token){
  var a=requireSessionResult_(token,['superadmin']);if(!a.ok)return a.response;
  settings=settings||{};var endpoint=String(settings.endpoint||'').trim(),provider=String(settings.provider||'GENERIC_JSON').trim().toUpperCase();
  if(endpoint && !/^https:\/\//i.test(endpoint))return {success:false,message:'Endpoint WhatsApp harus menggunakan HTTPS.'};
  if(['GENERIC_JSON','FONNTE_STYLE','EVOLUTION_STYLE'].indexOf(provider)<0)return {success:false,message:'Provider WhatsApp tidak dikenali.'};
  var p=PropertiesService.getScriptProperties();p.setProperty(WA8.PREFIX+'ENABLED',settings.enabled?'true':'false');p.setProperty(WA8.PREFIX+'ENDPOINT',endpoint);p.setProperty(WA8.PREFIX+'PROVIDER',provider);p.setProperty(WA8.PREFIX+'SENDER',String(settings.sender||'').trim());p.setProperty(WA8.PREFIX+'AUTO_QUEUE',settings.autoQueue===false?'false':'true');p.setProperty(WA8.PREFIX+'MAX_RETRIES',String(Math.min(5,Math.max(1,Number(settings.maxRetries||3)))));
  if(String(settings.token||'').trim())p.setProperty(WA8.PREFIX+'TOKEN',String(settings.token).trim());
  auditLog_(a.session,'UPDATE_WHATSAPP_SETTINGS','NOTIFICATION','Provider='+provider+'; Enabled='+!!settings.enabled);
  return {success:true,message:'Pengaturan WhatsApp berhasil disimpan.',data:getWhatsAppSettings_(false)};
}

function normalizeWhatsAppNumber_(raw){
  var n=String(raw||'').replace(/[^0-9+]/g,''); if(!n)return '';
  if(n.indexOf('+62')===0)n=n.substring(1);
  else if(n.indexOf('62')===0)n=n;
  else if(n.indexOf('0')===0)n='62'+n.substring(1);
  else n='62'+n;
  return /^62[1-9][0-9]{7,14}$/.test(n)?n:'';
}
function getGuardianPhoneBySantri_(santri){
  if(!santri)return '';
  try{var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri'),m=headerMap(sh),d=sh.getDataRange().getValues();for(var i=1;i<d.length;i++){var sameId=m['ID_Santri']&&String(d[i][m['ID_Santri']-1])===String(santri.id||'');var sameName=m['Nama_Santri']&&String(d[i][m['Nama_Santri']-1]).trim().toLowerCase()===String(santri.nama||'').trim().toLowerCase();if(sameId||sameName)return normalizeWhatsAppNumber_(m['No_HP_Ortu']?d[i][m['No_HP_Ortu']-1]:'');}}catch(e){}return '';}

function buildWhatsAppMessage_(type,data){
  data=data||{};var app=CONFIG.APP_NAME||'TAICIMASTER FM',n=data.santriNama||'Santri',d=data.detail||'';
  var lines=['*'+app+'*','Assalamu\'alaikum Ayah/Bunda '+(data.parentName||'Wali Santri')+'.','','Informasi perkembangan santri:','Nama: '+n+(data.kelas?'\nKelas: '+data.kelas:''),'Jenis: '+(data.category||type),(data.status?'Status: '+data.status:''),(d?'Keterangan: '+d:''),'','Pesan ini dikirim otomatis oleh sistem '+app+'.','Wassalamu\'alaikum.'];
  return lines.filter(function(x){return x!=='' || true;}).join('\n');
}

function queueWhatsAppNotification_(type,santri,eventId,data,session){
  var cfg=getWhatsAppSettings_(false); if(!cfg.enabled||!cfg.autoQueue)return {queued:false,reason:'DISABLED'};
  var recipient=getGuardianPhoneBySantri_(santri); if(!recipient)return {queued:false,reason:'NO_PHONE'};
  ensureNotificationDatabase_();
  var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WA8.SHEET),m=headerMap(sh),id=generateRecordId_('WA'),now=new Date(),message=buildWhatsAppMessage_(type,Object.assign({},data,{santriNama:santri.nama,kelas:santri.kelas}));
  var row=new Array(sh.getLastColumn()).fill(''),vals={'ID_Notification':id,'Created_At':now,'Scheduled_At':now,'Type':type,'Event_ID':eventId||'','Santri_ID':santri.id||'','Santri_Name':santri.nama||'','Recipient':recipient,'Message':message,'Status':WA8.STATUS.QUEUED,'Attempts':0,'Created_By':session?session.name:'SYSTEM'};
  Object.keys(vals).forEach(function(h){if(m[h])row[m[h]-1]=vals[h];});sh.appendRow(row);if(session)auditLog_(session,'QUEUE_WHATSAPP',id,'Recipient='+recipient+'; Type='+type);return {queued:true,id:id,recipient:recipient};
}
function queueWhatsAppNotification(type,santriNama,eventId,data,token){var a=requireCapability_(token,'notification.send');if(!a.ok)return a.response;var st=getSantriRecordByName_(santriNama);if(!st)return {success:false,message:'Santri tidak ditemukan.'};var q=queueWhatsAppNotification_(type,st,eventId,data,a.session);return {success:true,data:q,message:q.queued?'Notifikasi masuk antrean WhatsApp.':'Notifikasi tidak diantrekan: '+q.reason};}

function buildProviderRequest_(cfg,recipient,message){
  var headers={'Content-Type':'application/json'},payload={to:recipient,message:message,sender:cfg.sender||'',appName:CONFIG.APP_NAME};
  if(cfg.provider==='FONNTE_STYLE'){payload.target=recipient;payload.message=message;if(cfg.sender)payload.countryCode='62';}
  if(cfg.provider==='EVOLUTION_STYLE'){payload.number=recipient;payload.text=message;}
  var token=PropertiesService.getScriptProperties().getProperty(WA8.PREFIX+'TOKEN')||'';if(token)headers.Authorization='Bearer '+token;
  if(cfg.provider==='FONNTE_STYLE'&&token){headers.Authorization=token;}
  return {headers:headers,payload:payload};
}
function sendQueuedNotification_(rowNumber){
  ensureNotificationDatabase_();var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WA8.SHEET),m=headerMap(sh),r=sh.getRange(rowNumber,1,1,sh.getLastColumn()).getValues()[0],cfg=getWhatsAppSettings_(false),id=r[m['ID_Notification']-1],recipient=normalizeWhatsAppNumber_(r[m['Recipient']-1]),message=String(r[m['Message']-1]||''),attempts=Number(r[m['Attempts']-1]||0);
  if(!cfg.enabled)return {success:false,code:'WA_DISABLED'};if(!cfg.endpoint)return {success:false,code:'WA_ENDPOINT_MISSING'};if(!recipient)return {success:false,code:'INVALID_RECIPIENT'};
  var req=buildProviderRequest_(cfg,recipient,message);sh.getRange(rowNumber,m['Status']).setValue(WA8.STATUS.PROCESSING);sh.getRange(rowNumber,m['Attempts']).setValue(attempts+1);sh.getRange(rowNumber,m['Last_Attempt_At']).setValue(new Date());
  try{var res=UrlFetchApp.fetch(cfg.endpoint,{method:'post',contentType:'application/json',headers:req.headers,payload:JSON.stringify(req.payload),muteHttpExceptions:true});var code=res.getResponseCode(),body=res.getContentText().slice(0,1000);if(code>=200&&code<300){sh.getRange(rowNumber,m['Status']).setValue(WA8.STATUS.SENT);if(m['Sent_At'])sh.getRange(rowNumber,m['Sent_At']).setValue(new Date());if(m['Error'])sh.getRange(rowNumber,m['Error']).clearContent();return {success:true,code:code};}throw new Error('HTTP '+code+': '+body);}catch(e){var next=attempts+1,final=next>=cfg.maxRetries;sh.getRange(rowNumber,m['Status']).setValue(final?WA8.STATUS.FAILED:WA8.STATUS.QUEUED);sh.getRange(rowNumber,m['Error']).setValue(String(e.message||e).slice(0,1000));return {success:false,final:final,message:String(e.message||e)};}
}
function processWhatsAppQueue(){
  var cfg=getWhatsAppSettings_(false);if(!cfg.enabled||!cfg.endpoint)return {success:false,message:'WhatsApp belum dikonfigurasi.'};ensureNotificationDatabase_();var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WA8.SHEET),m=headerMap(sh),d=sh.getDataRange().getValues(),count=0,sent=0,failed=0,now=Date.now();
  for(var i=1;i<d.length&&count<20;i++){var status=String(d[i][m['Status']-1]||''),scheduled=d[i][m['Scheduled_At']-1],attempts=Number(d[i][m['Attempts']-1]||0);if((status===WA8.STATUS.QUEUED||status===WA8.STATUS.FAILED)&&attempts<cfg.maxRetries&&(!scheduled||new Date(scheduled).getTime()<=now)){var r=sendQueuedNotification_(i+1);count++;if(r.success)sent++;else if(r.final)failed++;Utilities.sleep(150);}}
  return {success:true,processed:count,sent:sent,failed:failed};
}
function installWhatsAppQueueTrigger(token){var a=requireSessionResult_(token,['superadmin']);if(!a.ok)return a.response;var existing=ScriptApp.getProjectTriggers().filter(function(t){return t.getHandlerFunction()==='processWhatsAppQueue';});if(!existing.length)ScriptApp.newTrigger('processWhatsAppQueue').timeBased().everyMinutes(WA8.TRIGGER_EVERY_MINUTES).create();PropertiesService.getScriptProperties().setProperty(WA8.PREFIX+'TRIGGER_ENABLED','true');auditLog_(a.session,'ENABLE_WHATSAPP_TRIGGER','NOTIFICATION','Every '+WA8.TRIGGER_EVERY_MINUTES+' minutes');return {success:true,message:'Pemrosesan antrean WhatsApp otomatis diaktifkan.'};}
function disableWhatsAppQueueTrigger(token){var a=requireSessionResult_(token,['superadmin']);if(!a.ok)return a.response;ScriptApp.getProjectTriggers().forEach(function(t){if(t.getHandlerFunction()==='processWhatsAppQueue')ScriptApp.deleteTrigger(t);});PropertiesService.getScriptProperties().setProperty(WA8.PREFIX+'TRIGGER_ENABLED','false');auditLog_(a.session,'DISABLE_WHATSAPP_TRIGGER','NOTIFICATION','Trigger dinonaktifkan');return {success:true,message:'Pemrosesan antrean WhatsApp otomatis dimatikan.'};}
function getNotificationQueue(token,status,limit){var a=requireAnyCapability_(token,['notification.send','notification.manage']);if(!a.ok)return a.response;ensureNotificationDatabase_();var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WA8.SHEET),m=headerMap(sh),d=sh.getDataRange().getValues(),o=[],max=Math.min(100,Number(limit||50));for(var i=d.length-1;i>=1&&o.length<max;i--){var st=String(d[i][m['Status']-1]||'');if(status&&status!=='ALL'&&st!==status)continue;o.push({id:d[i][m['ID_Notification']-1],createdAt:d[i][m['Created_At']-1],type:d[i][m['Type']-1],santriName:d[i][m['Santri_Name']-1],recipient:d[i][m['Recipient']-1],status:st,attempts:d[i][m['Attempts']-1],error:d[i][m['Error']-1]||''});}return {success:true,data:o};}
function retryWhatsAppNotification(id,token){var a=requireCapability_(token,'notification.send');if(!a.ok)return a.response;ensureNotificationDatabase_();var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WA8.SHEET),m=headerMap(sh),d=sh.getDataRange().getValues();for(var i=1;i<d.length;i++)if(String(d[i][m['ID_Notification']-1])===String(id)){sh.getRange(i+1,m['Status']).setValue(WA8.STATUS.QUEUED);sh.getRange(i+1,m['Scheduled_At']).setValue(new Date());if(m['Error'])sh.getRange(i+1,m['Error']).clearContent();auditLog_(a.session,'RETRY_WHATSAPP',id,'Notification queued again');return {success:true,message:'Notifikasi dikembalikan ke antrean.'};}return {success:false,message:'Notification ID tidak ditemukan.'};}
function testWhatsAppConnection(token){var a=requireSessionResult_(token,['superadmin']);if(!a.ok)return a.response;var cfg=getWhatsAppSettings_(false);if(!cfg.endpoint)return {success:false,message:'Endpoint WhatsApp belum diatur.'};var testRecipient=normalizeWhatsAppNumber_(cfg.sender);if(!testRecipient)return {success:false,message:'Isi Nomor Penguji (Sender/Test Number) dengan nomor WhatsApp valid.'};var req=buildProviderRequest_(cfg,testRecipient,'Tes koneksi TAICIMASTER FM Stage 8. Jika pesan ini diterima, gateway WhatsApp berhasil terhubung.');try{var r=UrlFetchApp.fetch(cfg.endpoint,{method:'post',contentType:'application/json',headers:req.headers,payload:JSON.stringify(req.payload),muteHttpExceptions:true}),code=r.getResponseCode();auditLog_(a.session,'TEST_WHATSAPP','GATEWAY','HTTP '+code);return {success:code>=200&&code<300,message:code>=200&&code<300?'Gateway merespons HTTP '+code+'.':'Gateway merespons HTTP '+code+'. Periksa endpoint/token/provider.',httpCode:code};}catch(e){return {success:false,message:'Gagal menghubungi gateway: '+e.message};}}
function getStage8Status(token){var a=requireSessionResult_(token,['superadmin']);if(!a.ok)return a.response;ensureNotificationDatabase_();var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WA8.SHEET),m=headerMap(sh),d=sh.getDataRange().getValues(),counts={QUEUED:0,PROCESSING:0,SENT:0,FAILED:0,SKIPPED:0};for(var i=1;i<d.length;i++){var s=String(d[i][m['Status']-1]||'');if(counts[s]!==undefined)counts[s]++;}var cfg=getWhatsAppSettings_(false);return {success:true,version:WA8.VERSION,config:{enabled:cfg.enabled,endpointConfigured:!!cfg.endpoint,provider:cfg.provider,autoQueue:cfg.autoQueue,triggerEnabled:cfg.triggerEnabled,maxRetries:cfg.maxRetries},counts:counts};}

/* ===== BEGIN WebPush Notifications =====
 * Transactional web push for installed Android/iOS PWAs, delivered by OneSignal.
 * Store ONESIGNAL_APP_ID and ONESIGNAL_REST_API_KEY in Script Properties.
 */
var WEB_PUSH = {
  SHEET: 'WebPush_Queue',
  APP_ID_PROPERTY: 'ONESIGNAL_APP_ID',
  API_KEY_PROPERTY: 'ONESIGNAL_REST_API_KEY',
  ENABLED_PROPERTY: 'ONESIGNAL_ENABLED',
  INBOX_SHEET: 'WebPush_Inbox',
  EXTERNAL_ID_SECRET_PROPERTY: 'TAICI_WEBPUSH_EXTERNAL_ID_SECRET',
  MAX_RETRIES: 3,
  BATCH_SIZE: 10,
  TRIGGER_EVERY_MINUTES: 1,
  APP_URL: 'https://appfathanmubina.github.io/fm-taicimaster/'
};

function ensureWebPushExternalIdSecret_() {
  var props=PropertiesService.getScriptProperties();
  if(!props.getProperty(WEB_PUSH.EXTERNAL_ID_SECRET_PROPERTY)) props.setProperty(WEB_PUSH.EXTERNAL_ID_SECRET_PROPERTY,Utilities.getUuid()+Utilities.getUuid()+Utilities.getUuid());
  return props.getProperty(WEB_PUSH.EXTERNAL_ID_SECRET_PROPERTY);
}

function toWebPushExternalId_(userId) {
  var bytes=Utilities.computeHmacSha256Signature(String(userId||''),ensureWebPushExternalIdSecret_(),Utilities.Charset.UTF_8);
  return 'tm_'+Utilities.base64EncodeWebSafe(bytes).replace(/=+$/,'');
}

function getWebPushIdentity(token) {
  var auth=requireSessionResult_(token);if(!auth.ok)return auth.response;
  if(!auth.session||!auth.session.id)return {success:false,code:'SESSION_INVALID',message:'Sesi tidak valid.'};
  var props=PropertiesService.getScriptProperties();
  return {success:true,externalId:toWebPushExternalId_(auth.session.id),enabled:props.getProperty(WEB_PUSH.ENABLED_PROPERTY)==='true',appId:props.getProperty(WEB_PUSH.APP_ID_PROPERTY)||''};
}

function ensureWebPushDatabase_() {
  var ss=SpreadsheetApp.getActiveSpreadsheet(),props=PropertiesService.getScriptProperties();
  ensureSheetHeaders(ss,WEB_PUSH.SHEET,['ID','Created_At','Scheduled_At','Event_ID','Audience','External_IDs','Title','Message','URL','Status','Attempts','Last_Attempt_At','Sent_At','Provider_ID','Error']);
  ensureSheetHeaders(ss,WEB_PUSH.INBOX_SHEET,['ID_Notification','Created_At','User_ID','Santri_ID','Event_ID','Type','Title','Message','URL','Read_At']);
  ensureWebPushExternalIdSecret_();
  if(props.getProperty(WEB_PUSH.ENABLED_PROPERTY)==='true'&&props.getProperty(WEB_PUSH.APP_ID_PROPERTY)&&props.getProperty(WEB_PUSH.API_KEY_PROPERTY)){
    var triggers=ScriptApp.getProjectTriggers().filter(function(t){return t.getHandlerFunction()==='processWebPushQueue';});
    if(!triggers.length)ScriptApp.newTrigger('processWebPushQueue').timeBased().everyMinutes(WEB_PUSH.TRIGGER_EVERY_MINUTES).create();
  }
}

function getWebPushRecipients_(santri,type,session) {
  var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Users');
  if(!sh||sh.getLastRow()<2)return {wali:[],admins:[],waliKelas:[]};
  var m=headerMap(sh),data=sh.getDataRange().getValues(),sid=String(santri&&santri.id||'').trim(),studentIds=sid.split(/[,;\n]+/).map(function(x){return x.trim().toLowerCase();}).filter(Boolean),studentClass=String(santri&&santri.kelas||'').trim().toLowerCase(),actorId=String(session&&session.id||'').trim();
  var routes={PRESTASI:['admin_prestasi'],PELANGGARAN:['admin_pelanggaran'],PERIZINAN:['admin_perizinan','admin_pelanggaran'],KESEHATAN:['admin_kesehatan'],CATATAN_WALI:[]},route=routes[type]||[],out={wali:[],admins:[],waliKelas:[]};
  function list(value){return String(value||'').split(/[,;\n]+/).map(function(x){return x.trim().toLowerCase();}).filter(Boolean);}
  function add(bucket,id){id=String(id||'').trim();if(id&&id!==actorId)bucket.push({userId:id,externalId:toWebPushExternalId_(id)});}
  for(var i=1;i<data.length;i++){
    var id=String(m.ID_User?data[i][m.ID_User-1]:'' ).trim(),role=normalizeRole_(m.Role?data[i][m.Role-1]:''),status=normalizeText_(m.Status?data[i][m.Status-1]:'',30).toLowerCase();
    if(!id||id===actorId||(status!=='aktif'&&status!=='active'))continue;
    if(role==='wali_santri'){
      var linked=list(m.ID_Santri_Wali?data[i][m.ID_Santri_Wali-1]:'');
      if(studentIds.some(function(x){return linked.indexOf(x)>=0;}))add(out.wali,id);
    }else if(role==='walikelas'){
      var scope=list(m.Akses_Kelas?data[i][m.Akses_Kelas-1]:''),matches=scope.indexOf('all')>=0||(studentClass&&scope.indexOf(studentClass)>=0);
      if(matches)add(out.waliKelas,id);
    }else if(role==='superadmin'||role==='supervisor'||route.indexOf(role)>=0)add(out.admins,id);
  }
  Object.keys(out).forEach(function(key){var seen={};out[key]=out[key].filter(function(user){if(seen[user.userId])return false;seen[user.userId]=true;return true;});});
  return out;
}

function queueWebPushMessage_(eventId,audience,recipientUsers,title,message,url) {
  var props=PropertiesService.getScriptProperties();
  if(!recipientUsers||!recipientUsers.length||props.getProperty(WEB_PUSH.ENABLED_PROPERTY)!=='true'||!props.getProperty(WEB_PUSH.APP_ID_PROPERTY)||!props.getProperty(WEB_PUSH.API_KEY_PROPERTY))return false;
  try{
    var ss=SpreadsheetApp.getActiveSpreadsheet();ensureSheetHeaders(ss,WEB_PUSH.SHEET,['ID','Created_At','Scheduled_At','Event_ID','Audience','External_IDs','Title','Message','URL','Status','Attempts','Last_Attempt_At','Sent_At','Provider_ID','Error']);
    var sh=ss.getSheetByName(WEB_PUSH.SHEET),now=new Date(),ids=recipientUsers.map(function(user){return String(user.externalId);});
    sh.appendRow([generateRecordId_('PUSH'),now,now,String(eventId||''),String(audience||''),JSON.stringify(ids),String(title||'Informasi TAICIMASTER FM').slice(0,80),String(message||'Ada informasi baru. Buka aplikasi untuk melihat detail.').slice(0,180),String(url||WEB_PUSH.APP_URL),'QUEUED',0,'','','','']);
    return true;
  }catch(e){console.error('Web push enqueue failed: '+e);return false;}
}

function recordUserNotifications_(eventId,type,santri,users,title,message,url) {
  if(!users||!users.length)return;
  var ss=SpreadsheetApp.getActiveSpreadsheet();ensureSheetHeaders(ss,WEB_PUSH.INBOX_SHEET,['ID_Notification','Created_At','User_ID','Santri_ID','Event_ID','Type','Title','Message','URL','Read_At']);
  var sh=ss.getSheetByName(WEB_PUSH.INBOX_SHEET),now=new Date(),rows=[];
  users.forEach(function(user){rows.push([generateRecordId_('NFO'),now,String(user.userId),String(santri&&santri.id||''),String(eventId||''),String(type||''),String(title||'Notifikasi TAICIMASTER FM'),String(message||'Ada informasi baru. Buka aplikasi untuk melihat detail.'),String(url||WEB_PUSH.APP_URL),'']);});
  if(rows.length)sh.getRange(sh.getLastRow()+1,1,rows.length,rows[0].length).setValues(rows);
}

function queueNewDataPush_(type,santri,eventId,status,session) {
  try{
    var recipients=getWebPushRecipients_(santri,type,session),labels={PRESTASI:'prestasi',PELANGGARAN:'disiplin',PERIZINAN:'perizinan',KESEHATAN:'kesehatan',CATATAN_WALI:'catatan Wali Kelas'},label=labels[type]||'data santri',pending=String(status||'').toLowerCase()==='pending',studentName=String(santri&&santri.nama||'santri');
    var parentTitle=pending?'Pengajuan prestasi menunggu persetujuan':'Informasi baru: '+label,parentBody='Ada pembaruan '+label+' untuk '+studentName+'. Buka aplikasi untuk melihat detail.';
    var peerTitle=pending?'Perlu tinjauan: '+label:'Data baru: '+label,peerBody=(session&&normalizeRole_(session.role)==='walikelas'?'Wali Kelas mencatat ':'Admin mencatat ')+label+' untuk '+studentName+'.';
    var rejected=String(status||'').toLowerCase()==='rejected';
    var groups=rejected?[{users:recipients.waliKelas,audience:'wali_kelas',title:'Pengajuan prestasi ditolak',message:'Pengajuan prestasi untuk '+studentName+' ditolak. Buka aplikasi untuk melihat status dan tindak lanjut.'}]:pending?[{users:recipients.admins,audience:'admin_review',title:peerTitle,message:peerBody}]:[{users:recipients.wali,audience:'wali_santri',title:parentTitle,message:parentBody},{users:recipients.admins,audience:'admin',title:peerTitle,message:peerBody},{users:recipients.waliKelas,audience:'wali_kelas',title:peerTitle,message:peerBody}],seen={};
    groups.forEach(function(group){
      var users=group.users.filter(function(user){if(seen[user.userId])return false;seen[user.userId]=true;return true;});
      if(!users.length)return;
      recordUserNotifications_(eventId,type,santri,users,group.title,group.message,WEB_PUSH.APP_URL);
      queueWebPushMessage_(eventId,group.audience,users,group.title,group.message,WEB_PUSH.APP_URL);
    });
  }catch(e){console.error('Notification enqueue failed: '+e);}
}

function getUserNotifications(token,limit){
  var a=requireSessionResult_(token);if(!a.ok)return a.response;var ss=SpreadsheetApp.getActiveSpreadsheet();ensureSheetHeaders(ss,WEB_PUSH.INBOX_SHEET,['ID_Notification','Created_At','User_ID','Santri_ID','Event_ID','Type','Title','Message','URL','Read_At']);
  var sh=ss.getSheetByName(WEB_PUSH.INBOX_SHEET),out=[],max=Math.min(100,Math.max(1,Number(limit||40))),userId=String(a.session.id||''),m=headerMap(sh),data=sh.getDataRange().getValues();
  for(var i=data.length-1;i>=1&&out.length<max;i--){if(String(data[i][m.User_ID-1]||'')!==userId)continue;out.push({id:String(data[i][m.ID_Notification-1]||''),timestamp:formatDateSafe(data[i][m.Created_At-1]),type:String(data[i][m.Type-1]||''),santriId:String(data[i][m.Santri_ID-1]||''),eventId:String(data[i][m.Event_ID-1]||''),title:String(data[i][m.Title-1]||''),message:String(data[i][m.Message-1]||''),url:String(data[i][m.URL-1]||WEB_PUSH.APP_URL),read:!!data[i][m.Read_At-1],status:data[i][m.Read_At-1]?'Dibaca':'Baru'});}
  return {success:true,data:out,unread:out.filter(function(x){return !x.read;}).length};
}

function markUserNotificationRead(token,notificationId){
  var a=requireSessionResult_(token);if(!a.ok)return a.response;var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WEB_PUSH.INBOX_SHEET);if(!sh)return {success:false,message:'Riwayat notifikasi belum tersedia.'};
  var m=headerMap(sh),data=sh.getDataRange().getValues(),userId=String(a.session.id||''),id=String(notificationId||'');
  for(var i=1;i<data.length;i++)if(String(data[i][m.ID_Notification-1]||'')===id&&String(data[i][m.User_ID-1]||'')===userId){if(!data[i][m.Read_At-1])sh.getRange(i+1,m.Read_At).setValue(new Date());return {success:true};}
  return {success:false,message:'Notifikasi tidak ditemukan.'};
}

function getWebPushStatus(token){
  var a=requireSessionResult_(token,['superadmin']);if(!a.ok)return a.response;var props=PropertiesService.getScriptProperties(),ss=SpreadsheetApp.getActiveSpreadsheet();
  ensureWebPushDatabase_();var q=ss.getSheetByName(WEB_PUSH.SHEET),m=headerMap(q),data=q.getDataRange().getValues(),counts={QUEUED:0,PROCESSING:0,SENT:0,FAILED:0,SKIPPED:0};
  for(var i=1;i<data.length;i++){var status=String(data[i][m.Status-1]||'');if(counts[status]!==undefined)counts[status]++;}
  return {success:true,config:{enabled:props.getProperty(WEB_PUSH.ENABLED_PROPERTY)==='true',appId:props.getProperty(WEB_PUSH.APP_ID_PROPERTY)||'',apiKeyConfigured:!!props.getProperty(WEB_PUSH.API_KEY_PROPERTY)},triggerEnabled:ScriptApp.getProjectTriggers().some(function(t){return t.getHandlerFunction()==='processWebPushQueue';}),counts:counts};
}

function saveWebPushSettings(settings,token){
  var a=requireSessionResult_(token,['superadmin']);if(!a.ok)return a.response;settings=settings||{};
  var props=PropertiesService.getScriptProperties(),appId=String(settings.appId||'').trim(),apiKey=String(settings.apiKey||'').trim(),enabled=settings.enabled===true;
  if(appId&&!/^[A-Za-z0-9-]{20,64}$/.test(appId))return {success:false,message:'Format OneSignal App ID tidak valid.'};
  if(apiKey&&apiKey.length<20)return {success:false,message:'REST API Key tampak tidak valid.'};
  if(appId)props.setProperty(WEB_PUSH.APP_ID_PROPERTY,appId);
  if(apiKey)props.setProperty(WEB_PUSH.API_KEY_PROPERTY,apiKey);
  var hasCredentials=!!props.getProperty(WEB_PUSH.APP_ID_PROPERTY)&&!!props.getProperty(WEB_PUSH.API_KEY_PROPERTY);
  if(enabled&&!hasCredentials)return {success:false,message:'Isi App ID dan REST API Key terlebih dahulu.'};
  props.setProperty(WEB_PUSH.ENABLED_PROPERTY,enabled?'true':'false');
  var triggers=ScriptApp.getProjectTriggers().filter(function(t){return t.getHandlerFunction()==='processWebPushQueue';});
  if(enabled&&!triggers.length)ScriptApp.newTrigger('processWebPushQueue').timeBased().everyMinutes(WEB_PUSH.TRIGGER_EVERY_MINUTES).create();
  if(!enabled)triggers.forEach(function(t){ScriptApp.deleteTrigger(t);});
  auditLog_(a.session,'UPDATE_WEB_PUSH_SETTINGS','NOTIFICATION','Enabled='+enabled+'; Credentials configured='+hasCredentials);
  return {success:true,message:enabled?'Web Push aktif. Notifikasi baru akan diproses otomatis.':'Web Push dinonaktifkan.',config:{enabled:enabled,appId:props.getProperty(WEB_PUSH.APP_ID_PROPERTY)||'',apiKeyConfigured:!!props.getProperty(WEB_PUSH.API_KEY_PROPERTY)}};
}

function retryFailedWebPushNotifications(token,limit){
  var a=requireSessionResult_(token,['superadmin']);if(!a.ok)return a.response;var props=PropertiesService.getScriptProperties();
  if(props.getProperty(WEB_PUSH.ENABLED_PROPERTY)!=='true'||!props.getProperty(WEB_PUSH.APP_ID_PROPERTY)||!props.getProperty(WEB_PUSH.API_KEY_PROPERTY))return {success:false,message:'Aktifkan dan lengkapi konfigurasi OneSignal terlebih dahulu.'};
  var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WEB_PUSH.SHEET);if(!sh)return {success:true,count:0,message:'Tidak ada antrean yang perlu dicoba ulang.'};
  var m=headerMap(sh),data=sh.getDataRange().getValues(),max=Math.min(100,Math.max(1,Number(limit||30))),count=0;
  for(var i=1;i<data.length&&count<max;i++)if(String(data[i][m.Status-1]||'')==='FAILED'){
    sh.getRange(i+1,m.Status).setValue('QUEUED');sh.getRange(i+1,m.Attempts).setValue(0);sh.getRange(i+1,m.Scheduled_At).setValue(new Date());if(m.Error)sh.getRange(i+1,m.Error).clearContent();count++;
  }
  if(count)auditLog_(a.session,'RETRY_WEB_PUSH','NOTIFICATION','Rows='+count);
  return {success:true,count:count,message:count+' notifikasi gagal dimasukkan kembali ke antrean.'};
}

function processWebPushQueue() {
  var props=PropertiesService.getScriptProperties(), appId=props.getProperty(WEB_PUSH.APP_ID_PROPERTY), apiKey=props.getProperty(WEB_PUSH.API_KEY_PROPERTY);
  if(!appId || !apiKey || props.getProperty(WEB_PUSH.ENABLED_PROPERTY)!=='true') return {success:false,message:'OneSignal belum dikonfigurasi atau dinonaktifkan.'};
  var lock=LockService.getScriptLock(); if(!lock.tryLock(1000)) return {success:false,message:'Proses antrean web push sedang berjalan.'};
  try {
    ensureSheetHeaders(SpreadsheetApp.getActiveSpreadsheet(),WEB_PUSH.SHEET,['ID','Created_At','Scheduled_At','Event_ID','Audience','External_IDs','Title','Message','URL','Status','Attempts','Last_Attempt_At','Sent_At','Provider_ID','Error']);
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WEB_PUSH.SHEET), data=sh.getDataRange().getValues(), m=headerMap(sh), processed=0, now=new Date();
    for(var i=1;i<data.length && processed<WEB_PUSH.BATCH_SIZE;i++){
      var status=String(data[i][m['Status']-1]||''), scheduled=data[i][m['Scheduled_At']-1], row=i+1;
      if(status!=='QUEUED' || (scheduled instanceof Date && scheduled.getTime()>now.getTime())) continue;
      var recipients=[]; try{recipients=JSON.parse(data[i][m['External_IDs']-1]||'[]');}catch(e){}
      if(!recipients.length){sh.getRange(row,m['Status']).setValue('SKIPPED');continue;}
      var attempts=Number(data[i][m['Attempts']-1]||0)+1;
      sh.getRange(row,m['Status']).setValue('PROCESSING'); sh.getRange(row,m['Attempts']).setValue(attempts); sh.getRange(row,m['Last_Attempt_At']).setValue(now);
      try {
        var payload={app_id:appId,target_channel:'push',include_aliases:{external_id:recipients},headings:{id:'TAICIMASTER FM'},contents:{id:String(data[i][m['Message']-1]||'Ada informasi baru.')},url:String(data[i][m['URL']-1]||WEB_PUSH.APP_URL),name:'TAICIMASTER '+String(data[i][m['Audience']-1]||'')+' '+String(data[i][m['Event_ID']-1]||'')};
        var response=UrlFetchApp.fetch('https://api.onesignal.com/notifications',{method:'post',contentType:'application/json',headers:{Authorization:'Key '+apiKey},payload:JSON.stringify(payload),muteHttpExceptions:true});
        var code=response.getResponseCode(), text=response.getContentText(), result={}; try{result=JSON.parse(text||'{}');}catch(e){}
        if(code>=200 && code<300 && result.id){sh.getRange(row,m['Status']).setValue('SENT');sh.getRange(row,m['Sent_At']).setValue(new Date());sh.getRange(row,m['Provider_ID']).setValue(result.id);sh.getRange(row,m['Error']).clearContent();}
        else if(code>=200 && code<300){sh.getRange(row,m['Status']).setValue('SKIPPED');sh.getRange(row,m['Error']).setValue('Tidak ada subscription aktif untuk penerima saat ini.');}
        else throw new Error('OneSignal HTTP '+code+': '+String(text).slice(0,500));
      } catch(e) {
        sh.getRange(row,m['Error']).setValue(String(e).slice(0,500));
        if(attempts>=WEB_PUSH.MAX_RETRIES) sh.getRange(row,m['Status']).setValue('FAILED');
        else {sh.getRange(row,m['Status']).setValue('QUEUED');sh.getRange(row,m['Scheduled_At']).setValue(new Date(Date.now()+attempts*60000));}
      }
      processed++;
    }
    return {success:true,processed:processed};
  } finally {lock.releaseLock();}
}
/* ===== END WebPush Notifications ===== */


/* Bridge.html embedded to keep the Apps Script project to three files. */
function taiciPwaBridgeOutput_() {
  return HtmlService.createHtmlOutput("<!doctype html>\n<html lang=\"id\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <meta name=\"referrer\" content=\"no-referrer\">\n  <title>TAICIMASTER FM — PWA Bridge</title>\n  <style>\n    html, body {\n      margin: 0;\n      padding: 0;\n      background: transparent;\n      font: 14px/1.4 system-ui, sans-serif;\n    }\n  </style>\n</head>\n<body>\n<script>\n(() => {\n  'use strict';\n\n  /*\n   * File: Bridge.html\n   * Tujuan: jembatan pesan antara PWA GitHub Pages dan Apps Script.\n   *\n   * PENTING:\n   * - File ini harus dipasangkan dengan fungsi server:\n   *     getTaiciPwaBridgeConfig()\n   *     taiciPwaBridgeCall(functionName, args)\n   * - Fungsi server wajib memvalidasi origin dan allowlist fungsi,\n   *   serta tetap menjalankan pemeriksaan sesi/otorisasi setiap fungsi.\n   * - Jangan menganggap file ini sendiri sebagai pengamanan backend.\n   */\n\n  const BRIDGE_SOURCE = 'taicimaster-fm-api-bridge';\n  const CLIENT_SOURCE = 'taicimaster-fm-pwa';\n  const BRIDGE_VERSION = '11.28.6-migration.1';\n\n  // Origin GitHub Pages yang diizinkan. Jangan gunakan wildcard (*).\n  const ALLOWED_PARENT_ORIGIN = 'https://appfathanmubina.github.io';\n\n  let bridgeReady = false;\n  function postToParent(type, payload) {\n    if (window.top === window) return;\n\n    window.top.postMessage(\n      Object.assign({\n        source: BRIDGE_SOURCE,\n        type,\n        version: BRIDGE_VERSION\n      }, payload || {}),\n      ALLOWED_PARENT_ORIGIN\n    );\n  }\n\n  function errorMessage(error, fallback) {\n    const message = error && typeof error.message === 'string'\n      ? error.message\n      : fallback;\n    return String(message || fallback).slice(0, 1000);\n  }\n\n  // Minta konfigurasi ke backend. Backend harus mengembalikan allowedOrigins\n  // yang memuat origin PWA hanya jika origin tersebut benar-benar diizinkan.\n  google.script.run\n    .withSuccessHandler((config) => {\n      const origins = config && Array.isArray(config.allowedOrigins)\n        ? config.allowedOrigins\n        : [];\n\n      bridgeReady = origins.includes(ALLOWED_PARENT_ORIGIN);\n\n      if (bridgeReady) {\n        postToParent('ready', { ready: true });\n      } else {\n        postToParent('bridge-error', {\n          ready: false,\n          error: { message: 'Origin PWA tidak diizinkan oleh konfigurasi server.' }\n        });\n      }\n    })\n    .withFailureHandler((error) => {\n      bridgeReady = false;\n      postToParent('bridge-error', {\n        ready: false,\n        error: { message: errorMessage(error, 'Konfigurasi bridge gagal dimuat.') }\n      });\n    })\n    .getTaiciPwaBridgeConfig();\n\n  window.addEventListener('message', (event) => {\n    // Tolak pesan dari origin lain, jendela lain, atau format yang tidak dikenal.\n    if (event.origin !== ALLOWED_PARENT_ORIGIN) return;\n    if (event.source !== window.top) return;\n\n    const data = event.data;\n    if (!data || typeof data !== 'object') return;\n    if (data.source !== CLIENT_SOURCE || data.type !== 'request') return;\n\n    const requestId = String(data.id || '').slice(0, 120);\n    const functionName = String(data.fn || '').trim();\n    const args = Array.isArray(data.args) ? data.args : [];\n\n    if (!requestId || !/^[A-Za-z0-9_.:-]{1,120}$/.test(requestId)) return;\n\n    if (!bridgeReady) {\n      postToParent('response', {\n        id: requestId,\n        ok: false,\n        error: { message: 'Bridge belum siap. Muat ulang aplikasi dan coba lagi.' }\n      });\n      return;\n    }\n\n    // Batas dasar di sisi iframe; validasi yang otoritatif tetap wajib di server.\n    if (!/^[A-Za-z_$][A-Za-z0-9_$]{0,99}$/.test(functionName)) {\n      postToParent('response', {\n        id: requestId,\n        ok: false,\n        error: { message: 'Nama fungsi tidak valid.' }\n      });\n      return;\n    }\n\n    if (args.length > 12) {\n      postToParent('response', {\n        id: requestId,\n        ok: false,\n        error: { message: 'Jumlah argumen melebihi batas bridge.' }\n      });\n      return;\n    }\n\n    google.script.run\n      .withSuccessHandler((result) => {\n        postToParent('response', {\n          id: requestId,\n          ok: true,\n          result\n        });\n      })\n      .withFailureHandler((error) => {\n        postToParent('response', {\n          id: requestId,\n          ok: false,\n          error: {\n            message: errorMessage(error, 'Permintaan backend gagal.')\n          }\n        });\n      })\n      .taiciPwaBridgeCall(functionName, args);\n  });\n})();\n</script>\n</body>\n</html>\n")
    .setTitle('TAICIMASTER FM Bridge')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}
