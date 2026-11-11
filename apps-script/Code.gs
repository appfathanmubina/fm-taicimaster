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
        var um=headerMap(sheet); var canonicalRole=(typeof normalizeRole_==='function'?normalizeRole_(row[4]):String(row[4]||'').trim().toLowerCase().replace(/[\s-]+/g,'_')); var user={id:row[0],name:row[1],email:row[2],role:canonicalRole,aksesKelas:row[6]||'All',lingkupSantri:normalizeSantriScope_(um['Lingkup_Santri']?row[um['Lingkup_Santri']-1]:'ALL'),waliSantriIds:um['ID_Santri_Wali']?String(row[um['ID_Santri_Wali']-1]||''):''};
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
      var scopeCheck=assertSantriAccess_(s,{kelas:kelas,jenisKelamin:m['Jenis_Kelamin']?d[i][m['Jenis_Kelamin']-1]:''});
      if(!scopeCheck.ok)return {success:false,message:scopeCheck.message};
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
      if(!assertSantriAccess_(a.session,{kelas:kelas,jenisKelamin:m['Jenis_Kelamin']?rows[i][m['Jenis_Kelamin']-1]:''}).ok)continue;
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
      id: './',
      name: CONFIG.APP_NAME,
      short_name: 'TAICIMASTER',
      description: 'Sistem Perkembangan Santri - TAICIMASTER FM',
      start_url: './',
      scope: './',
      display: 'standalone',
      orientation: 'portrait-primary',
      background_color: '#F8FAFC',
      theme_color: CONFIG.THEME_COLOR,
      icons: [
        { src: 'https://appfathanmubina.github.io/fm-taicimaster/assets/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
        { src: 'https://appfathanmubina.github.io/fm-taicimaster/assets/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' }
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
    var classSantriList = [], santriClassMap = {}, santriGenderMap = {}, santriVisibleMap = {};
    var santriMap = sheetSantri ? headerMap(sheetSantri) : {};
    for (var i = 1; i < santriData.length; i++) {
      var nama = String(santriMap['Nama_Santri'] ? santriData[i][santriMap['Nama_Santri']-1] : santriData[i][2] || '').trim();
      var kelas = String(santriMap['Kelas'] ? santriData[i][santriMap['Kelas']-1] : santriData[i][3] || '').trim();
      var gender = santriMap['Jenis_Kelamin'] ? santriData[i][santriMap['Jenis_Kelamin']-1] : '';
      if (!nama) continue;
      santriClassMap[nama.toLowerCase()] = kelas;
      santriGenderMap[nama.toLowerCase()] = gender;
      var allowedStudent=assertSantriAccess_(_session,{kelas:kelas,jenisKelamin:gender}).ok &&
        (role!=='walikelas'||aksesKelas==='All'||aksesKelas===''||kelas.toLowerCase()===String(aksesKelas).trim().toLowerCase());
      if(allowedStudent){santriVisibleMap[nama.toLowerCase()]=true;classSantriList.push(nama);}
    }

    var totalSantri = classSantriList.length;
    function countVisibleRows(sheet, nameHeader) {
      if(!sheet||sheet.getLastRow()<=1)return 0;
      var rows=sheet.getDataRange().getValues(),m=headerMap(sheet),col=m[nameHeader]||2,count=0;
      for(var ri=1;ri<rows.length;ri++){var n=String(rows[ri][col-1]||'').trim().toLowerCase();if(n&&santriVisibleMap[n])count++;}
      return count;
    }
    var totalPrestasi = countVisibleRows(sheetPrestasi,'Nama_Santri');
    var totalPelanggaran = countVisibleRows(sheetPelanggaran,'Nama_Santri');
    var recentActivities = [];
    var search = String(searchName || '').trim().toLowerCase();
    var filter = String(filterType || 'ALL').toUpperCase();

    function visible(name, type) {
      var n = String(name || '').trim();
      var classAllowed = !!santriVisibleMap[n.toLowerCase()];
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
    var targetSantri=getSantriRecordByName_(santriNama),targetAccess=assertSantriAccess_(_session,targetSantri);if(!targetAccess.ok)return targetAccess;
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
    var classMap={},genderMap={}, san=ss.getSheetByName('Data_Santri');
    if(san){var sd=san.getDataRange().getValues(),sm=headerMap(san);for(var i=1;i<sd.length;i++){var n=sm['Nama_Santri']?String(sd[i][sm['Nama_Santri']-1]||'').trim():'';var k=sm['Kelas']?String(sd[i][sm['Kelas']-1]||'').trim():'';if(n){classMap[n.toLowerCase()]=k;genderMap[n.toLowerCase()]=sm['Jenis_Kelamin']?sd[i][sm['Jenis_Kelamin']-1]:'';}}}
    function dk(v){if(!v)return '';var d=v instanceof Date?v:new Date(v);if(isNaN(d.getTime())){var m=String(v).match(/^(\d{4})[-\/](\d{1,2})[-\/](\d{1,2})/);return m?m[1]+'-'+('0'+m[2]).slice(-2)+'-'+('0'+m[3]).slice(-2):'';}return Utilities.formatDate(d,tz,'yyyy-MM-dd');}
    function allowed(n,k){var key=String(n||'').trim().toLowerCase(),kelas=String(k||classMap[key]||'').trim();var scopeCheck=assertSantriAccess_(session,{kelas:kelas,jenisKelamin:genderMap[key]||''});if(!scopeCheck.ok)return false;var target=String(session.aksesKelas||'All').trim();return session.role!=='walikelas'||!target||target==='All'||kelas.toLowerCase()===target.toLowerCase();}
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
  var m=headerMap(sheet), nameCol=m['Nama_Santri'], classCol=m['Kelas'], idCol=m['ID_Santri'], genderCol=m['Jenis_Kelamin'];
  if(!nameCol || !classCol) return null;
  var target=normalizeText_(nama).toLowerCase(), data=sheet.getDataRange().getValues();
  for(var i=1;i<data.length;i++) if(normalizeText_(data[i][nameCol-1]).toLowerCase()===target) {
    return {row:i+1,id:idCol?normalizeText_(data[i][idCol-1]):'',nama:normalizeText_(data[i][nameCol-1]),kelas:normalizeText_(data[i][classCol-1]),jenisKelamin:genderCol?normalizeStudentGender_(data[i][genderCol-1]):''};
  }
  return null;
}

function normalizeSantriScope_(value) {
  var v=String(value||'ALL').trim().toUpperCase();
  if(v==='PUTRA'||v==='L'||v==='LAKI-LAKI'||v==='LAKI LAKI')return 'PUTRA';
  if(v==='PUTRI'||v==='P'||v==='PEREMPUAN'||v==='WANITA')return 'PUTRI';
  return 'ALL';
}
function normalizeStudentGender_(value) {
  var v=String(value||'').trim().toUpperCase();
  if(/^(L|LAKI[- ]?LAKI|PUTRA|MALE|PRIA)$/.test(v))return 'PUTRA';
  if(/^(P|PEREMPUAN|PUTRI|FEMALE|WANITA)$/.test(v))return 'PUTRI';
  return '';
}
function assertSantriAccess_(session, santri) {
  if (!session) return {ok:false,message:'Sesi tidak valid.'};
  if (!santri) return {ok:false,message:'Santri tidak ditemukan.'};
  var scope=normalizeSantriScope_(session.lingkupSantri);
  if(scope!=='ALL') {
    var gender=normalizeStudentGender_(santri.jenisKelamin||santri.jenis_kelamin||santri.gender);
    if(!gender || gender!==scope)return {ok:false,message:'Akses dibatasi untuk santri '+(scope==='PUTRA'?'Putra':'Putri')+'.'};
  }
  if (session.role==='walikelas' && normalizeText_(session.aksesKelas)!=='All' && normalizeText_(session.aksesKelas).toLowerCase()!==normalizeText_(santri.kelas).toLowerCase()) return {ok:false,message:'Anda tidak memiliki akses ke kelas santri tersebut.'};
  return {ok:true};
}


/** Stage 11.19 — server-side scope index for transaction rows. */
function buildSantriScopeIndex_() {
  var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri');
  var out={byId:{},byName:{}};
  if(!sh || sh.getLastRow()<=1) return out;
  var d=sh.getDataRange().getValues(),m=headerMap(sh),idCol=m['ID_Santri']||0,nameCol=m['Nama_Santri']||0,classCol=m['Kelas']||0,genderCol=m['Jenis_Kelamin']||0;
  if(!nameCol || !classCol) return out;
  for(var i=1;i<d.length;i++){
    var id=idCol?normalizeText_(d[i][idCol-1]):'', name=normalizeText_(d[i][nameCol-1]), kelas=normalizeText_(d[i][classCol-1]);
    if(!name || !kelas) continue;
    var rec={id:id,nama:name,kelas:kelas,jenisKelamin:genderCol?normalizeStudentGender_(d[i][genderCol-1]):''};
    if(id) out.byId[id]=rec;
    out.byName[name.toLowerCase()]=rec;
  }
  return out;
}

function assertTransactionRowAccess_(session,row,rowMap,index) {
  if(!session) return {ok:false,message:'Sesi tidak valid.'};
  var needsClass=session.role==='walikelas' && normalizeText_(session.aksesKelas)!=='All';
  var needsGender=normalizeSantriScope_(session.lingkupSantri)!=='ALL';
  if(!needsClass && !needsGender)return {ok:true};
  var id=rowMap && rowMap['ID_Santri'] ? normalizeText_(row[rowMap['ID_Santri']-1]) : '';
  var nama=rowMap && rowMap['Nama_Santri'] ? normalizeText_(row[rowMap['Nama_Santri']-1]) : '';
  var idx=index || buildSantriScopeIndex_();
  var st=(id && idx.byId[id]) || (nama && idx.byName[nama.toLowerCase()]);
  if(!st) return {ok:false,message:'Santri pada data tidak ditemukan dalam Data_Santri.'};
  var check=assertSantriAccess_(session,st); if(!check.ok)return check;
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
  var tempFile = null;
  var tempDocId = null;
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

    var tz = Session.getScriptTimeZone() || 'Asia/Jakarta';
    var now = new Date();
    var stamp = Utilities.formatDate(now, tz, 'yyyyMMdd_HHmmss');
    var safeFilter = String((santriName || filterLabel || 'ALL')).replace(/[^a-zA-Z0-9_-]+/g,'_').substring(0,60);
    var fileName = 'TAICIMASTER_' + modeU + '_' + safeFilter + '_' + stamp;

    // Google Docs dipakai hanya sebagai dokumen sementara agar format laporan tetap konsisten.
    // Tidak membuat folder laporan dan tidak menyimpan PDF hasil ekspor ke Drive.
    var doc = DocumentApp.create(fileName);
    tempDocId = doc.getId();
    tempFile = DriveApp.getFileById(tempDocId);
    var body = doc.getBody();
    body.setMarginTop(36).setMarginBottom(36).setMarginLeft(42).setMarginRight(42);
    appendReportBranding_(body, doc);
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

    var meta = body.appendParagraph('Dicetak: ' + Utilities.formatDate(now, tz, 'dd MMMM yyyy, HH:mm:ss') +
      '  •  Mode: ' + modeU +
      (filterLabel && filterLabel.toUpperCase() !== 'ALL' ? '  •  Kelas: ' + filterLabel : ''));
    meta.setAlignment(DocumentApp.HorizontalAlignment.CENTER);
    meta.setForegroundColor('#64748B').setFontSize(8);
    appendReportSummary_(body, data, modeU, filterLabel, santriName, tz);

    if (modeU === 'KELAS') {
      data.forEach(function(x, idx){ appendClassSection_(body, x, idx + 1); });
    } else {
      data.forEach(function(x, idx){ appendStudentSection_(body, x, idx + 1); });
    }
    var footer = doc.getFooter() || doc.addFooter();
    footer.clear();
    footer.appendParagraph(CONFIG.APP_NAME + ' • Laporan resmi • ' + Utilities.formatDate(now, tz, 'dd/MM/yyyy HH:mm:ss'))
      .setAlignment(DocumentApp.HorizontalAlignment.CENTER).setForegroundColor('#64748B').setFontSize(8);
    body.appendParagraph('Dokumen ini dihasilkan oleh ' + CONFIG.APP_NAME + ' dan diunduh langsung oleh pengguna.')
      .setForegroundColor('#64748B').setFontSize(8);
    doc.saveAndClose();

    var pdfBlob = tempFile.getAs(MimeType.PDF).setName(fileName + '.pdf');
    var pdfBase64 = Utilities.base64Encode(pdfBlob.getBytes());
    auditLog_(auth.session, 'GENERATE_REPORT_PDF', 'REPORT', fileName + '.pdf|' + modeU + '|TEMP_DOC_DIRECT_DOWNLOAD');
    return {success:true,name:fileName + '.pdf',mimeType:'application/pdf',base64:pdfBase64,mode:modeU};
  } catch (e) {
    return {success:false,message:'Pembuatan PDF gagal: ' + e.toString()};
  } finally {
    // Dokumen Google sementara selalu dibersihkan, termasuk saat konversi gagal.
    if (tempDocId) {
      try {
        (tempFile || DriveApp.getFileById(tempDocId)).setTrashed(true);
      } catch (cleanupError) {
        console.error('Gagal membersihkan dokumen PDF sementara: ' + cleanupError);
      }
    }
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
function simpanKesehatan(data,token){var a=requireCapability_(token,'kesehatan.create');if(!a.ok)return a.response;var d=data||{},req=requireFields_(d,['santriNama','tanggal','keluhan']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama);if(!st)return {success:false,message:'Santri tidak ditemukan.'};var access=assertSantriAccess_(a.session,st);if(!access.ok)return {success:false,message:access.message};if(!normalizeDateInput_(d.tanggal))return {success:false,message:'Tanggal pemeriksaan tidak valid.'};if(!cacheDuplicateGuard_('KESEHATAN',a.session.id,{santri:st.id||st.nama,tanggal:d.tanggal,keluhan:d.keluhan}))return {success:false,code:'DUPLICATE_REQUEST',message:'Permintaan yang sama baru saja diproses. Hindari klik dua kali.'};try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan'),m=headerMap(sh),now=new Date(),id=generateRecordId_('KES'),vals={'ID_Kesehatan':id,'Nama_Santri':st.nama,'Kelas':st.kelas,'Tanggal':d.tanggal,'Keluhan':normalizeText_(d.keluhan,1000),'Pemeriksaan':normalizeText_(d.pemeriksaan,2000),'Diagnosa':normalizeText_(d.diagnosa,1000),'Tindakan':normalizeText_(d.tindakan,2000),'Obat':normalizeText_(d.obat,1000),'Suhu':d.suhu||'','Berat_Badan':d.beratBadan||'','Status':normalizeText_(d.status,100),'Tindak_Lanjut':normalizeText_(d.tindakLanjut,1000),'Status_Kesehatan':'Belum Sehat','Created_By':a.session.name,'Created_At':now};var row=new Array(sh.getLastColumn()).fill('');Object.keys(vals).forEach(function(h){if(m[h])row[m[h]-1]=vals[h];});if(m['ID_Santri'])row[m['ID_Santri']-1]=st.id;if(m['Updated_At'])row[m['Updated_At']-1]=now;if(m['Updated_By'])row[m['Updated_By']-1]=a.session.name;sh.appendRow(row);auditLog_(a.session,'CREATE_KESEHATAN',id,'Santri='+st.id);queueNewDataPush_('KESEHATAN',st,id,'Approved',a.session);try{queueWhatsAppNotification_('KESEHATAN',st,id,{category:'Pemeriksaan Kesehatan',status:d.status||'Tercatat',detail:d.keluhan},a.session);}catch(e){}return {success:true,idKesehatan:id,message:'Data pemeriksaan kesehatan berhasil disimpan.'};});}catch(e){return {success:false,message:e.toString()};}}
function getKesehatanList(role,aksesKelas,token){
  var a=requireCapability_(token,'kesehatan.view');
  if(!a.ok)return a.response;
  var sess=a.session;
  try{
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan');
    if(!sh)return {success:false,message:'Sheet Trx_Kesehatan tidak ditemukan. Jalankan inisialisasi database terlebih dahulu.'};
    var m=headerMap(sh),lastRow=sh.getLastRow(),lastCol=sh.getLastColumn(),o=[],scopeIndex=buildSantriScopeIndex_();
    if(lastRow<2)return {success:true,data:[]};
    function gv(row,name){return m[name]?row[m[name]-1]:'';}
    function pushRow(row){
      var nama=String(gv(row,'Nama_Santri')||'').trim();
      if(!nama)return;
      var kelas=String(gv(row,'Kelas')||'').trim();
      if(!assertTransactionRowAccess_(sess,row,m,scopeIndex).ok)return;
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
 var a=requireCapability_(token,'kesehatan.edit');if(!a.ok)return a.response;var d=data||{},req=requireFields_(d,['id','santriNama','tanggal','keluhan']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama);if(!st)return {success:false,message:'Santri tidak ditemukan.'};var access=assertSantriAccess_(a.session,st);if(!access.ok)return {success:false,message:access.message};
 try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Kesehatan']-1])===String(d.id)){var rowAccess=assertTransactionRowAccess_(a.session,rows[i],m);if(!rowAccess.ok)return {success:false,message:rowAccess.message};var vals={'Nama_Santri':st.nama,'Kelas':st.kelas,'Tanggal':d.tanggal,'Keluhan':normalizeText_(d.keluhan,1000),'Pemeriksaan':normalizeText_(d.pemeriksaan,2000),'Diagnosa':normalizeText_(d.diagnosa,1000),'Tindakan':normalizeText_(d.tindakan,2000),'Obat':normalizeText_(d.obat,1000),'Suhu':d.suhu||'','Berat_Badan':d.beratBadan||'','Status':normalizeText_(d.status,100),'Tindak_Lanjut':normalizeText_(d.tindakLanjut,1000)};Object.keys(vals).forEach(function(h){if(m[h])sh.getRange(i+1,m[h]).setValue(vals[h]);});if(m['ID_Santri'])sh.getRange(i+1,m['ID_Santri']).setValue(st.id);if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(new Date());if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(a.session.name);auditLog_(a.session,'UPDATE_KESEHATAN',String(d.id),'Santri='+st.id);return {success:true,message:'Data Kesehatan berhasil diperbarui.'};}return {success:false,message:'Data Kesehatan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}

function bulkMarkKesehatanRecovered(ids,token){
  var a=requireCapability_(token,'kesehatan.edit');if(!a.ok)return a.response;
  ids=Array.isArray(ids)?ids.map(String).filter(Boolean):[];if(!ids.length)return {success:false,message:'Pilih minimal satu data kesehatan.'};
  try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan'),m=headerMap(sh),rows=sh.getDataRange().getValues(),set={};ids.forEach(function(id){set[id]=true;});var count=0,now=new Date();
    for(var i=1;i<rows.length;i++){var id=String(rows[i][m['ID_Kesehatan']-1]||'');if(!set[id])continue;var access=assertTransactionRowAccess_(a.session,rows[i],m);if(!access.ok)return {success:false,message:access.message};
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

function deleteKesehatan(id,token){var a=requireCapability_(token,'kesehatan.delete');if(!a.ok)return a.response;try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Kesehatan'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Kesehatan']-1])===String(id)){var access=assertTransactionRowAccess_(a.session,rows[i],m);if(!access.ok)return {success:false,message:access.message};sh.deleteRow(i+1);auditLog_(a.session,'DELETE_KESEHATAN',String(id),'');return {success:true,message:'Data Kesehatan berhasil dihapus.'};}return {success:false,message:'Data Kesehatan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}


/* ===== BEGIN Pelanggaran.gs ===== */
/** TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0 — Pelanggaran */
function simpanPelanggaran(formData,fileObj,token){var a=requireCapability_(token,'pelanggaran.create');if(!a.ok)return a.response;var s=a.session,d=formData||{},req=requireFields_(d,['santriNama','tanggal','jenisPelanggaran','deskripsi']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama),ac=assertSantriAccess_(s,st);if(!ac.ok)return {success:false,message:ac.message};if(!normalizeDateInput_(d.tanggal))return {success:false,message:'Tanggal pelanggaran tidak valid.'};if(!cacheDuplicateGuard_('PELANGGARAN',s.id,{santri:st.id||st.nama,tanggal:d.tanggal,jenis:d.jenisPelanggaran,deskripsi:d.deskripsi}))return {success:false,code:'DUPLICATE_REQUEST',message:'Permintaan yang sama baru saja diproses. Hindari klik dua kali.'};try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Pelanggaran'),m=headerMap(sh),url='',now=new Date();if(fileObj&&fileObj.data){var f=DriveApp.getFolderById(CONFIG.DRIVE_PELANGGARAN_FOLDER_ID);url=f.createFile(Utilities.newBlob(Utilities.base64Decode(fileObj.data),fileObj.mimeType||'application/octet-stream',normalizeText_(fileObj.fileName,150)||('bukti-'+generateRecordId_('PLG')))).getUrl();}var id=generateRecordId_('PLG'),vals={'ID_Pelanggaran':id,'Nama_Santri':st.nama,'Tanggal':d.tanggal,'Jenis_Pelanggaran':normalizeText_(d.jenisPelanggaran,100),'Tingkat_Pelanggaran':normalizeText_(d.tingkatPelanggaran,100),'Deskripsi':normalizeText_(d.deskripsi,2000),'Kronologi':normalizeText_(d.kronologi,3000),'Tindak_Pembinaan':normalizeText_(d.tindakPembinaan,2000),'Tindak_Lanjut':normalizeText_(d.tindakLanjut,2000),'Link_Bukti':url,'Status_Approval':'Approved','Created_By':a.session.name};var row=new Array(sh.getLastColumn()).fill('');Object.keys(vals).forEach(function(h){if(m[h])row[m[h]-1]=vals[h];});if(m['ID_Santri'])row[m['ID_Santri']-1]=st.id;if(m['Created_At'])row[m['Created_At']-1]=now;if(m['Updated_At'])row[m['Updated_At']-1]=now;if(m['Updated_By'])row[m['Updated_By']-1]=a.session.name;sh.appendRow(row);auditLog_(a.session,'CREATE_PELANGGARAN',id,'Santri='+st.id);try{sendNotificationEmail('PELANGGARAN',st.nama,d.jenisPelanggaran+' (Tingkat '+d.tingkatPelanggaran+')',d.deskripsi,token);}catch(e){}
queueNewDataPush_('PELANGGARAN',st,id,'Approved',a.session);try{queueWhatsAppNotification_('PELANGGARAN',st,id,{category:d.jenisPelanggaran,status:'Tercatat',detail:d.deskripsi},a.session);}catch(e){}return {success:true,idPelanggaran:id,message:'Data Pelanggaran Berhasil Disimpan!'};});}catch(e){return {success:false,message:'Gagal menyimpan data: '+e.toString()};}}

function getPelanggaranList(token){
  var a=requireCapability_(token,'pelanggaran.view'); if(!a.ok)return a.response;
  try{
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Pelanggaran');
    if(!sh)return {success:true,data:[]};
    var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[],scopeIndex=buildSantriScopeIndex_();
    for(var i=d.length-1;i>=1;i--){
      var access=assertTransactionRowAccess_(a.session,d[i],m,scopeIndex);if(!access.ok)continue;
      var sid=m['ID_Santri']?String(d[i][m['ID_Santri']-1]||'').trim():'';
      var nm=String(d[i][m['Nama_Santri']-1]||'').trim().toLowerCase();
      var student=(sid&&scopeIndex.byId[sid])||scopeIndex.byName[nm]||null;
      var kelas=String((m['Kelas']?d[i][m['Kelas']-1]:'')||student&&student.kelas||'').trim();
      o.push({id:d[i][m['ID_Pelanggaran']-1],santriNama:d[i][m['Nama_Santri']-1],kelas:kelas,tanggal:d[i][m['Tanggal']-1]?Utilities.formatDate(new Date(d[i][m['Tanggal']-1]),Session.getScriptTimeZone(),'yyyy-MM-dd'):'',jenisPelanggaran:d[i][m['Jenis_Pelanggaran']-1],tingkatPelanggaran:d[i][m['Tingkat_Pelanggaran']-1],deskripsi:d[i][m['Deskripsi']-1],kronologi:d[i][m['Kronologi']-1],tindakPembinaan:d[i][m['Tindak_Pembinaan']-1],tindakLanjut:d[i][m['Tindak_Lanjut']-1]});
    }
    return {success:true,data:o};
  }catch(e){return {success:false,message:e.toString()};}
}
function updatePelanggaran(data,token){
 var a=requireCapability_(token,'pelanggaran.edit');if(!a.ok)return a.response;var d=data||{},req=requireFields_(d,['id','santriNama','tanggal','jenisPelanggaran','deskripsi']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama);if(!st)return {success:false,message:'Santri tidak ditemukan.'};var targetAccess=assertSantriAccess_(a.session,st);if(!targetAccess.ok)return {success:false,message:targetAccess.message};if(!normalizeDateInput_(d.tanggal))return {success:false,message:'Tanggal tidak valid.'};
 try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Pelanggaran'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Pelanggaran']-1])===String(d.id)){var rowAccess=assertTransactionRowAccess_(a.session,rows[i],m);if(!rowAccess.ok)return {success:false,message:rowAccess.message};var vals={'Nama_Santri':st.nama,'Tanggal':d.tanggal,'Jenis_Pelanggaran':normalizeText_(d.jenisPelanggaran,100),'Tingkat_Pelanggaran':normalizeText_(d.tingkatPelanggaran,100),'Deskripsi':normalizeText_(d.deskripsi,2000),'Kronologi':normalizeText_(d.kronologi,3000),'Tindak_Pembinaan':normalizeText_(d.tindakPembinaan,2000),'Tindak_Lanjut':normalizeText_(d.tindakLanjut,2000)};Object.keys(vals).forEach(function(h){if(m[h])sh.getRange(i+1,m[h]).setValue(vals[h]);});if(m['ID_Santri'])sh.getRange(i+1,m['ID_Santri']).setValue(st.id);if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(new Date());if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(a.session.name);auditLog_(a.session,'UPDATE_PELANGGARAN',String(d.id),'Santri='+st.id);return {success:true,message:'Data Pelanggaran berhasil diperbarui.'};}return {success:false,message:'Data Pelanggaran tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
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
  var santriAccess=assertSantriAccess_(auth.session,santri);if(!santriAccess.ok)return {success:false,message:santriAccess.message};
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
    ['Status_Kembali','Returned_At','Returned_By'].forEach(function(h){ensureColumn(sh,h);});var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[],scopeIndex=buildSantriScopeIndex_();
    function gv(row,name){return m[name]?row[m[name]-1]:'';}
    for(var i=d.length-1;i>=1;i--){
      if(!assertTransactionRowAccess_(s,d[i],m,scopeIndex).ok)continue;
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
  ids=Array.isArray(ids)?Array.from(new Set(ids.map(function(id){return String(id||'').trim();}).filter(Boolean))):[];
  if(!ids.length)return {success:false,message:'Pilih minimal satu data perizinan.'};
  try{return withDataLock_(function(){
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Perizinan');
    if(!sh)return {success:false,message:'Sheet Trx_Perizinan tidak ditemukan.'};
    ['Status_Kembali','Returned_At','Returned_By','Updated_At','Updated_By'].forEach(function(h){ensureColumn(sh,h);});
    var m=headerMap(sh),rows=sh.getDataRange().getValues(),wanted={},matched={},targets=[];
    if(!m['ID_Perizinan'])return {success:false,message:'Kolom ID_Perizinan tidak ditemukan.'};
    ids.forEach(function(id){wanted[id]=true;});
    for(var i=1;i<rows.length;i++){
      var id=String(rows[i][m['ID_Perizinan']-1]||'').trim();
      if(!wanted[id])continue;
      var access=assertTransactionRowAccess_(a.session,rows[i],m);
      if(!access.ok)return {success:false,message:access.message};
      targets.push(i+1);matched[id]=true;
    }
    var missing=ids.filter(function(id){return !matched[id];});
    if(missing.length)return {success:false,message:'Sebagian data perizinan tidak ditemukan atau sudah tidak dapat diakses. Tidak ada perubahan yang diterapkan.'};
    if(targets.length!==ids.length)return {success:false,message:'Jumlah data yang cocok tidak sesuai. Tidak ada perubahan yang diterapkan.'};
    var now=new Date();
    targets.forEach(function(row){
      sh.getRange(row,m['Status_Kembali']).setValue('Sudah Kembali');
      sh.getRange(row,m['Returned_At']).setValue(now);
      sh.getRange(row,m['Returned_By']).setValue(a.session.name);
      if(m['Updated_At'])sh.getRange(row,m['Updated_At']).setValue(now);
      if(m['Updated_By'])sh.getRange(row,m['Updated_By']).setValue(a.session.name);
    });
    SpreadsheetApp.flush();
    auditLog_(a.session,'BULK_RETURN_PERIZINAN',ids.join(','),'Jumlah='+targets.length);
    return {success:true,count:targets.length,updatedIds:ids,message:targets.length+' data santri berhasil ditandai sudah kembali.'};
  });}catch(e){return {success:false,message:'Gagal memperbarui status kembali: '+e.toString()};}
}

function deletePerizinan(id,token){var a=requireCapability_(token,'perizinan.delete');if(!a.ok)return a.response;try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Perizinan'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Perizinan']-1])===String(id)){var access=assertTransactionRowAccess_(a.session,rows[i],m);if(!access.ok)return {success:false,message:access.message};sh.deleteRow(i+1);auditLog_(a.session,'DELETE_PERIZINAN',String(id),'');return {success:true,message:'Data Perizinan berhasil dihapus.'};}return {success:false,message:'Data Perizinan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
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
function updatePrestasiApprovalStatus(idPrestasi,newStatus,token){var a=requireCapability_(token,'prestasi.approve');if(!a.ok)return a.response;if(['Approved','Rejected'].indexOf(newStatus)<0)return {success:false,message:'Status approval tidak valid.'};try{return withDataLock_(function(){var s=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Prestasi'),m=headerMap(s),d=s.getDataRange().getValues();for(var i=1;i<d.length;i++)if(String(d[i][m['ID_Prestasi']-1])===String(idPrestasi)){var rowAccess=assertTransactionRowAccess_(a.session,d[i],m);if(!rowAccess.ok)return {success:false,message:rowAccess.message};var previousStatus=String(d[i][m['Status_Approval']-1]||'');s.getRange(i+1,m['Status_Approval']).setValue(newStatus);if(m['Updated_At'])s.getRange(i+1,m['Updated_At']).setValue(new Date());if(m['Updated_By'])s.getRange(i+1,m['Updated_By']).setValue(a.session.name);auditLog_(a.session,'UPDATE_PRESTASI_APPROVAL',String(idPrestasi),'Status='+newStatus);
        try{var st=getSantriRecordByName_(d[i][m['Nama_Santri']-1]); if(newStatus==='Approved' && previousStatus!=='Approved')queueNewDataPush_('PRESTASI',st,String(idPrestasi),'Approved',a.session); else if(newStatus==='Rejected' && previousStatus!=='Rejected')queueNewDataPush_('PRESTASI',st,String(idPrestasi),'Rejected',a.session); queueWhatsAppNotification_('PRESTASI_APPROVAL',st,String(idPrestasi),{category:'Persetujuan Prestasi',status:newStatus,detail:'Status prestasi diperbarui.'},a.session);}catch(e){}
        return {success:true,message:'Status persetujuan prestasi berhasil diperbarui menjadi: '+newStatus};}return {success:false,message:'ID Prestasi tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}}

function getPrestasiList(token){
  var a=requireCapability_(token,'prestasi.view'); if(!a.ok)return a.response;
  try{
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Prestasi'); if(!sh)return {success:true,data:[]};
    var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[],scopeIndex=buildSantriScopeIndex_();
    for(var i=d.length-1;i>=1;i--){ var access=assertTransactionRowAccess_(a.session,d[i],m,scopeIndex); if(!access.ok) continue; o.push({
      id:d[i][m['ID_Prestasi']-1],santriNama:d[i][m['Nama_Santri']-1],
      kelas:(function(){var sid=m['ID_Santri']?String(d[i][m['ID_Santri']-1]||'').trim():'';var nm=String(d[i][m['Nama_Santri']-1]||'').trim().toLowerCase();var st=(sid&&scopeIndex.byId[sid])||scopeIndex.byName[nm];return st?st.kelas:'';})(),
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
      var rowAccess=assertTransactionRowAccess_(a.session,rows[i],m);if(!rowAccess.ok)return {success:false,message:rowAccess.message};
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
    var rows=sh.getDataRange().getValues(), m=headerMap(sh), idxK=m['Kelas']-1, idxGender=(m['Jenis_Kelamin']||0)-1;
    if(idxK<0)return {success:false,message:'Kolom Kelas pada Data_Santri tidak ditemukan.'};
    var map={};
    for(var i=1;i<rows.length;i++){
      var k=String(rows[i][idxK]||'').trim(); if(!k)continue;
      if(!assertSantriAccess_(session,{kelas:k,jenisKelamin:idxGender>=0?rows[i][idxGender]:''}).ok)continue;
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
    var rows=sh.getDataRange().getValues(), sm=headerMap(sh), ni=(sm['Nama_Santri']||0)-1, ki=(sm['Kelas']||0)-1, gi=(sm['Jenis_Kelamin']||0)-1;
    if(ni<0||ki<0)return {success:false,message:'Kolom Nama_Santri/Kelas pada Data_Santri tidak ditemukan.'};
    var wanted=String(kelasFilter||'ALL').trim().toLowerCase(), siswa=[];
    for(var i=1;i<rows.length;i++){
      var nama=String(rows[i][ni]||'').trim(), kelas=String(rows[i][ki]||'').trim(); if(!nama)continue;
      if(!assertSantriAccess_(session,{kelas:kelas,jenisKelamin:gi>=0?rows[i][gi]:''}).ok)continue;
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
    var rows=sh.getDataRange().getValues(), sm=headerMap(sh), ni=(sm['Nama_Santri']||0)-1,ki=(sm['Kelas']||0)-1,gi=(sm['Jenis_Kelamin']||0)-1;if(ni<0||ki<0)return {success:false,message:'Kolom Nama_Santri/Kelas pada Data_Santri tidak ditemukan.'};
    var classes={},nameToClass={};
    for(var i=1;i<rows.length;i++){var nama=String(rows[i][ni]||'').trim(),kelas=String(rows[i][ki]||'').trim();if(!kelas)continue;if(!assertSantriAccess_(session,{kelas:kelas,jenisKelamin:gi>=0?rows[i][gi]:''}).ok)continue;if(session.role==='walikelas'&&session.aksesKelas!=='All'&&kelas.toLowerCase()!==String(session.aksesKelas||'').trim().toLowerCase())continue;if(!classes[kelas])classes[kelas]={kelas:kelas,santri:0,prestasi:[],pelanggaran:[],catatanWali:[],perizinan:[],kesehatan:[]};classes[kelas].santri++;if(nama)nameToClass[nama.toLowerCase()]=kelas;}
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
  var rows=sh.getDataRange().getValues(),m=headerMap(sh);
  for(var i=1;i<rows.length;i++){
    var name=String(m['Nama_Santri']?rows[i][m['Nama_Santri']-1]:rows[i][2]||'').trim();
    var kelas=String(m['Kelas']?rows[i][m['Kelas']-1]:rows[i][3]||'').trim();
    var gender=m['Jenis_Kelamin']?rows[i][m['Jenis_Kelamin']-1]:'';
    if(!name || !assertSantriAccess_(session,{kelas:kelas,jenisKelamin:gender}).ok) continue;
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
  return {success:true,version:ROLE_PERMISSION_VERSION,role:role,label:ROLE_PERMISSIONS[role].label,scope:ROLE_PERMISSIONS[role].scope,lingkupSantri:normalizeSantriScope_(auth.session.lingkupSantri),capabilities:ROLE_PERMISSIONS[role].capabilities.slice()};
}

function validateUserRole_(role) {
  return !!normalizeRole_(role);
}


/* ===== BEGIN Santri.gs ===== */
/** TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0 — Santri */
function getSantriList(role,aksesKelas,token){var a=requireCapability_(token,'santri.view');if(!a.ok)return a.response;var s=a.session;try{var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Santri');if(!sh)return {success:false,message:'Sheet Data_Santri tidak ditemukan.'};var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[];for(var i=1;i<d.length;i++){var st={kelas:normalizeText_(m['Kelas']?d[i][m['Kelas']-1]:''),jenisKelamin:m['Jenis_Kelamin']?d[i][m['Jenis_Kelamin']-1]:''};if(!assertSantriAccess_(s,st).ok)continue;o.push({id:m['ID_Santri']?d[i][m['ID_Santri']-1]:'',nisn:m['NISN']?d[i][m['NISN']-1]:'',nama:m['Nama_Santri']?d[i][m['Nama_Santri']-1]:'',kelas:st.kelas,waliKelas:m['Wali_Kelas']?d[i][m['Wali_Kelas']-1]:''});}return {success:true,data:o};}catch(e){return {success:false,message:e.toString()};}}
function getStudentClass(nama,token){var a=requireCapability_(token,'santri.view');if(!a.ok)return '';var s=getSantriRecordByName_(nama);if(!s)return '';if(!assertSantriAccess_(a.session,s).ok)return '';return s.kelas||'';}


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
  var payload = { id:String(user.id), name:String(user.name), email:String(user.email), role:canonicalRole, aksesKelas:String(user.aksesKelas || 'All'), lingkupSantri:normalizeSantriScope_(user.lingkupSantri), waliSantriIds:String(user.waliSantriIds || ''), createdAt:Date.now(), expiresAt:Date.now()+SECURITY.SESSION_TTL_SECONDS*1000 };
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
      lingkupSantri:normalizeSantriScope_(um['Lingkup_Santri']?row[um['Lingkup_Santri']-1]:'ALL'),
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
  return {success:true,user:{id:r.session.id,name:r.session.name,email:r.session.email,role:r.session.role,aksesKelas:r.session.aksesKelas,lingkupSantri:normalizeSantriScope_(r.session.lingkupSantri)}};
}

function initializeSecurityDatabase_() {
  var ss=SpreadsheetApp.getActiveSpreadsheet();
  var user=ss.getSheetByName('Data_Users');
  if (user) ['Password_Salt','Failed_Login_Count','Locked_Until','Last_Login_At','Lingkup_Santri'].forEach(function(h){ensureColumn(user,h);});
  var audit=ss.getSheetByName('Audit_Log');
  if (!audit) { audit=ss.insertSheet('Audit_Log'); audit.appendRow(['ID_Audit','Timestamp','User_ID','User_Name','Role','Action','Target','Detail']); audit.getRange(1,1,1,8).setFontWeight('bold').setBackground('#7E22CE').setFontColor('#FFFFFF'); }
  return {success:true,message:'Security database siap.'};
}


/* ===== BEGIN Users.gs ===== */
/** TAICIMASTER FM — Stage 2 Security FINAL v2.0 — User Management */
function getUserList(token) {
  try { var auth=requireCapability_(token,'user.manage'); if(!auth.ok)return auth.response;
    var sheet=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Users'),data=sheet.getDataRange().getValues(),users=[];
    var um=headerMap(sheet); for(var i=1;i<data.length;i++)users.push({id:data[i][0],nama:data[i][1],email:data[i][2],role:data[i][4],status:data[i][5],aksesKelas:data[i][6],lingkupSantri:normalizeSantriScope_(um['Lingkup_Santri']?data[i][um['Lingkup_Santri']-1]:'ALL')});
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
    withDataLock_(function(){ var m=headerMap(sheet), row=new Array(sheet.getLastColumn()).fill(''); var vals={'ID_User':idUser,'Nama':normalizeText_(userData.nama,150),'Email':email,'Password':makePasswordHash_(pass),'Role':userData.role||'walikelas','Status':'Aktif','Akses_Kelas':userData.aksesKelas||'All','Lingkup_Santri':normalizeSantriScope_(userData.lingkupSantri),'Password_Salt':'','Failed_Login_Count':0,'Locked_Until':'','Last_Login_At':'','ID_Santri_Wali':String(userData.idSantriWali||'').trim(),'Updated_At':new Date(),'Updated_By':auth.session.name}; Object.keys(vals).forEach(function(h){if(m[h])row[m[h]-1]=vals[h];}); sheet.appendRow(row); });
    auditLog_(auth.session,'CREATE_USER','USER',email); return {success:true,message:'Pengguna baru berhasil ditambahkan!'};
  }catch(e){return {success:false,message:'Gagal menambahkan user: '+e.toString()};}
}

function updateUserSantriScope(userId,scope,token){
  var auth=requireSessionResult_(token,['superadmin']);if(!auth.ok)return auth.response;
  scope=normalizeSantriScope_(scope);
  try{var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Data_Users');if(!sh)return {success:false,message:'Sheet Data_Users tidak ditemukan.'};var m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++){if(String(rows[i][m['ID_User']-1])!==String(userId))continue;if(!m['Lingkup_Santri'])ensureColumn(sh,'Lingkup_Santri');m=headerMap(sh);sh.getRange(i+1,m['Lingkup_Santri']).setValue(scope);if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(new Date());if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(auth.session.name);revokeRememberTokensForUser_(userId);var props=PropertiesService.getScriptProperties(),all=props.getProperties();Object.keys(all).forEach(function(key){if(key.indexOf(SECURITY.SESSION_PREFIX)!==0)return;try{var p=JSON.parse(all[key]);if(String(p.id)===String(userId))props.deleteProperty(key);}catch(ignore){}});auditLog_(auth.session,'UPDATE_USER_SCOPE',String(userId),'Lingkup='+scope+'; sesi aktif dicabut');return {success:true,message:'Lingkup akses pengguna diperbarui. Pengguna harus login kembali agar pembatasan baru berlaku.'};}return {success:false,message:'Pengguna tidak ditemukan.'};}catch(e){return {success:false,message:'Gagal memperbarui lingkup: '+e.toString()};}
}


/* ===== BEGIN Utils.gs ===== */
/**\n * TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0\n * Utilities
 */

function formatDateSafe(v){if(!v)return '';try{return Utilities.formatDate(new Date(v),Session.getScriptTimeZone(),'dd/MM/yyyy');}catch(e){return String(v);}}



/* ===== BEGIN WaliKelas.gs ===== */
/** TAICIMASTER FM — Stage 5 Dashboard, Rekapan Stage 4 Core Modules & Role Permission FINAL v4.0 Reporting FINAL v5.0 — Wali Kelas */
function simpanCatatanWaliKelas(data,token){var a=requireCapability_(token,'catatan_wali.create');if(!a.ok)return a.response;var d=data||{},req=requireFields_(d,['santriNama','tanggal','kategori','catatan']);if(!req.ok)return {success:false,message:req.message};var st=getSantriRecordByName_(d.santriNama),ac=assertSantriAccess_(a.session,st);if(!ac.ok)return {success:false,message:ac.message};if(!normalizeDateInput_(d.tanggal))return {success:false,message:'Tanggal catatan tidak valid.'};if(!cacheDuplicateGuard_('CATATAN_WALI',a.session.id,{santri:st.id||st.nama,tanggal:d.tanggal,kategori:d.kategori,catatan:d.catatan}))return {success:false,code:'DUPLICATE_REQUEST',message:'Permintaan yang sama baru saja diproses. Hindari klik dua kali.'};try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Catatan_Wali');if(!sh){sh=SpreadsheetApp.getActiveSpreadsheet().insertSheet('Trx_Catatan_Wali');sh.appendRow(['ID_Catatan','Nama_Santri','Kelas','Tanggal','Kategori','Catatan','Created_By']);}ensureColumn(sh,'ID_Santri');ensureColumn(sh,'Created_At');ensureColumn(sh,'Updated_At');ensureColumn(sh,'Updated_By');var m=headerMap(sh),id=generateRecordId_('CWK'),now=new Date(),row=new Array(sh.getLastColumn()).fill(''),vals={'ID_Catatan':id,'Nama_Santri':st.nama,'Kelas':st.kelas,'Tanggal':d.tanggal,'Kategori':normalizeText_(d.kategori,100),'Catatan':normalizeText_(d.catatan,3000),'Created_By':a.session.name};Object.keys(vals).forEach(function(h){if(m[h])row[m[h]-1]=vals[h];});row[m['ID_Santri']-1]=st.id;row[m['Created_At']-1]=now;row[m['Updated_At']-1]=now;row[m['Updated_By']-1]=a.session.name;sh.appendRow(row);auditLog_(a.session,'CREATE_CATATAN_WALI',id,'Santri='+st.id);queueNewDataPush_('CATATAN_WALI',st,id,'Approved',a.session);return {success:true,idCatatan:id,message:'Catatan Wali Kelas Berhasil Disimpan!'};});}catch(e){return {success:false,message:'Gagal menyimpan catatan: '+e.toString()};}}
function getRiwayatCatatanWaliKelas(aksesKelas,token){
  var a=requireCapability_(token,'catatan_wali.view');if(!a.ok)return a.response;
  var s=a.session;
  try{
    var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Catatan_Wali');
    if(!sh)return {success:true,data:[]};
    var d=sh.getDataRange().getValues(),m=headerMap(sh),o=[],scopeIndex=buildSantriScopeIndex_();
    for(var i=d.length-1;i>=1;i--){
      if(!assertTransactionRowAccess_(s,d[i],m,scopeIndex).ok)continue;
      var sid=m['ID_Santri']?String(d[i][m['ID_Santri']-1]||'').trim():'';
      var nm=String(d[i][m['Nama_Santri']-1]||'').trim().toLowerCase();
      var student=(sid&&scopeIndex.byId[sid])||scopeIndex.byName[nm]||null;
      var kelas=String((m['Kelas']?d[i][m['Kelas']-1]:'')||student&&student.kelas||'').trim();
      if(s.role==='walikelas'&&s.aksesKelas!=='All'&&kelas.toLowerCase()!==String(s.aksesKelas).toLowerCase())continue;
      o.push({idCatatan:d[i][m['ID_Catatan']-1],santriNama:d[i][m['Nama_Santri']-1],kelas:kelas,tanggal:d[i][m['Tanggal']-1]?Utilities.formatDate(new Date(d[i][m['Tanggal']-1]),Session.getScriptTimeZone(),'dd/MM/yyyy'):'',kategori:d[i][m['Kategori']-1],catatan:d[i][m['Catatan']-1],createdBy:d[i][m['Created_By']-1]});
    }
    return {success:true,data:o};
  }catch(e){return {success:false,message:e.toString()};}
}

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
  try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Catatan_Wali'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Catatan']-1])===String(d.idCatatan)){var rowAccess=assertTransactionRowAccess_(a.session,rows[i],m);if(!rowAccess.ok)return {success:false,message:rowAccess.message};var vals={'Nama_Santri':st.nama,'Kelas':st.kelas,'Tanggal':d.tanggal,'Kategori':normalizeText_(d.kategori,100),'Catatan':normalizeText_(d.catatan,3000)};Object.keys(vals).forEach(function(h){if(m[h])sh.getRange(i+1,m[h]).setValue(vals[h]);});if(m['ID_Santri'])sh.getRange(i+1,m['ID_Santri']).setValue(st.id);if(m['Updated_At'])sh.getRange(i+1,m['Updated_At']).setValue(new Date());if(m['Updated_By'])sh.getRange(i+1,m['Updated_By']).setValue(a.session.name);auditLog_(a.session,'UPDATE_CATATAN_WALI',String(d.idCatatan),'Santri='+st.id);return {success:true,message:'Catatan Wali Kelas berhasil diperbarui.'};}return {success:false,message:'Catatan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
}
function deleteCatatanWaliKelas(id,token){var a=requireCapability_(token,'catatan_wali.delete');if(!a.ok)return a.response;try{return withDataLock_(function(){var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName('Trx_Catatan_Wali'),m=headerMap(sh),rows=sh.getDataRange().getValues();for(var i=1;i<rows.length;i++)if(String(rows[i][m['ID_Catatan']-1])===String(id)){var rowAccess=assertTransactionRowAccess_(a.session,rows[i],m);if(!rowAccess.ok)return {success:false,message:rowAccess.message};sh.deleteRow(i+1);auditLog_(a.session,'DELETE_CATATAN_WALI',String(id),'');return {success:true,message:'Catatan Wali Kelas berhasil dihapus.'};}return {success:false,message:'Catatan tidak ditemukan.'};});}catch(e){return {success:false,message:e.toString()};}
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
function queueWhatsAppNotification(type,santriNama,eventId,data,token){var a=requireCapability_(token,'notification.send');if(!a.ok)return a.response;var st=getSantriRecordByName_(santriNama);if(!st)return {success:false,message:'Santri tidak ditemukan.'};var access=assertSantriAccess_(a.session,st);if(!access.ok)return {success:false,message:access.message};var q=queueWhatsAppNotification_(type,st,eventId,data,a.session);return {success:true,data:q,message:q.queued?'Notifikasi masuk antrean WhatsApp.':'Notifikasi tidak diantrekan: '+q.reason};}

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
function getNotificationQueue(token,status,limit){var a=requireAnyCapability_(token,['notification.send','notification.manage']);if(!a.ok)return a.response;ensureNotificationDatabase_();var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WA8.SHEET),m=headerMap(sh),d=sh.getDataRange().getValues(),o=[],max=Math.min(100,Number(limit||50)),rowMap={ID_Santri:m['Santri_ID'],Nama_Santri:m['Santri_Name']};for(var i=d.length-1;i>=1&&o.length<max;i--){if(!assertTransactionRowAccess_(a.session,d[i],rowMap).ok)continue;var st=String(d[i][m['Status']-1]||'');if(status&&status!=='ALL'&&st!==status)continue;o.push({id:d[i][m['ID_Notification']-1],createdAt:d[i][m['Created_At']-1],type:d[i][m['Type']-1],santriName:d[i][m['Santri_Name']-1],recipient:d[i][m['Recipient']-1],status:st,attempts:d[i][m['Attempts']-1],error:d[i][m['Error']-1]||''});}return {success:true,data:o};}
function retryWhatsAppNotification(id,token){var a=requireCapability_(token,'notification.send');if(!a.ok)return a.response;ensureNotificationDatabase_();var sh=SpreadsheetApp.getActiveSpreadsheet().getSheetByName(WA8.SHEET),m=headerMap(sh),d=sh.getDataRange().getValues();for(var i=1;i<d.length;i++)if(String(d[i][m['ID_Notification']-1])===String(id)){var access=assertTransactionRowAccess_(a.session,d[i],{ID_Santri:m['Santri_ID'],Nama_Santri:m['Santri_Name']});if(!access.ok)return {success:false,message:access.message};sh.getRange(i+1,m['Status']).setValue(WA8.STATUS.QUEUED);sh.getRange(i+1,m['Scheduled_At']).setValue(new Date());if(m['Error'])sh.getRange(i+1,m['Error']).clearContent();auditLog_(a.session,'RETRY_WHATSAPP',id,'Notification queued again');return {success:true,message:'Notifikasi dikembalikan ke antrean.'};}return {success:false,message:'Notification ID tidak ditemukan.'};}
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
  var m=headerMap(sh),data=sh.getDataRange().getValues(),sid=String(santri&&santri.id||'').trim(),studentIds=sid.split(/[,;\n]+/).map(function(x){return x.trim().toLowerCase();}).filter(Boolean),studentClass=String(santri&&santri.kelas||'').trim().toLowerCase(),studentGender=normalizeStudentGender_(santri&&santri.jenisKelamin),actorId=String(session&&session.id||'').trim();
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
      var classScope=list(m.Akses_Kelas?data[i][m.Akses_Kelas-1]:''),classMatches=classScope.indexOf('all')>=0||(studentClass&&classScope.indexOf(studentClass)>=0);
      var genderScope=normalizeSantriScope_(m.Lingkup_Santri?data[i][m.Lingkup_Santri-1]:'ALL'),genderMatches=genderScope==='ALL'||(studentGender&&genderScope===studentGender);
      if(classMatches&&genderMatches)add(out.waliKelas,id);
    }else if(role==='superadmin'||role==='supervisor'||route.indexOf(role)>=0){
      var adminScope=normalizeSantriScope_(m.Lingkup_Santri?data[i][m.Lingkup_Santri-1]:'ALL');
      if(adminScope==='ALL'||(studentGender&&adminScope===studentGender))add(out.admins,id);
    }
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
  var scopeIndex=buildSantriScopeIndex_();
  for(var i=data.length-1;i>=1&&out.length<max;i--){if(String(data[i][m.User_ID-1]||'')!==userId)continue;var santriId=String(data[i][m.Santri_ID-1]||'');if(santriId){var student=scopeIndex.byId[santriId];if(!student||!assertSantriAccess_(a.session,student).ok)continue;}out.push({id:String(data[i][m.ID_Notification-1]||''),timestamp:formatDateSafe(data[i][m.Created_At-1]),type:String(data[i][m.Type-1]||''),santriId:santriId,eventId:String(data[i][m.Event_ID-1]||''),title:String(data[i][m.Title-1]||''),message:String(data[i][m.Message-1]||''),url:String(data[i][m.URL-1]||WEB_PUSH.APP_URL),read:!!data[i][m.Read_At-1],status:data[i][m.Read_At-1]?'Dibaca':'Baru'});}
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
