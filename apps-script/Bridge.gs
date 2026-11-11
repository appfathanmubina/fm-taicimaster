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
  updateUserSantriScope: updateUserSantriScope,
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
  return { version: '11.28.7-user-scope.1', allowedOrigins: TAICI_PWA_ALLOWED_ORIGINS_.slice() };
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
