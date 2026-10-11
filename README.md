# TAICIMASTER FM PWA

## Mengaktifkan Web Push

Push dikirim melalui OneSignal. App ID dan REST API Key dikelola dari panel Superadmin aplikasi; REST API Key tidak perlu ditaruh di `config.js` atau GitHub.

1. Buat aplikasi Web Push di OneSignal dan gunakan host PWA `https://appfathanmubina.github.io`. Pastikan worker `push/onesignal/OneSignalSDKWorker.js` dapat diakses dari GitHub Pages.
2. Ganti `Code.gs` dan `SetupDatabase.gs` di Apps Script dengan berkas pada paket tiga-file, lalu deploy ulang Web App. Jalankan `setupDatabaseSheets()` untuk memastikan sheet antrean dan inbox dibuat.
3. Masuk sebagai Superadmin, buka menu **WhatsApp & Notifikasi**, isi **OneSignal App ID** dan **REST API Key**, centang aktivasi Web Push, lalu pilih **Simpan & Terapkan**. Kunci disimpan di Script Properties.
4. Pengguna lain perlu masuk kembali setelah push diaktifkan. Tekan **Aktifkan Push** pada perangkat dan setujui izin notifikasi.
5. Pengguna iPhone/iPad perlu iOS/iPadOS 16.4 atau lebih baru, menambahkan PWA ke Layar Utama, lalu membuka aplikasi dari ikon tersebut sebelum meminta izin push.

Kode mengarahkan notifikasi ke wali santri yang terhubung dengan santri, wali kelas yang `Akses_Kelas`-nya cocok, serta admin yang relevan dengan jenis data. Prestasi pending hanya dikirim ke admin untuk ditinjau; hasil persetujuan atau penolakan dikirim kepada wali kelas terkait. Riwayat di dalam aplikasi bersifat per akun. Push diproses oleh trigger Apps Script kira-kira setiap menit, dan antrean mencoba ulang kegagalan sampai tiga kali.

Notifikasi push hanya berlaku untuk data baru setelah Code.gs yang diperbarui aktif. Kode tidak mengirim detail kesehatan, disiplin, atau catatan pribadi ke teks push.
