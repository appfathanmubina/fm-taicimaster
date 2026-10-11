# TAICIMASTER FM PWA

Frontend GitHub Pages untuk TAICIMASTER FM. Aplikasi menggunakan Google Apps Script sebagai backend melalui PWA bridge.

## Publikasi GitHub Pages

1. Buka **Settings → Pages** pada repository `appfathanmubina/fm-taicimaster`.
2. Pilih **GitHub Actions** sebagai build and deployment source.
3. Workflow akan menerbitkan isi repository ke `https://appfathanmubina.github.io/fm-taicimaster/` setiap ada perubahan di `main`.

## Hubungkan ke Apps Script

`config.js` saat ini menunjuk ke deployment Apps Script yang digunakan oleh paket Stage 11.28.6. Jika URL deployment berubah, perbarui `appsScriptUrl`, `bridgeUrl`, dan `pwaOrigin` di file tersebut. Origin PWA harus tetap sama dengan allowlist bridge di Apps Script.

Pastikan deployment Apps Script yang dituju sudah memuat `doGet(...?bridge=1)`, `getTaiciPwaBridgeConfig()`, dan `taiciPwaBridgeCall()`. Sesudah mengubah kode server, terbitkan versi deployment Web App terbaru pada URL yang dikonfigurasi.

## PWA dan mode offline

Manifest, ikon, dan service worker disiapkan untuk instalasi PWA dari browser. Service worker menyimpan app shell agar halaman dapat dibuka kembali tanpa jaringan; autentikasi, data, dan operasi tetap memerlukan koneksi ke Apps Script.

Tailwind, SweetAlert2, Font Awesome, dan Google Fonts masih dimuat dari CDN, sehingga tampilan penuh membutuhkan koneksi internet.
