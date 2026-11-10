# TAICIMASTER FM Apps Script — PWA icon correction

## Audit finding

The supplied Apps Script archive contained the Pesantren/PSB crest embedded as the browser favicon in `Index.html` and as both icon sizes returned by `Code.gs` when the web app is requested with `?manifest=1`.

The GitHub Pages PWA manifest already points to the TAICIMASTER assets. The mismatch was in the Apps Script fallback/legacy web-app HTML and its dynamically generated manifest.

## Required correction

In `Index.html`, use the existing TAICIMASTER FM PWA icon instead of the embedded crest:

```html
<link rel="icon" type="image/png" href="https://appfathanmubina.github.io/fm-taicimaster/assets/icon-192.png">
```

In `Code.gs`, the dynamic manifest should use:

```js
name: CONFIG.APP_NAME,
short_name: 'TAICIMASTER',
description: 'Sistem Perkembangan Santri - TAICIMASTER FM',
icons: [
  { src: 'https://appfathanmubina.github.io/fm-taicimaster/assets/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
  { src: 'https://appfathanmubina.github.io/fm-taicimaster/assets/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' }
]
```

## Duplicate bridge declaration

The supplied archive included the same PWA bridge declarations both inside `Code.gs` and in the standalone `Bridge.gs`. Keep the standalone `Bridge.gs` and remove the duplicated bridge block from `Code.gs` to avoid maintaining two copies of the same global functions.

## Validation

The corrected local source archive passed:
- Node syntax checks for `Code.gs`, `Bridge.gs`, and `SetupDatabase.gs`.
- Node syntax checks for all inline JavaScript blocks in `Index.html`.
- ZIP integrity check.
- A check that the favicon and dynamic manifest now point to TAICIMASTER icon assets.

The report/PDF logo constant `STAGE11_18_1_LOGO_BASE64_` was intentionally not changed: it is used for document branding, not the PWA/browser icon.

## Source archive status

The corrected Apps Script source archive is prepared separately. The original and corrected source files are not copied into this repository by this patch document; the full source archive still needs to be committed under this folder.
