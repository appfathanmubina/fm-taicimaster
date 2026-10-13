(function () {
  'use strict';

  const config = window.TAICI_PWA_CONFIG || {};
  const configuredBridgeUrl = String(config.bridgeUrl || '').trim();
  const appsScriptUrl = String(config.appsScriptUrl || '').trim();
  const BRIDGE_URL = configuredBridgeUrl || (appsScriptUrl
    ? appsScriptUrl + (appsScriptUrl.indexOf('?') >= 0 ? '&' : '?') + 'bridge=1'
    : '');
  const BRIDGE_ORIGIN_PATTERN = /^https:\/\/(script\.google\.com|[a-z0-9-]+-script\.googleusercontent\.com)$/i;
  const SOURCE = 'taicimaster-fm-pwa';
  const BRIDGE_SOURCE = 'taicimaster-fm-api-bridge';
  const pending = new Map();
  let serial = 0;
  let ready = false;
  let bridgeOrigin = '';
  let bridgeWindow = null;

  const frame = document.createElement('iframe');
  frame.title = 'TAICIMASTER backend bridge';
  frame.setAttribute('aria-hidden', 'true');
  frame.tabIndex = -1;
  frame.style.cssText = 'position:absolute;width:1px;height:1px;border:0;opacity:0;pointer-events:none;left:-10px;top:-10px';

  function reportPendingFailure(message) {
    pending.forEach(function (item, id) {
      clearTimeout(item.timer);
      pending.delete(id);
      item.fail(new Error(message));
    });
  }

  function ensureFrame() {
    if (!/^https:\/\/script\.google\.com\/macros\/s\//i.test(BRIDGE_URL)) {
      throw new Error('URL deployment Apps Script belum dikonfigurasi dengan benar.');
    }
    if (!frame.isConnected) {
      frame.src = BRIDGE_URL;
      document.body.appendChild(frame);
    }
  }

  function sendPending(item) {
    if (!ready || !bridgeOrigin || !bridgeWindow || item.sent) return;
    item.sent = true;
    bridgeWindow.postMessage({
      source: SOURCE,
      type: 'request',
      id: item.id,
      fn: item.fn,
      args: item.args
    }, bridgeOrigin);
  }

  // Apps Script wraps HtmlService output in one or more internal frames.
  // Accept bridge messages only from a descendant of our iframe, then target
  // that exact window for requests and responses.
  function isFrameDescendant(source) {
    if (!source || !frame.contentWindow) return false;
    const queue = [{ win: frame.contentWindow, depth: 0 }];
    const visited = new Set();
    while (queue.length && visited.size < 100) {
      const current = queue.shift();
      if (!current.win || visited.has(current.win)) continue;
      visited.add(current.win);
      if (current.win === source) return true;
      if (current.depth >= 8) continue;
      try {
        for (let i = 0; i < current.win.frames.length; i++) {
          queue.push({ win: current.win.frames[i], depth: current.depth + 1 });
        }
      } catch (_) {
        // Cross-origin frame enumeration may be restricted by the browser.
      }
    }
    return false;
  }

  window.addEventListener('message', function (event) {
    if (!BRIDGE_ORIGIN_PATTERN.test(event.origin) || !isFrameDescendant(event.source)) return;
    const data = event.data || {};
    if (data.source !== BRIDGE_SOURCE) return;

    if (data.type === 'ready') {
      bridgeOrigin = event.origin;
      bridgeWindow = event.source;
      ready = true;
      pending.forEach(sendPending);
      return;
    }
    if (data.type === 'bridge-error') {
      ready = false;
      bridgeOrigin = '';
      bridgeWindow = null;
      reportPendingFailure(data.error && data.error.message || 'Konfigurasi bridge gagal dimuat.');
      return;
    }
    if (data.type !== 'response') return;
    if (event.source !== bridgeWindow || event.origin !== bridgeOrigin) return;

    const id = String(data.id || '');
    const item = pending.get(id);
    if (!item) return;
    pending.delete(id);
    clearTimeout(item.timer);
    if (data.ok) item.ok(data.result);
    else item.fail(new Error(data.error && data.error.message || 'Permintaan ke backend gagal.'));
  });

  function rpc(fn, args, ok, fail) {
    try {
      ensureFrame();
    } catch (error) {
      (fail || console.error)(error);
      return;
    }

    const id = String(++serial);
    // Login dan pemulihan sesi membutuhkan waktu lebih lama pada cold start Apps Script.
    // Jangan retry otomatis karena autentikasi dapat berhasil di server meski respons terlambat.
    const timeoutMs = fn === 'authenticateUser' ? 120000
      : (fn === 'restoreRememberedSession' || fn === 'getSystemConfig') ? 90000
      : (fn === 'getUserNotifications' || fn === 'markUserNotificationRead') ? 90000
      : 60000;
    const item = {
      id: id,
      fn: fn,
      args: args,
      ok: ok || function () {},
      fail: fail || function (error) { console.error(error); },
      sent: false,
      timer: setTimeout(function () {
        if (!pending.has(id)) return;
        pending.delete(id);
        item.fail(new Error('Waktu tunggu backend habis setelah ' + Math.round(timeoutMs / 1000) + ' detik. Server mungkin sedang sibuk; periksa koneksi sebelum mencoba login kembali.'));
      }, timeoutMs)
    };
    pending.set(id, item);
    sendPending(item);
  }

  function makeRunner(ok, fail) {
    return new Proxy({
      withSuccessHandler: function (handler) { return makeRunner(handler, fail); },
      withFailureHandler: function (handler) { return makeRunner(ok, handler); }
    }, {
      get: function (target, property) {
        if (property in target) return target[property];
        if (typeof property !== 'string' || property === 'then') return undefined;
        return function () { rpc(property, Array.prototype.slice.call(arguments), ok, fail); };
      }
    });
  }

  window.TaiciBridge = {
    run: makeRunner(null, null),
    ready: function () { return ready; }
  };

  if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', ensureFrame, { once: true });
  } else {
    ensureFrame();
  }
})();

