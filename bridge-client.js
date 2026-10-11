(function () {
  'use strict';

  const config = window.TAICI_PWA_CONFIG || {};
  const configuredBridgeUrl = String(config.bridgeUrl || '').trim();
  const appsScriptUrl = String(config.appsScriptUrl || '').trim();
  const BRIDGE_URL = configuredBridgeUrl || (appsScriptUrl
    ? appsScriptUrl + (appsScriptUrl.indexOf('?') >= 0 ? '&' : '?') + 'bridge=1'
    : '');
  const ORIGIN = String(config.pwaOrigin || window.location.origin).replace(/\/$/, '');
  const BRIDGE_ORIGIN_PATTERN = /^https:\/\/(script\.google\.com|[a-z0-9-]+-script\.googleusercontent\.com)$/i;
  const SOURCE = 'taicimaster-fm-pwa';
  const BRIDGE_SOURCE = 'taicimaster-fm-api-bridge';
  const pending = new Map();
  let serial = 0;
  let ready = false;

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
    if (!ready || !frame.contentWindow || item.sent) return;
    item.sent = true;
    frame.contentWindow.postMessage({
      source: SOURCE,
      type: 'request',
      id: item.id,
      fn: item.fn,
      args: item.args
    }, ORIGIN);
  }

  window.addEventListener('message', function (event) {
    if (!BRIDGE_ORIGIN_PATTERN.test(event.origin) || event.source !== frame.contentWindow) return;
    const data = event.data || {};
    if (data.source !== BRIDGE_SOURCE) return;

    if (data.type === 'ready') {
      ready = true;
      pending.forEach(sendPending);
      return;
    }
    if (data.type === 'bridge-error') {
      ready = false;
      reportPendingFailure(data.error && data.error.message || 'Konfigurasi bridge gagal dimuat.');
      return;
    }
    if (data.type !== 'response') return;

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
        item.fail(new Error('Waktu tunggu backend habis.'));
      }, 45000)
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

