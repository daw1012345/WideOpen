// Widevine EME setup: negotiate a MediaKeys session and forward license
// requests to the proxy. Nothing is actually encrypted — the stream is
// flagged as encrypted while every sample is sent marked clear.

import { buildWidevinePsshBox } from './mp4.js?v=drainv1';

const KEY_SYSTEM = 'com.widevine.alpha';

const ROBUSTNESS_CHAIN = ['SW_SECURE_CRYPTO', ''];

export async function setupEme({
  video,
  licenseUrl,
  defaultKid,
  fetchLicense,
  log = () => {},
}) {
  if (!defaultKid || defaultKid.length !== 16) {
    throw new Error('setupEme: defaultKid must be a 16-byte Uint8Array');
  }

  const tag = async (name, fn) => {
    try { return await fn(); }
    catch (e) {
      const errName = e?.name ?? typeof e;
      const errMsg = e?.message ?? '';
      throw new Error(`eme.${name} failed: ${errName}${errMsg ? ' — ' + errMsg : ''}`);
    }
  };

  const config = [{
    initDataTypes: ['cenc'],
    videoCapabilities: ROBUSTNESS_CHAIN.map((robustness) => ({
      contentType: 'video/mp4; codecs="avc1.42E01E"',
      robustness,
    })),
    persistentState: 'optional',
    sessionTypes: ['temporary'],
  }];

  const access = await tag('requestMediaKeySystemAccess',
    () => navigator.requestMediaKeySystemAccess(KEY_SYSTEM, config));
  log(`    access ok (keySystem=${access.keySystem})`);

  const mediaKeys = await tag('createMediaKeys', () => access.createMediaKeys());
  log(`    mediaKeys ok`);

  await tag('setMediaKeys', () => video.setMediaKeys(mediaKeys));
  log(`    setMediaKeys ok`);

  const session = await tag('createSession',
    async () => mediaKeys.createSession('temporary'));
  log(`    createSession ok`);

  let discoveredKid = null;
  const messagePromise = new Promise((resolve, reject) => {
    session.addEventListener('message', async (event) => {
      try {
        log(`    license-request message (${event.message.byteLength} bytes)`);
        const raw = await (fetchLicense
          ? fetchLicense(event.message)
          : defaultFetchLicense(licenseUrl, event.message));
        // fetchLicense may return either an ArrayBuffer or {body, kid}.
        const body = (raw && raw.body) ? raw.body : raw;
        if (raw && raw.kid) {
          discoveredKid = raw.kid;
          const hex = Array.from(discoveredKid)
            .map((b) => b.toString(16).padStart(2, '0')).join('');
          log(`    license carries KID ${hex}`);
        }
        await session.update(body);
        log(`    session.update ok`);
        resolve();
      } catch (err) {
        reject(err);
      }
    }, { once: true });
  });

  const initData = buildWidevinePsshBox(defaultKid);
  await tag('generateRequest',
    () => session.generateRequest('cenc', initData));
  log(`    generateRequest ok (${initData.length}B widevine pssh)`);

  await messagePromise;
  return { session, discoveredKid };
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length !== 32) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    const b = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) return null;
    out[i] = b;
  }
  return out;
}

async function defaultFetchLicense(licenseUrl, message) {
  if (!licenseUrl) {
    throw new Error('setupEme: licenseUrl or fetchLicense required');
  }
  const resp = await fetch(licenseUrl, {
    method: 'POST',
    body: message,
    headers: { 'Content-Type': 'application/octet-stream' },
  });
  if (!resp.ok) {
    throw new Error(`License fetch failed: ${resp.status} ${resp.statusText}`);
  }
  const kidHeader = resp.headers.get('X-Widevine-Key-IDs');
  const body = await resp.arrayBuffer();
  // Proxy returns a comma-separated list of hex KIDs; take the first.
  let kid = null;
  if (kidHeader) {
    const firstHex = kidHeader.split(',')[0].trim();
    kid = hexToBytes(firstHex);
  }
  return { body, kid };
}
