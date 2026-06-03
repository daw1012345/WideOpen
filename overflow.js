// Arithmetic for building SPS offset_for_ref_frame[] overflow deltas.

// Element 289 lands at the next SPS slot's +0x00: the overflow writes element
// K at SPS+0x278+4*K, and the next SPS slot starts at SPS+0x700.
const EL_BASE = 289;

export function el(off) {
  return EL_BASE + (off >>> 2);
}

// Given { elementIndex: u32 } targets and a total element count, return
// signed se(v) deltas whose prefix sums equal each target value.
export function solveDeltas(targets, count) {
  let prev = 0;
  const offs = [];
  for (let k = 0; k < count; k++) {
    const t = (targets[k] ?? 0) >>> 0;
    let d = (t - prev) >>> 0;
    if (d >= 0x80000000) d -= 0x100000000;
    offs.push(d);
    prev = t;
  }
  return offs;
}

// Distribute `target` (as i32) across n se(v) deltas, each within
// ±CUMULATE_DELTA_MAX so the encoder can fit them and the CDM's SPS parser
// accepts them. The cap stays below the se(v) magnitude limit (2^31-1); the
// caller picks n small enough that each step fits.
export const CUMULATE_DELTA_MAX = 0x70000000;
export function cumulateDeltas(target, n) {
  let t = target >>> 0;
  if (t >= 0x80000000) t -= 0x100000000;
  const step = Math.trunc(t / n);
  const rem = t - step * n;
  const ds = [];
  for (let i = 0; i < n - 1; i++) ds.push(step);
  ds.push(step + rem);
  let s = 0;
  for (const d of ds) s = (s + d) >>> 0;
  if (s !== (target >>> 0)) {
    throw new Error(`cumulateDeltas: sum ${s.toString(16)} != target ${(target>>>0).toString(16)}`);
  }
  for (const d of ds) {
    if (d < -CUMULATE_DELTA_MAX || d > CUMULATE_DELTA_MAX) {
      throw new Error(`cumulateDeltas: delta ${d.toString(16)} out of range (cap=${CUMULATE_DELTA_MAX.toString(16)})`);
    }
  }
  return ds;
}
