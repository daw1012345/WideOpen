// ISO-BMFF fragment writer for Widevine-EME H.264 delivery. Builds an init
// segment (ftyp + moov) and media segments (moof + mdat).
//
// Each AU is one MP4 sample with a single subsample marked fully clear
// (clear = sample_size, cipher = 0), so every byte of the payload reaches the
// CDM verbatim. Inside the mdat each NAL is length-prefixed; Gecko rewrites
// those back to AnnexB start codes before handing bytes to the CDM.

const TIMESCALE = 90000;
const TRACK_ID = 1;
const SAMPLE_DURATION = 3000; // 90000/30 — 30 fps; per-sample override OK.

// Widevine system ID — edef8ba9-79d6-4ace-a3c8-27dcd51d21ed
export const WIDEVINE_SYSTEM_ID = new Uint8Array([
  0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
  0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
]);

// Minimal Widevine pssh_data protobuf: just the key_ids field.
// WidevinePsshData { repeated bytes key_ids = 2; }
//   tag = (2 << 3) | wire_type=2 (length-delimited) = 0x12
//   length varint = 16 (keyId is always 16 bytes)
export function buildWidevinePsshData(keyId) {
  if (keyId.length !== 16) throw new Error('buildWidevinePsshData: keyId must be 16 bytes');
  const out = new Uint8Array(2 + 16);
  out[0] = 0x12;
  out[1] = 0x10;
  out.set(keyId, 2);
  return out;
}

// Full version-0 PSSH box for the Widevine CDM (a binary data blob, not a kid
// list). Firefox's sanitizer ignores non-version-1 boxes, so it passes through
// with zero recognized keyIds and the raw bytes are forwarded to the CDM.
export function buildWidevinePsshBox(keyId) {
  const data = buildWidevinePsshData(keyId);
  const totalSize = 4 + 4 + 4 + 16 + 4 + data.length;
  const out = new Uint8Array(totalSize);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, totalSize);
  out.set([0x70, 0x73, 0x73, 0x68], 4);  // 'pssh'
  dv.setUint8(8, 0);                      // version 0
  // flags = 0 (already zero)
  out.set(WIDEVINE_SYSTEM_ID, 12);
  dv.setUint32(28, data.length);
  out.set(data, 32);
  return out;
}

function tag(name) {
  if (name.length !== 4) throw new Error(`tag must be 4 bytes: ${name}`);
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) out[i] = name.charCodeAt(i);
  return out;
}

function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// Big-endian writers.
function u8(v)  { return new Uint8Array([v & 0xff]); }
function u16(v) { return new Uint8Array([(v >> 8) & 0xff, v & 0xff]); }
function u24(v) { return new Uint8Array([(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]); }
function u32(v) {
  return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff,
                         (v >>> 8) & 0xff,  v & 0xff]);
}
function u64(v) {
  if (typeof v !== 'bigint') v = BigInt(v);
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

function box(name, body) {
  const size = body.length + 8;
  return concat(u32(size), tag(name), body);
}

function fullBox(name, version, flags, body) {
  const head = concat(u8(version), u24(flags));
  return box(name, concat(head, body));
}

// ---------- Init segment ----------

function ftyp() {
  return box('ftyp', concat(
    tag('iso6'), u32(1),
    tag('iso6'), tag('isom'), tag('dash'), tag('cenc'),
  ));
}

function mvhd() {
  return fullBox('mvhd', 0, 0, concat(
    u32(0),               // creation_time
    u32(0),               // modification_time
    u32(TIMESCALE),
    u32(0),               // duration (0 for fragmented)
    u32(0x00010000),      // rate 1.0
    u16(0x0100),          // volume 1.0
    u16(0),               // reserved
    u32(0), u32(0),       // reserved
    // matrix
    u32(0x00010000), u32(0), u32(0),
    u32(0), u32(0x00010000), u32(0),
    u32(0), u32(0), u32(0x40000000),
    // pre_defined
    u32(0), u32(0), u32(0), u32(0), u32(0), u32(0),
    u32(2),               // next_track_ID
  ));
}

function tkhd(width, height) {
  const flags = 0x000007;  // track_enabled | track_in_movie | track_in_preview
  return fullBox('tkhd', 0, flags, concat(
    u32(0), u32(0),       // creation/modification time
    u32(TRACK_ID),
    u32(0),               // reserved
    u32(0),               // duration
    u32(0), u32(0),       // reserved
    u16(0), u16(0),       // layer, alternate_group
    u16(0), u16(0),       // volume, reserved
    // matrix
    u32(0x00010000), u32(0), u32(0),
    u32(0), u32(0x00010000), u32(0),
    u32(0), u32(0), u32(0x40000000),
    u32(width << 16),
    u32(height << 16),
  ));
}

function mdhd() {
  return fullBox('mdhd', 0, 0, concat(
    u32(0), u32(0),
    u32(TIMESCALE),
    u32(0),
    u16(0x55c4),          // language 'und'
    u16(0),
  ));
}

function hdlr() {
  const name = new TextEncoder().encode('VideoHandler\0');
  return fullBox('hdlr', 0, 0, concat(
    u32(0),
    tag('vide'),
    u32(0), u32(0), u32(0),
    name,
  ));
}

function vmhd() {
  return fullBox('vmhd', 0, 1, concat(
    u16(0),               // graphicsmode
    u16(0), u16(0), u16(0),
  ));
}

function dref() {
  // single 'url ' entry, self-contained
  const url = fullBox('url ', 0, 1, new Uint8Array(0));
  return fullBox('dref', 0, 0, concat(u32(1), url));
}

function dinf() { return box('dinf', dref()); }

// avcC — AVC decoder configuration record.
function avcC(spsList, ppsList) {
  // Inspect first SPS for profile/level bytes.
  const sps0 = spsList[0];
  const profile = sps0[1];
  const constraints = sps0[2];
  const level = sps0[3];
  const parts = [
    u8(1),                // configurationVersion
    u8(profile),
    u8(constraints),
    u8(level),
    u8(0xff),             // reserved(6) + lengthSizeMinusOne(2) = 3 (4-byte)
    u8(0xe0 | spsList.length),
  ];
  for (const sps of spsList) {
    parts.push(u16(sps.length));
    parts.push(sps);
  }
  parts.push(u8(ppsList.length));
  for (const pps of ppsList) {
    parts.push(u16(pps.length));
    parts.push(pps);
  }
  return box('avcC', concat(...parts));
}

// pasp — pixel aspect ratio (1:1)
function pasp() { return box('pasp', concat(u32(1), u32(1))); }

// tenc — track encryption defaults.
function tenc(defaultKid, defaultIsProtected = 1, defaultPerSampleIvSize = 8) {
  return fullBox('tenc', 0, 0, concat(
    u8(0), u8(0),                 // reserved
    u8(defaultIsProtected),
    u8(defaultPerSampleIvSize),
    defaultKid,                   // 16 bytes
  ));
}

function schi(defaultKid) { return box('schi', tenc(defaultKid)); }

function schm(scheme = 'cenc') {
  return fullBox('schm', 0, 0, concat(tag(scheme), u32(0x00010000)));
}

function frma(originalFormat = 'avc1') {
  return box('frma', tag(originalFormat));
}

function sinf(defaultKid) {
  return box('sinf', concat(frma(), schm(), schi(defaultKid)));
}

// Shared AVC visual sample entry body (everything except the sinf and box
// name). encv adds sinf at the end; avc1 has the same body without sinf.
function avcSampleEntryBody(width, height, spsList, ppsList) {
  return concat(
    new Uint8Array(6),    // reserved
    u16(1),               // data_reference_index
    u16(0), u16(0),       // pre_defined, reserved
    u32(0), u32(0), u32(0), // pre_defined
    u16(width), u16(height),
    u32(0x00480000),      // horiz resolution 72 dpi
    u32(0x00480000),      // vert resolution
    u32(0),               // reserved
    u16(1),               // frame_count
    new Uint8Array(32),   // compressor name (32 bytes, zero-padded)
    u16(0x0018),          // depth
    u16(0xffff),          // pre_defined
    avcC(spsList, ppsList),
    pasp(),
  );
}

// encv — encrypted AVC sample entry. Layout matches avc1 but the box name
// is 'encv' and a sinf box is appended at the end.
function encv(width, height, spsList, ppsList, defaultKid) {
  return box('encv', concat(
    avcSampleEntryBody(width, height, spsList, ppsList),
    sinf(defaultKid),
  ));
}

// avc1 — plain (unencrypted) AVC sample entry. Identical to encv body but
// without the sinf box. Per-moof tfhd's sample_description_index can point
// at this entry to mark individual samples as unencrypted; the track-level
// crypto info (set by the encv entry's sinf) still triggers EME / routes
// the track through the CDM, but per-sample those that reference avc1
// reach the CDM with encryption_scheme=kUnencrypted.
function avc1(width, height, spsList, ppsList) {
  return box('avc1', avcSampleEntryBody(width, height, spsList, ppsList));
}

// Two stsd entries: idx 1 = encv (default, encrypted samples),
// idx 2 = avc1 (referenced by moofs whose samples should hit the CDM as
// unencrypted — see r11 analysis in widevine-rip-firefox-layout memory).
function stsd(width, height, spsList, ppsList, defaultKid) {
  return fullBox('stsd', 0, 0, concat(
    u32(2),
    encv(width, height, spsList, ppsList, defaultKid),
    avc1(width, height, spsList, ppsList),
  ));
}

function stts() { return fullBox('stts', 0, 0, u32(0)); }
function stsc() { return fullBox('stsc', 0, 0, u32(0)); }
function stsz() { return fullBox('stsz', 0, 0, concat(u32(0), u32(0))); }
function stco() { return fullBox('stco', 0, 0, u32(0)); }

function stbl(width, height, spsList, ppsList, defaultKid) {
  return box('stbl', concat(
    stsd(width, height, spsList, ppsList, defaultKid),
    stts(), stsc(), stsz(), stco(),
  ));
}

function minf(width, height, spsList, ppsList, defaultKid) {
  return box('minf', concat(
    vmhd(), dinf(), stbl(width, height, spsList, ppsList, defaultKid),
  ));
}

function mdia(width, height, spsList, ppsList, defaultKid) {
  return box('mdia', concat(
    mdhd(), hdlr(), minf(width, height, spsList, ppsList, defaultKid),
  ));
}

function trak(width, height, spsList, ppsList, defaultKid) {
  return box('trak', concat(
    tkhd(width, height),
    mdia(width, height, spsList, ppsList, defaultKid),
  ));
}

function trex() {
  const flags = 0;
  return fullBox('trex', 0, 0, concat(
    u32(TRACK_ID),
    u32(1),               // default_sample_description_index
    u32(SAMPLE_DURATION),
    u32(0),               // default_sample_size
    u32(flags),           // default_sample_flags
  ));
}

function mvex() { return box('mvex', trex()); }

function pssh(systemId, data) {
  return fullBox('pssh', 0, 0, concat(
    systemId,
    u32(data.length),
    data,
  ));
}

export function buildInitSegment({
  width = 16, height = 16,
  benignSps, benignPps,
  defaultKid,
  widevinePsshData,
}) {
  if (!benignSps) throw new Error('buildInitSegment: benignSps required');
  if (!benignPps) throw new Error('buildInitSegment: benignPps required');
  if (!defaultKid || defaultKid.length !== 16) {
    throw new Error('buildInitSegment: defaultKid must be 16 bytes');
  }
  const boxes = [
    ftyp(),
    box('moov', concat(
      mvhd(),
      trak(width, height, [benignSps], [benignPps], defaultKid),
      mvex(),
      ...(widevinePsshData
        ? [pssh(WIDEVINE_SYSTEM_ID, widevinePsshData)]
        : []),
    )),
  ];
  return concat(...boxes);
}

// ---------- Media segment ----------

// Convert an AnnexB AU (with 4-byte start codes between NALs) into the
// MP4 sample byte form (4-byte big-endian length prefix per NAL).
export function annexBToMp4Sample(annexB) {
  if (annexB.length === 0) return new Uint8Array(0);
  const nals = [];
  let i = 0;
  while (i < annexB.length) {
    // Find next start code 00 00 00 01 (or 00 00 01).
    let scStart = i;
    let scLen = 0;
    if (i + 3 < annexB.length &&
        annexB[i] === 0 && annexB[i+1] === 0 &&
        annexB[i+2] === 0 && annexB[i+3] === 1) {
      scLen = 4;
    } else if (i + 2 < annexB.length &&
               annexB[i] === 0 && annexB[i+1] === 0 && annexB[i+2] === 1) {
      scLen = 3;
    } else {
      throw new Error(`annexBToMp4Sample: missing start code at offset ${i}`);
    }
    const nalStart = scStart + scLen;
    // Find next start code or end of buffer.
    let j = nalStart;
    let nextSc = annexB.length;
    while (j + 2 < annexB.length) {
      if (annexB[j] === 0 && annexB[j+1] === 0 &&
          (annexB[j+2] === 1 ||
           (annexB[j+2] === 0 && j + 3 < annexB.length && annexB[j+3] === 1))) {
        nextSc = j;
        break;
      }
      j++;
    }
    nals.push(annexB.subarray(nalStart, nextSc));
    i = nextSc;
  }
  let total = 0;
  for (const n of nals) total += 4 + n.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const n of nals) {
    out[o] = (n.length >>> 24) & 0xff;
    out[o + 1] = (n.length >>> 16) & 0xff;
    out[o + 2] = (n.length >>> 8) & 0xff;
    out[o + 3] = n.length & 0xff;
    out.set(n, o + 4);
    o += 4 + n.length;
  }
  return out;
}

function mfhd(seqNum) {
  return fullBox('mfhd', 0, 0, u32(seqNum));
}

// tfhd flag bits
const TFHD_BASE_DATA_OFFSET     = 0x000001;
const TFHD_SAMPLE_DESCRIPTION   = 0x000002;
const TFHD_DEFAULT_DURATION     = 0x000008;
const TFHD_DEFAULT_SIZE         = 0x000010;
const TFHD_DEFAULT_FLAGS        = 0x000020;
const TFHD_DURATION_IS_EMPTY    = 0x010000;
const TFHD_DEFAULT_BASE_IS_MOOF = 0x020000;

// Bit 0x00010000 = sample_is_non_sync_sample. Firefox only extracts inband
// SPS/PPS from sync samples, so flagging every sample non-sync lets our
// overflow SPSes reach the CDM's per-sample H.264 parser instead of being
// rejected by the avcC validator. The first sample still counts as a
// random-access point by virtue of opening the segment.
const NON_SYNC_FLAGS = 0x00010000;

// tfhd builder. `sampleDescriptionIndex` (1-based) optionally overrides the
// trex default. Fields are emitted in flag-bit order.
function tfhd(defaultSampleDuration, sampleDescriptionIndex = null) {
  let flags = TFHD_DEFAULT_BASE_IS_MOOF | TFHD_DEFAULT_DURATION | TFHD_DEFAULT_FLAGS;
  const parts = [u32(TRACK_ID)];
  if (sampleDescriptionIndex != null) {
    flags |= TFHD_SAMPLE_DESCRIPTION;
    parts.push(u32(sampleDescriptionIndex));
  }
  parts.push(u32(defaultSampleDuration));
  parts.push(u32(NON_SYNC_FLAGS));
  return fullBox('tfhd', 0, flags, concat(...parts));
}

function tfdt(baseMediaDecodeTime) {
  return fullBox('tfdt', 1, 0, u64(BigInt(baseMediaDecodeTime)));
}

// trun flag bits
const TRUN_DATA_OFFSET        = 0x000001;
const TRUN_FIRST_SAMPLE_FLAGS = 0x000004;
const TRUN_SAMPLE_DURATION    = 0x000100;
const TRUN_SAMPLE_SIZE        = 0x000200;
const TRUN_SAMPLE_FLAGS       = 0x000400;
const TRUN_SAMPLE_CTS         = 0x000800;

function trun(samples, dataOffset) {
  // first_sample_flags overrides the tfhd default for sample 0 only —
  // we need that one to be sync (random access point) so MSE accepts
  // the segment start.
  const flags = TRUN_DATA_OFFSET | TRUN_SAMPLE_SIZE | TRUN_SAMPLE_DURATION |
                TRUN_FIRST_SAMPLE_FLAGS;
  const parts = [
    u32(samples.length),
    u32(dataOffset),
    u32(0),  // first_sample_flags = 0 → sync (sample_is_non_sync_sample=0)
  ];
  for (const s of samples) {
    parts.push(u32(s.duration));
    parts.push(u32(s.size));
  }
  return fullBox('trun', 0, flags, concat(...parts));
}

// saiz: one auxiliary-info entry per sample (8-byte IV + 2-byte subsample
// count + 6 bytes per subsample = 16 bytes for a single subsample).
function saizForSamples(numSamples, sizePerSample) {
  const flags = 0x1;
  return fullBox('saiz', 0, flags, concat(
    tag('cenc'),
    tag('\0\0\0\0'),
    u8(sizePerSample),
    u32(numSamples),
  ));
}

function saioForOffset(offset) {
  const flags = 0x1;
  return fullBox('saio', 0, flags, concat(
    tag('cenc'),
    tag('\0\0\0\0'),
    u32(1),               // entry_count
    u32(offset),
  ));
}

// senc — sample encryption box. One entry per sample.
// Per-sample: 8-byte IV + 2-byte subsample_count + N × (2 byte clear + 4 byte cipher).
function senc(samples, iv) {
  const flags = 0x000002;   // UseSubSampleEncryption
  const parts = [u32(samples.length)];
  for (const s of samples) {
    parts.push(iv);
    parts.push(u16(1));    // one subsample
    parts.push(u16(s.size)); // clear bytes
    parts.push(u32(0));     // cipher bytes
  }
  return fullBox('senc', 0, flags, concat(...parts));
}

// `samples` is Array<{ data: Uint8Array, duration: number }>; each `data` must
// already be in MP4 byte form (length-prefixed NALs).
//
// With `unencrypted=true` the moof references stsd index 2 (avc1) and omits the
// encryption boxes, so the CDM sees encryption_scheme=kUnencrypted and passes
// bs_buf through unchanged — letting AU6's ROP bytes reach the parser as plaintext.
export function buildMediaSegment({
  samples,
  sequenceNumber,
  baseMediaDecodeTime,
  iv,
  unencrypted = false,
}) {
  if (!unencrypted && (!iv || iv.length !== 8)) {
    throw new Error('buildMediaSegment: iv must be 8 bytes (encrypted moof)');
  }
  const sampleInfos = samples.map((s) => ({
    size: s.data.length,
    duration: s.duration ?? SAMPLE_DURATION,
  }));

  // Compose traf with a placeholder data_offset = 0 to measure its size, then
  // rebuild with the correct offset.
  const buildTraf = (dataOffset) => {
    const trunBox = trun(sampleInfos, dataOffset);
    if (unencrypted) {
      // avc1 stsd entry (idx 2), no senc/saiz/saio. The track-level encv's
      // sinf still sets mCrypto on the TrackInfo, so PDMFactory routes the
      // track through the CDM — only per-sample the scheme becomes None.
      return box('traf', concat(
        tfhd(SAMPLE_DURATION, 2),
        tfdt(baseMediaDecodeTime),
        trunBox,
      ));
    }
    // Encrypted path (existing).
    const sencBox = senc(sampleInfos, iv);
    // saiz: one entry per sample, each 16 bytes (8 IV + 2 count + 6 subs).
    const sizPerSample = 8 + 2 + 6;
    const saizBox = saizForSamples(samples.length, sizPerSample);
    // saio points at the byte after senc's flags/version/sample_count.
    // We'll patch the offset after we know the moof layout.
    const saioPlaceholder = saioForOffset(0);
    return box('traf', concat(
      tfhd(SAMPLE_DURATION),
      tfdt(baseMediaDecodeTime),
      saizBox,
      saioPlaceholder,
      sencBox,
      trunBox,
    ));
  };

  // First pass: dataOffset = 0 to learn moof size.
  const probeMoof = box('moof', concat(mfhd(sequenceNumber), buildTraf(0)));
  const dataOffsetValue = probeMoof.length + 8;
  const trafFinal = buildTraf(dataOffsetValue);
  const moofFinal = box('moof', concat(mfhd(sequenceNumber), trafFinal));
  if (moofFinal.length !== probeMoof.length) {
    throw new Error('buildMediaSegment: moof size mismatch between passes');
  }

  // Concatenate mdat.
  let mdatBodyLen = 0;
  for (const s of samples) mdatBodyLen += s.data.length;
  const mdatBody = new Uint8Array(mdatBodyLen);
  let o = 0;
  for (const s of samples) { mdatBody.set(s.data, o); o += s.data.length; }
  const mdat = box('mdat', mdatBody);

  return concat(moofFinal, mdat);
}

// Convenience: take an array of AnnexB AUs, convert to samples,
// build a media segment.
export function annexBAusToMediaSegment({
  aus, durations, sequenceNumber, baseMediaDecodeTime, iv,
  unencrypted = false,
}) {
  const samples = aus.map((au, idx) => ({
    data: annexBToMp4Sample(au),
    duration: durations?.[idx] ?? SAMPLE_DURATION,
  }));
  // Empty AUs are valid (no NALs) but most muxers reject zero-size samples.
  // For empty drain AUs we emit a single 4-byte zero NAL length to satisfy
  // the demuxer; the CDM will see an empty AU on the AnnexB side.
  for (const s of samples) {
    if (s.data.length === 0) {
      s.data = new Uint8Array([0, 0, 0, 0]);  // zero-length NAL
    }
  }
  return buildMediaSegment({
    samples, sequenceNumber, baseMediaDecodeTime, iv, unencrypted,
  });
}
