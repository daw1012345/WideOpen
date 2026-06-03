// Bit-level writer with Exp-Golomb (ue/se) encoders.

export class BW {
  constructor() {
    this.bits = [];
  }

  u(val, n) {
    val = Number(val);
    for (let i = n - 1; i >= 0; i--) {
      this.bits.push((val >>> i) & 1);
    }
  }

  ue(val) {
    val = Number(val);
    const code = val + 1;
    let n = 0;
    let v = code;
    while (v > 0) { n++; v >>>= 1; }
    if (n === 0) n = 1;
    this.u(0, n - 1);
    this.u(code, n);
  }

  se(val) {
    val = Number(val) | 0;
    if (val <= 0) this.ue(-2 * val);
    else          this.ue(2 * val - 1);
  }

  bytes() {
    const b = this.bits.slice();
    while (b.length % 8) b.push(0);
    const out = new Uint8Array(b.length / 8);
    for (let i = 0; i < b.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | b[i + j];
      out[i / 8] = byte;
    }
    return out;
  }
}

// H.264 emulation-prevention: escape 00 00 0x (x<=3) by inserting 0x03.
export function escapeEmulation(rbsp) {
  const out = [];
  let zeros = 0;
  for (const byte of rbsp) {
    if (zeros >= 2 && byte <= 3) {
      out.push(0x03);
      zeros = 0;
    }
    out.push(byte);
    zeros = byte === 0 ? zeros + 1 : 0;
  }
  return new Uint8Array(out);
}

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
