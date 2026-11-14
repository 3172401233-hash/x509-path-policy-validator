// Minimal DER (Distinguished Encoding Rules) reader for X.509 structures.
// Not a general ASN.1 library: it only supports what certificate parsing needs.

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
};

export class DerError extends Error {}

// A parsed TLV node.
export class DerNode {
  constructor(buf, tag, tagClass, constructed, headerLen, start, end) {
    this.buf = buf;
    this.tag = tag; // universal tag number, or context-specific index
    this.tagClass = tagClass; // 0 universal, 1 application, 2 context, 3 private
    this.constructed = constructed;
    this.headerLen = headerLen;
    this.start = start; // offset of the TLV itself
    this.end = end; // offset one past the value
  }

  get valueStart() {
    return this.start + this.headerLen;
  }

  // Raw content octets (without tag/length).
  value() {
    return this.buf.subarray(this.valueStart, this.end);
  }

  // Full TLV octets.
  raw() {
    return this.buf.subarray(this.start, this.end);
  }

  children() {
    if (!this.constructed) {
      throw new DerError('node is not constructed');
    }
    const out = [];
    let offset = this.valueStart;
    while (offset < this.end) {
      const node = readNode(this.buf, offset);
      out.push(node);
      offset = node.end;
    }
    if (offset !== this.end) {
      throw new DerError('constructed content length mismatch');
    }
    return out;
  }

  // Context-specific constructed wrapper: unwrap to the inner node.
  inner() {
    const nodes = this.children();
    if (nodes.length !== 1) {
      throw new DerError('expected exactly one inner node');
    }
    return nodes[0];
  }

  oid() {
    const bytes = this.value();
    if (bytes.length === 0) throw new DerError('empty OID');
    const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
    let value = 0;
    for (let i = 1; i < bytes.length; i++) {
      value = value * 128 + (bytes[i] & 0x7f);
      if ((bytes[i] & 0x80) === 0) {
        parts.push(value);
        value = 0;
      }
    }
    if (value !== 0) throw new DerError('truncated OID');
    return parts.join('.');
  }

  integerBytes() {
    // Returns the unsigned big-endian magnitude (leading 0x00 stripped).
    let bytes = this.value();
    while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
    return bytes;
  }

  integerHex() {
    return Buffer.from(this.integerBytes()).toString('hex');
  }

  bitStringBytes() {
    const bytes = this.value();
    if (bytes.length === 0) throw new DerError('empty BIT STRING');
    if (bytes[0] !== 0) throw new DerError('only byte-aligned BIT STRINGs supported');
    return bytes.subarray(1);
  }

  // BIT STRING with arbitrary alignment: returns { unusedBits, bytes }.
  bitString() {
    const bytes = this.value();
    if (bytes.length === 0) throw new DerError('empty BIT STRING');
    return { unusedBits: bytes[0], bytes: bytes.subarray(1) };
  }

  string() {
    return Buffer.from(this.value()).toString('utf8');
  }

  time() {
    const s = Buffer.from(this.value()).toString('ascii');
    if (this.tag === TAG.UTC_TIME) {
      const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
      if (!m) throw new DerError(`bad UTCTime: ${s}`);
      let year = Number(m[1]);
      year += year < 50 ? 2000 : 1900;
      return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
    }
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new DerError(`bad GeneralizedTime: ${s}`);
    return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  }
}

export function readNode(buf, offset = 0) {
  if (offset + 2 > buf.length) throw new DerError('truncated TLV header');
  const first = buf[offset];
  const tagClass = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let pos = offset + 1;
  if (tag === 0x1f) {
    // High-tag-number form.
    tag = 0;
    let b;
    do {
      if (pos >= buf.length) throw new DerError('truncated high-tag number');
      b = buf[pos++];
      tag = tag * 128 + (b & 0x7f);
    } while (b & 0x80);
  }
  if (pos >= buf.length) throw new DerError('truncated length');
  let length = buf[pos++];
  if (length & 0x80) {
    const numBytes = length & 0x7f;
    if (numBytes === 0) throw new DerError('indefinite length not allowed in DER');
    if (numBytes > 4) throw new DerError('length too large');
    if (pos + numBytes > buf.length) throw new DerError('truncated long length');
    length = 0;
    for (let i = 0; i < numBytes; i++) length = length * 256 + buf[pos++];
  }
  const end = pos + length;
  if (end > buf.length) throw new DerError('TLV value overruns buffer');
  return new DerNode(buf, tag, tagClass, constructed, pos - offset, offset, end);
}

export function pemToDer(pem) {
  const text = Buffer.isBuffer(pem) ? pem.toString('utf8') : String(pem);
  const m = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----/.exec(text);
  if (!m) throw new DerError('no PEM certificate block found');
  return Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
}
