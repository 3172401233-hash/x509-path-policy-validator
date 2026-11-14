// X.509 certificate parsing on top of the minimal DER reader.

import { createHash, createPublicKey } from 'node:crypto';
import { readNode, pemToDer, TAG, DerError } from './der.js';

export const OID = {
  CN: '2.5.4.3',
  SUBJECT_KEY_ID: '2.5.29.14',
  KEY_USAGE: '2.5.29.15',
  SUBJECT_ALT_NAME: '2.5.29.17',
  BASIC_CONSTRAINTS: '2.5.29.19',
  NAME_CONSTRAINTS: '2.5.29.30',
  CRL_DISTRIBUTION_POINTS: '2.5.29.31',
  CERTIFICATE_POLICIES: '2.5.29.32',
  AUTHORITY_KEY_ID: '2.5.29.35',
  EXTENDED_KEY_USAGE: '2.5.29.37',
  EKU_SERVER_AUTH: '1.3.6.1.5.5.7.3.1',
  EKU_CLIENT_AUTH: '1.3.6.1.5.5.7.3.2',
  EKU_ANY: '2.5.29.37.0',
};

// Extensions this library understands. Any *critical* extension outside this
// set causes the certificate to be rejected (fail-closed, RFC 5280 4.2).
const KNOWN_EXTENSIONS = new Set([
  OID.SUBJECT_KEY_ID,
  OID.KEY_USAGE,
  OID.SUBJECT_ALT_NAME,
  OID.BASIC_CONSTRAINTS,
  OID.NAME_CONSTRAINTS,
  OID.CRL_DISTRIBUTION_POINTS,
  OID.CERTIFICATE_POLICIES,
  OID.AUTHORITY_KEY_ID,
  OID.EXTENDED_KEY_USAGE,
]);

const KEY_USAGE_BITS = [
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
];

const ATTRIBUTE_SHORT_NAMES = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

// Parses a Name (SEQUENCE OF RelativeDistinguishedName) into an ordered list
// of { oid, name, value } attributes, preserving order.
function parseName(node) {
  const attrs = [];
  for (const rdn of node.children()) {
    for (const atv of rdn.children()) {
      const [oidNode, valueNode] = atv.children();
      const oid = oidNode.oid();
      attrs.push({ oid, name: ATTRIBUTE_SHORT_NAMES[oid] ?? oid, value: valueNode.string() });
    }
  }
  return attrs;
}

export function formatName(attrs) {
  return attrs.map((a) => `${a.name}=${a.value}`).join(', ');
}

function namesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i].oid !== b[i].oid) return false;
    // Directory string comparison: case-insensitive, whitespace-collapsed.
    const norm = (s) => s.trim().replace(/\s+/g, ' ').toLowerCase();
    if (norm(a[i].value) !== norm(b[i].value)) return false;
  }
  return true;
}

// GeneralName parsing for SAN and name constraints. Only the name forms this
// library enforces are returned; others are reported via `unsupported`.
function parseGeneralNames(node, context) {
  const names = { dns: [], directory: [], unsupported: [] };
  for (const gn of node.children()) {
    if (gn.tagClass !== 2) continue;
    if (gn.tag === 2) {
      names.dns.push(gn.string().toLowerCase());
    } else if (gn.tag === 4) {
      names.directory.push(parseName(gn.inner()));
    } else {
      names.unsupported.push({ context, tag: gn.tag });
    }
  }
  return names;
}

function parseKeyUsage(node) {
  const { bytes } = node.bitString();
  const usages = new Set();
  for (let bit = 0; bit < KEY_USAGE_BITS.length; bit++) {
    const byte = bytes[bit >> 3];
    if (byte !== undefined && (byte & (0x80 >> (bit & 7))) !== 0) {
      usages.add(KEY_USAGE_BITS[bit]);
    }
  }
  return usages;
}

function parseBasicConstraints(node) {
  let ca = false;
  let pathLen = null;
  for (const child of node.children()) {
    if (child.tag === TAG.BOOLEAN) ca = child.value()[0] !== 0;
    else if (child.tag === TAG.INTEGER) pathLen = Number(BigInt('0x' + (child.integerHex() || '0')));
  }
  return { ca, pathLen };
}

function parseNameConstraints(node) {
  const result = { permitted: [], excluded: [], unsupported: [] };
  for (const subtree of node.children()) {
    if (subtree.tagClass !== 2 || (subtree.tag !== 0 && subtree.tag !== 1)) continue;
    const list = subtree.tag === 0 ? result.permitted : result.excluded;
    for (const generalSubtree of subtree.children()) {
      const base = generalSubtree.children()[0];
      if (base.tagClass !== 2) continue;
      if (base.tag === 2) {
        list.push({ type: 'dns', value: base.string().toLowerCase() });
      } else if (base.tag === 4) {
        list.push({ type: 'directory', value: parseName(base.inner()) });
      } else {
        result.unsupported.push({ tag: base.tag });
      }
    }
  }
  return result;
}

export class Certificate {
  constructor(der) {
    this.der = Buffer.from(der);
    this.fingerprint256 = createHash('sha256').update(this.der).digest('hex');

    const cert = readNode(this.der);
    const [tbs, sigAlg, sigValue] = cert.children();
    this.tbsDer = tbs.raw();
    this.signatureAlgorithmOid = sigAlg.children()[0].oid();
    this.signature = sigValue.bitStringBytes();

    const fields = tbs.children();
    let i = 0;
    if (fields[0].tagClass === 2 && fields[0].tag === 0) {
      this.version = Number(BigInt('0x' + fields[0].inner().integerHex())) + 1;
      i = 1;
    } else {
      this.version = 1;
    }
    this.serialNumber = fields[i++].integerHex();
    i++; // tbs signature algorithm (redundant with outer one)
    this.issuer = parseName(fields[i++]);
    const validity = fields[i++];
    const [notBefore, notAfter] = validity.children();
    this.notBefore = notBefore.time();
    this.notAfter = notAfter.time();
    this.subject = parseName(fields[i++]);
    this.spkiDer = fields[i++].raw();
    this.publicKey = createPublicKey({ key: Buffer.from(this.spkiDer), format: 'der', type: 'spki' });

    this.extensions = new Map(); // oid -> { critical, value: DerNode }
    for (; i < fields.length; i++) {
      const f = fields[i];
      if (f.tagClass === 2 && f.tag === 3) {
        for (const ext of f.inner().children()) {
          const parts = ext.children();
          const oid = parts[0].oid();
          let critical = false;
          let valueNode = parts[1];
          if (parts.length === 3) {
            critical = parts[1].value()[0] !== 0;
            valueNode = parts[2];
          }
          // Extension value is an OCTET STRING wrapping the real DER value.
          const inner = readNode(valueNode.value());
          this.extensions.set(oid, { critical, value: inner });
        }
      }
    }

    const bc = this.extensions.get(OID.BASIC_CONSTRAINTS);
    this.basicConstraints = bc ? parseBasicConstraints(bc.value) : { ca: false, pathLen: null };
    this.isCA = this.basicConstraints.ca;

    const ku = this.extensions.get(OID.KEY_USAGE);
    this.keyUsage = ku ? parseKeyUsage(ku.value) : null; // null = extension absent

    const eku = this.extensions.get(OID.EXTENDED_KEY_USAGE);
    this.extendedKeyUsage = eku ? eku.value.children().map((n) => n.oid()) : null;

    const san = this.extensions.get(OID.SUBJECT_ALT_NAME);
    this.subjectAltName = san ? parseGeneralNames(san.value, 'subjectAltName') : null;

    const nc = this.extensions.get(OID.NAME_CONSTRAINTS);
    this.nameConstraints = nc ? parseNameConstraints(nc.value) : null;

    this.unknownCriticalExtensions = [];
    for (const [oid, ext] of this.extensions) {
      if (ext.critical && !KNOWN_EXTENSIONS.has(oid)) {
        this.unknownCriticalExtensions.push(oid);
      }
    }
  }

  static fromPem(pem) {
    return new Certificate(pemToDer(pem));
  }

  get subjectCN() {
    const cn = this.subject.find((a) => a.oid === OID.CN);
    return cn ? cn.value : null;
  }

  get subjectString() {
    return formatName(this.subject);
  }

  get issuerString() {
    return formatName(this.issuer);
  }

  get isSelfSigned() {
    return namesEqual(this.subject, this.issuer);
  }

  issuerMatches(other) {
    return namesEqual(this.issuer, other.subject);
  }

  // DNS names this certificate claims: SAN dNSName entries, falling back to
  // the subject CN when no SAN is present (deprecated but common).
  dnsNames() {
    if (this.subjectAltName) return this.subjectAltName.dns;
    return this.subjectCN ? [this.subjectCN.toLowerCase()] : [];
  }

  toJSON() {
    return {
      subject: this.subjectString,
      issuer: this.issuerString,
      serialNumber: this.serialNumber,
      fingerprint256: this.fingerprint256,
      notBefore: this.notBefore.toISOString(),
      notAfter: this.notAfter.toISOString(),
    };
  }
}

export { namesEqual, DerError };
