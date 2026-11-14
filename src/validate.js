// Certificate path building and validation (offline, RFC 5280 inspired).

import { verify as cryptoVerify } from 'node:crypto';
import { Certificate, OID, namesEqual } from './certificate.js';

// Signature algorithm OIDs -> node:crypto verify parameters.
const SIGNATURE_ALGORITHMS = {
  '1.2.840.113549.1.1.5': { algorithm: 'RSA-SHA1' },
  '1.2.840.113549.1.1.11': { algorithm: 'RSA-SHA256' },
  '1.2.840.113549.1.1.12': { algorithm: 'RSA-SHA384' },
  '1.2.840.113549.1.1.13': { algorithm: 'RSA-SHA512' },
  '1.2.840.10045.4.3.2': { algorithm: 'sha256', dsaEncoding: 'der' },
  '1.2.840.10045.4.3.3': { algorithm: 'sha384', dsaEncoding: 'der' },
  '1.2.840.10045.4.3.4': { algorithm: 'sha512', dsaEncoding: 'der' },
};

export const REASON = {
  SIGNATURE: 'signature-verification-failed',
  NOT_CA: 'issuer-not-a-ca',
  KEY_USAGE: 'key-usage-violation',
  EKU: 'extended-key-usage-violation',
  EXPIRED: 'certificate-expired',
  NOT_YET_VALID: 'certificate-not-yet-valid',
  UNKNOWN_CRITICAL_EXTENSION: 'unknown-critical-extension',
  NAME_CONSTRAINT: 'name-constraint-violation',
  HOSTNAME_MISMATCH: 'hostname-mismatch',
  PATH_LENGTH: 'path-length-constraint-violation',
  REVOKED: 'certificate-revoked',
  NO_PATH_TO_TRUST: 'no-path-to-trust-anchor',
  UNSUPPORTED_SIGNATURE_ALGORITHM: 'unsupported-signature-algorithm',
  UNSUPPORTED_NAME_CONSTRAINT: 'unsupported-name-constraint-form',
  ANCHOR_NOT_SELF_SIGNED: 'trust-anchor-not-self-signed',
};

export function verifySignature(cert, issuerCert) {
  const spec = SIGNATURE_ALGORITHMS[cert.signatureAlgorithmOid];
  if (!spec) {
    return { ok: false, reason: REASON.UNSUPPORTED_SIGNATURE_ALGORITHM, detail: cert.signatureAlgorithmOid };
  }
  const key = spec.dsaEncoding
    ? { key: issuerCert.publicKey, dsaEncoding: spec.dsaEncoding }
    : issuerCert.publicKey;
  const ok = cryptoVerify(spec.algorithm, cert.tbsDer, key, cert.signature);
  return ok
    ? { ok: true }
    : { ok: false, reason: REASON.SIGNATURE, detail: `signed by ${issuerCert.subjectString}` };
}

// --- hostname matching ---------------------------------------------------

function matchDnsPattern(pattern, hostname) {
  pattern = pattern.toLowerCase();
  hostname = hostname.toLowerCase();
  if (pattern.startsWith('*.')) {
    // Wildcard covers exactly one left-most label.
    const suffix = pattern.slice(1); // ".example.com"
    if (!hostname.endsWith(suffix)) return false;
    const prefix = hostname.slice(0, hostname.length - suffix.length);
    return prefix.length > 0 && !prefix.includes('.');
  }
  return pattern === hostname;
}

export function matchHostname(cert, hostname) {
  const names = cert.dnsNames();
  if (names.length === 0) return false;
  return names.some((n) => matchDnsPattern(n, hostname));
}

// --- name constraints ----------------------------------------------------

function dnsNameWithin(name, constraint) {
  name = name.toLowerCase();
  constraint = constraint.toLowerCase();
  if (constraint.startsWith('.')) {
    // Leading dot: subdomains only.
    return name.endsWith(constraint) && name.length > constraint.length;
  }
  return name === constraint || name.endsWith('.' + constraint);
}

function directoryNameWithin(name, constraint) {
  // constraint must be a prefix (top-most RDNs) of name.
  if (constraint.length > name.length) return false;
  return namesEqual(name.slice(0, constraint.length), constraint);
}

// Checks the name constraints imposed by `caCert` against a subordinate
// certificate. Returns null when satisfied, or a failure detail string.
function checkNameConstraintsFor(caCert, subordinate, isLeaf) {
  const nc = caCert.nameConstraints;
  if (!nc) return null;
  if (nc.unsupported.length > 0) {
    return `unsupported GeneralName form in nameConstraints of ${caCert.subjectString}`;
  }
  const dnsNames = isLeaf ? subordinate.dnsNames() : [];
  const dnsConstraints = {
    permitted: nc.permitted.filter((c) => c.type === 'dns'),
    excluded: nc.excluded.filter((c) => c.type === 'dns'),
  };
  for (const name of dnsNames) {
    for (const c of dnsConstraints.excluded) {
      if (dnsNameWithin(name, c.value)) {
        return `DNS name "${name}" hits excluded subtree "${c.value}"`;
      }
    }
    if (dnsConstraints.permitted.length > 0) {
      const ok = dnsConstraints.permitted.some((c) => dnsNameWithin(name, c.value));
      if (!ok) return `DNS name "${name}" is outside all permitted subtrees`;
    }
  }
  const dirConstraints = {
    permitted: nc.permitted.filter((c) => c.type === 'directory'),
    excluded: nc.excluded.filter((c) => c.type === 'directory'),
  };
  if (dirConstraints.permitted.length > 0 || dirConstraints.excluded.length > 0) {
    const subject = subordinate.subject;
    for (const c of dirConstraints.excluded) {
      if (directoryNameWithin(subject, c.value)) {
        return `subject "${subordinate.subjectString}" hits excluded directoryName subtree`;
      }
    }
    if (dirConstraints.permitted.length > 0) {
      const ok = dirConstraints.permitted.some((c) => directoryNameWithin(subject, c.value));
      if (!ok) return `subject "${subordinate.subjectString}" is outside permitted directoryName subtrees`;
    }
  }
  return null;
}

// --- revocation ----------------------------------------------------------

function normalizeSerial(serial) {
  return String(serial).toLowerCase().replace(/[^0-9a-f]/g, '').replace(/^0+(?=.)/, '');
}

function isRevoked(cert, revocation) {
  if (!revocation) return false;
  const entries = Array.isArray(revocation) ? revocation : revocation.entries ?? [];
  for (const entry of entries) {
    if (entry.fingerprint256 && entry.fingerprint256.toLowerCase() === cert.fingerprint256) {
      return true;
    }
    if (entry.serialNumber !== undefined) {
      const serialMatch = normalizeSerial(entry.serialNumber) === normalizeSerial(cert.serialNumber);
      const issuerOk = !entry.issuer || entry.issuer === cert.issuerString;
      if (serialMatch && issuerOk) return true;
    }
  }
  return false;
}

// --- path building -------------------------------------------------------

// Depth-first search from the leaf towards any trust anchor. Handles
// cross-signed certificates (same subject, multiple certs), duplicate
// subjects, and breaks cycles by fingerprint.
export function buildPaths(leaf, intermediates, trustAnchors, { maxPathLength = 8 } = {}) {
  const anchorsBySubject = new Map();
  for (const a of trustAnchors) {
    const key = a.subjectString;
    if (!anchorsBySubject.has(key)) anchorsBySubject.set(key, []);
    anchorsBySubject.get(key).push(a);
  }
  const interBySubject = new Map();
  for (const c of intermediates) {
    const key = c.subjectString;
    if (!interBySubject.has(key)) interBySubject.set(key, []);
    interBySubject.get(key).push(c);
  }

  const paths = [];
  const visit = (chain, onPath) => {
    const current = chain[chain.length - 1];
    // maxPathLength bounds the number of CA certificates below the leaf.
    if (chain.length - 1 >= maxPathLength) return;
    // Candidate issuers: intermediates first, then trust anchors.
    const candidates = [
      ...(interBySubject.get(current.issuerString) ?? []),
      ...(anchorsBySubject.get(current.issuerString) ?? []),
    ];
    for (const issuer of candidates) {
      if (onPath.has(issuer.fingerprint256)) continue; // cycle guard
      const next = [...chain, issuer];
      if (anchorsBySubject.has(issuer.subjectString) && issuer.isSelfSigned) {
        paths.push(next);
      } else {
        visit(next, new Set([...onPath, issuer.fingerprint256]));
      }
    }
  };
  visit([leaf], new Set([leaf.fingerprint256]));

  // Stable ordering: by anchor fingerprint, then path length, then the
  // fingerprint sequence of the chain. Deterministic across runs.
  const keyOf = (path) =>
    [path[path.length - 1].fingerprint256, String(path.length).padStart(3, '0'),
     ...path.map((c) => c.fingerprint256)].join('|');
  paths.sort((a, b) => (keyOf(a) < keyOf(b) ? -1 : keyOf(a) > keyOf(b) ? 1 : 0));
  return paths;
}

// --- path validation -----------------------------------------------------

function checkCertificateCommon(cert, at) {
  if (cert.unknownCriticalExtensions.length > 0) {
    return { reason: REASON.UNKNOWN_CRITICAL_EXTENSION, detail: cert.unknownCriticalExtensions.join(', ') };
  }
  if (at < cert.notBefore) {
    return { reason: REASON.NOT_YET_VALID, detail: `${cert.subjectString} valid from ${cert.notBefore.toISOString()}` };
  }
  if (at > cert.notAfter) {
    return { reason: REASON.EXPIRED, detail: `${cert.subjectString} expired ${cert.notAfter.toISOString()}` };
  }
  return null;
}

export function validatePath(path, options = {}) {
  const {
    at = new Date(),
    hostname = null,
    purpose = OID.EKU_SERVER_AUTH,
    revocation = null,
  } = options;

  const fail = (reason, detail, certIndex) => ({ ok: false, reason, detail, certIndex });

  const leaf = path[0];
  const anchor = path[path.length - 1];

  // Trust anchor sanity: must be a self-signed CA.
  if (!anchor.isSelfSigned || !verifySignature(anchor, anchor).ok) {
    return fail(REASON.ANCHOR_NOT_SELF_SIGNED, anchor.subjectString, path.length - 1);
  }

  for (let i = 0; i < path.length; i++) {
    const cert = path[i];
    const isLeaf = i === 0;
    const isAnchor = i === path.length - 1;

    const common = checkCertificateCommon(cert, at);
    if (common) return fail(common.reason, common.detail, i);

    if (isRevoked(cert, revocation)) {
      return fail(REASON.REVOKED, `${cert.subjectString} serial ${cert.serialNumber}`, i);
    }

    if (!isLeaf) {
      // CA certificate checks.
      if (!cert.isCA) {
        return fail(REASON.NOT_CA, `${cert.subjectString} has basicConstraints CA=false`, i);
      }
      if (cert.keyUsage && !cert.keyUsage.has('keyCertSign')) {
        return fail(REASON.KEY_USAGE, `${cert.subjectString} keyUsage lacks keyCertSign`, i);
      }
      if (cert.extendedKeyUsage &&
          !cert.extendedKeyUsage.includes(purpose) &&
          !cert.extendedKeyUsage.includes(OID.EKU_ANY)) {
        return fail(REASON.EKU, `${cert.subjectString} EKU does not allow requested purpose`, i);
      }
      // pathLenConstraint: number of non-self-signed CA certs allowed below.
      if (cert.basicConstraints.pathLen !== null) {
        const caBelow = path.slice(1, i).filter((c) => !c.isSelfSigned).length;
        if (caBelow > cert.basicConstraints.pathLen) {
          return fail(REASON.PATH_LENGTH, `${cert.subjectString} pathLenConstraint=${cert.basicConstraints.pathLen} exceeded`, i);
        }
      }
      // Name constraints apply to every certificate below this CA.
      for (let j = 0; j < i; j++) {
        const detail = checkNameConstraintsFor(cert, path[j], j === 0);
        if (detail) return fail(REASON.NAME_CONSTRAINT, detail, i);
      }
    } else {
      // Leaf checks.
      if (cert.extendedKeyUsage &&
          !cert.extendedKeyUsage.includes(purpose) &&
          !cert.extendedKeyUsage.includes(OID.EKU_ANY)) {
        return fail(REASON.EKU, `leaf EKU [${cert.extendedKeyUsage.join(', ')}] lacks requested purpose`, i);
      }
      if (hostname && !matchHostname(cert, hostname)) {
        return fail(REASON.HOSTNAME_MISMATCH, `"${hostname}" not in [${cert.dnsNames().join(', ')}]`, i);
      }
    }

    // Signature link to the issuer (the anchor's self-signature was checked above).
    if (!isAnchor) {
      const sig = verifySignature(cert, path[i + 1]);
      if (!sig.ok) return fail(sig.reason, sig.detail, i);
    }
  }
  return { ok: true };
}

// --- public entry point --------------------------------------------------

function describePath(path) {
  return path.map((c) => ({ subject: c.subjectString, fingerprint256: c.fingerprint256 }));
}

// options: {
//   leaf, intermediates, trustAnchors: PEM strings or Certificate instances
//   hostname, purpose, at, revocation, maxPathLength
// }
export function validateCertificatePath(options) {
  const toCert = (c) => (c instanceof Certificate ? c : Certificate.fromPem(c));
  const leaf = toCert(options.leaf);
  const intermediates = (options.intermediates ?? []).map(toCert);
  const trustAnchors = (options.trustAnchors ?? []).map(toCert);

  const paths = buildPaths(leaf, intermediates, trustAnchors, {
    maxPathLength: options.maxPathLength ?? 8,
  });

  const rejected = [];
  let selected = null;
  for (const path of paths) {
    const result = validatePath(path, options);
    if (result.ok && !selected) {
      selected = { path: describePath(path), anchor: path[path.length - 1].subjectString };
    } else if (!result.ok) {
      rejected.push({ path: describePath(path), reason: result.reason, detail: result.detail });
    } else {
      // Valid but not selected (deterministic ordering picks the first).
      rejected.push({ path: describePath(path), reason: 'valid-but-not-selected', detail: null });
    }
  }

  return {
    ok: selected !== null,
    selected,
    rejected,
    ...(selected === null && paths.length === 0
      ? { reason: REASON.NO_PATH_TO_TRUST }
      : {}),
  };
}

export { Certificate, OID };
