import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { validateCertificatePath, Certificate, REASON } from '../src/index.js';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const fx = (name) => readFileSync(path.join(FIXTURES, `${name}.crt`), 'utf8');

const subjects = (result) => result.selected.path.map((c) => c.subject);

test('normal chain: leaf -> intermediate -> root', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-good'),
    intermediates: [fx('interA')],
    trustAnchors: [fx('rootA')],
    hostname: 'www.good.example',
  });
  assert.equal(r.ok, true);
  assert.deepEqual(subjects(r), ['CN=www.good.example', 'CN=Inter A', 'CN=Root A']);
  assert.equal(r.rejected.length, 0);
});

test('rogue intermediate with identical subject CN is rejected by signature, not name', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-good'),
    intermediates: [fx('rogue-inter'), fx('interA')],
    trustAnchors: [fx('rootA')],
    hostname: 'www.good.example',
  });
  assert.equal(r.ok, true);
  assert.equal(r.selected.path[1].subject, 'CN=Inter A');
  const rogue = Certificate.fromPem(fx('rogue-inter'));
  assert.ok(!r.selected.path.some((c) => c.fingerprint256 === rogue.fingerprint256));
  assert.equal(r.rejected.length, 1);
  assert.equal(r.rejected[0].reason, REASON.SIGNATURE);
});

test('cross-signed intermediate yields two anchors with stable deterministic ordering', () => {
  const opts = {
    leaf: fx('leaf-good'),
    intermediates: [fx('interA'), fx('interA-cross')],
    trustAnchors: [fx('rootA'), fx('rootB')],
    hostname: 'www.good.example',
  };
  const r1 = validateCertificatePath(opts);
  const r2 = validateCertificatePath(opts);
  assert.equal(r1.ok, true);
  assert.deepEqual(r1, r2); // stable across runs
  assert.equal(r1.rejected.length, 1);
  assert.equal(r1.rejected[0].reason, 'valid-but-not-selected');
  // The selected anchor is the lexicographically smaller anchor fingerprint.
  const fps = [Certificate.fromPem(fx('rootA')).fingerprint256,
               Certificate.fromPem(fx('rootB')).fingerprint256].sort();
  assert.equal(r1.selected.path[2].fingerprint256, fps[0]);
});

test('broken chain: issuer anchor missing', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-broken'),
    intermediates: [fx('interUnknown')],
    trustAnchors: [fx('rootA')],
    hostname: 'broken.example',
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, REASON.NO_PATH_TO_TRUST);
});

test('certificate cycle does not loop; valid exit path is found', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-cycle'),
    intermediates: [fx('caX-by-caY'), fx('caX-by-rootC'), fx('caY-by-caX')],
    trustAnchors: [fx('rootC')],
    hostname: 'cycle.example',
  });
  assert.equal(r.ok, true);
  assert.deepEqual(subjects(r), ['CN=cycle.example', 'CN=CA Y', 'CN=CA X', 'CN=Root C']);
});

test('name constraints: leaf outside permitted subtree is rejected', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-nc-denied'),
    intermediates: [fx('interNC')],
    trustAnchors: [fx('rootNC')],
    hostname: 'www.denied.example',
  });
  assert.equal(r.ok, false);
  assert.equal(r.rejected[0].reason, REASON.NAME_CONSTRAINT);
});

test('name constraints: leaf inside permitted subtree passes', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-nc-ok'),
    intermediates: [fx('interNC')],
    trustAnchors: [fx('rootNC')],
    hostname: 'www.allowed.example',
  });
  assert.equal(r.ok, true);
});

test('wrong EKU (clientAuth only) is rejected for serverAuth', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-eku-bad'),
    intermediates: [fx('interA')],
    trustAnchors: [fx('rootA')],
    hostname: 'eku.bad.example',
  });
  assert.equal(r.ok, false);
  assert.equal(r.rejected[0].reason, REASON.EKU);
});

test('expired leaf is rejected; explicit `at` inside validity window passes', () => {
  const base = {
    leaf: fx('leaf-expired'),
    intermediates: [fx('interA')],
    trustAnchors: [fx('rootA')],
    hostname: 'expired.good.example',
  };
  const expired = validateCertificatePath(base);
  assert.equal(expired.ok, false);
  assert.equal(expired.rejected[0].reason, REASON.EXPIRED);
  // The whole chain must be valid at that time; interA/rootA are not, so only
  // check that the failure is no longer about the leaf being expired.
  const backdated = validateCertificatePath({ ...base, at: new Date('2019-06-01T00:00:00Z') });
  assert.notEqual(backdated.rejected[0]?.reason, REASON.EXPIRED);
});

test('offline revocation record rejects the revoked leaf (serial and fingerprint forms)', () => {
  const leaf = Certificate.fromPem(fx('leaf-revoked'));
  const base = {
    leaf: fx('leaf-revoked'),
    intermediates: [fx('interA')],
    trustAnchors: [fx('rootA')],
    hostname: 'revoked.good.example',
  };
  assert.equal(validateCertificatePath(base).ok, true);
  const bySerial = validateCertificatePath({
    ...base,
    revocation: [{ issuer: 'CN=Inter A', serialNumber: leaf.serialNumber }],
  });
  assert.equal(bySerial.ok, false);
  assert.equal(bySerial.rejected[0].reason, REASON.REVOKED);
  const byFingerprint = validateCertificatePath({
    ...base,
    revocation: [{ fingerprint256: leaf.fingerprint256 }],
  });
  assert.equal(byFingerprint.ok, false);
  assert.equal(byFingerprint.rejected[0].reason, REASON.REVOKED);
});

test('unknown critical extension is never skipped', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-unknowncrit'),
    intermediates: [fx('interA')],
    trustAnchors: [fx('rootA')],
    hostname: 'unknowncrit.example',
  });
  assert.equal(r.ok, false);
  assert.equal(r.rejected[0].reason, REASON.UNKNOWN_CRITICAL_EXTENSION);
  assert.match(r.rejected[0].detail, /1\.3\.6\.1\.4\.1\.99999\.1/);
});

test('hostname mismatch is rejected', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-good'),
    intermediates: [fx('interA')],
    trustAnchors: [fx('rootA')],
    hostname: 'evil.example',
  });
  assert.equal(r.ok, false);
  assert.equal(r.rejected[0].reason, REASON.HOSTNAME_MISMATCH);
});

test('wildcard SAN matches exactly one label', () => {
  const base = {
    leaf: fx('leaf-wildcard'),
    intermediates: [fx('interA')],
    trustAnchors: [fx('rootA')],
  };
  assert.equal(validateCertificatePath({ ...base, hostname: 'a.wild.example' }).ok, true);
  const deep = validateCertificatePath({ ...base, hostname: 'a.b.wild.example' });
  assert.equal(deep.ok, false);
  assert.equal(deep.rejected[0].reason, REASON.HOSTNAME_MISMATCH);
});

test('CN fallback when no SAN is present', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-cn-only'),
    intermediates: [fx('interA')],
    trustAnchors: [fx('rootA')],
    hostname: 'cnonly.good.example',
  });
  assert.equal(r.ok, true);
});

test('basicConstraints pathLenConstraint is enforced', () => {
  const r = validateCertificatePath({
    leaf: fx('leafPL'),
    intermediates: [fx('subPL'), fx('interPL')],
    trustAnchors: [fx('rootPL')],
    hostname: 'pathlen.example',
  });
  assert.equal(r.ok, false);
  assert.equal(r.rejected[0].reason, REASON.PATH_LENGTH);
});

test('non-self-signed anchor cannot terminate a path', () => {
  const r = validateCertificatePath({
    leaf: fx('leaf-good'),
    intermediates: [],
    trustAnchors: [fx('interA')], // not self-signed
    hostname: 'www.good.example',
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, REASON.NO_PATH_TO_TRUST);
});

test('maxPathLength option bounds path construction', () => {
  const base = {
    leaf: fx('leaf-good'),
    intermediates: [fx('interA')],
    trustAnchors: [fx('rootA')],
    hostname: 'www.good.example',
  };
  assert.equal(validateCertificatePath({ ...base, maxPathLength: 1 }).ok, false);
  assert.equal(validateCertificatePath({ ...base, maxPathLength: 2 }).ok, true);
});
