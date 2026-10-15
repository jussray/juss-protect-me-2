import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertEvidenceIdentity,
  canCandidateProceed,
  createEvidenceReceipt,
  evaluateStaleness,
  isGovernedActionEligible,
  shieldObservationToReceipt,
} from './ledger.mjs';

const identity = Object.freeze({
  source: {
    canonicalRemote: 'https://github.com/jussray/juss-protect-me-2.git',
    repository: 'jussray/juss-protect-me-2',
    branch: 'main',
    commitSha: 'a'.repeat(40),
  },
  dependency: {
    lockfilePath: 'package-lock.json',
    lockfileSha256: 'c'.repeat(64),
    packageManager: 'npm',
  },
  runtime: {
    environment: 'production',
    buildId: 'build-100',
    deploymentUrl: 'https://security.example.test',
  },
});

function receipt(overrides = {}) {
  return createEvidenceReceipt({
    id: 'SEC-001',
    findingId: 'FINDING-001',
    check: 'focused_test',
    state: 'verified',
    observedAt: '2026-10-05T18:00:00.000Z',
    identity,
    summary: 'Focused defensive test passed against the exact candidate identity.',
    evidenceRefs: ['artifact://focused-test/SEC-001'],
    ...overrides,
  });
}

test('short Git SHA cannot become source authority', () => {
  assert.throws(() => assertEvidenceIdentity({
    ...identity,
    source: { ...identity.source, commitSha: 'abc1234' },
  }), /full 40-character Git SHA/);
});

test('security evidence is evidence-only and cannot self-authorize', () => {
  const r = receipt();
  assert.deepEqual(r.authority, { level: 'evidence_only', canAuthorize: false });
});

test('source, dependency, and runtime changes make proof stale', () => {
  const r = receipt();
  const changed = {
    source: { ...identity.source, commitSha: 'b'.repeat(40) },
    dependency: { ...identity.dependency, lockfileSha256: 'd'.repeat(64) },
    runtime: { ...identity.runtime, buildId: 'build-101' },
  };
  const result = evaluateStaleness(r, changed);
  assert.equal(result.state, 'stale');
  assert.deepEqual(result.invalidatedBy, [
    'source_identity_changed',
    'dependency_identity_changed',
    'runtime_identity_changed',
  ]);
});

test('every required check needs its own current verified receipt', () => {
  const receipts = [receipt({ check: 'lint' }), receipt({ id: 'SEC-002', check: 'focused_test' })];
  assert.equal(canCandidateProceed(receipts, ['lint', 'focused_test', 'playwright'], identity), false);
});

test('a separate blocked receipt prevents governed action', () => {
  const receipts = [
    receipt({ check: 'focused_test' }),
    receipt({ id: 'SEC-002', check: 'playwright' }),
    createEvidenceReceipt({
      id: 'SEC-003',
      findingId: 'FINDING-003',
      check: 'live_provider_smoke',
      state: 'blocked',
      observedAt: '2026-10-05T18:00:00.000Z',
      identity,
      summary: 'Provider identity is not yet proven.',
      evidenceRefs: [],
    }),
  ];
  assert.equal(isGovernedActionEligible({
    receipts,
    requiredChecks: ['focused_test', 'playwright'],
    currentIdentity: identity,
    authorization: {
      kind: 'founder_approval',
      approvalId: 'APPROVAL-001',
      repository: identity.source.repository,
      commitSha: identity.source.commitSha,
    },
  }), false);
});

test('receipt id cannot masquerade as founder authorization', () => {
  const receipts = [receipt()];
  assert.equal(isGovernedActionEligible({
    receipts,
    requiredChecks: ['focused_test'],
    currentIdentity: identity,
    authorization: {
      kind: 'founder_approval',
      approvalId: 'SEC-001',
      repository: identity.source.repository,
      commitSha: identity.source.commitSha,
    },
  }), false);
});

test('exact separate founder approval can authorize only after required proof is current', () => {
  const receipts = [receipt({ check: 'focused_test' }), receipt({ id: 'SEC-002', check: 'playwright' })];
  assert.equal(isGovernedActionEligible({
    receipts,
    requiredChecks: ['focused_test', 'playwright'],
    currentIdentity: identity,
    authorization: {
      kind: 'founder_approval',
      approvalId: 'APPROVAL-001',
      repository: identity.source.repository,
      commitSha: identity.source.commitSha,
    },
  }), true);
});

test('authenticated Shield observation becomes verified evidence, not authority', () => {
  const observation = {
    event: { service: 'portfolio-api', verdict: 'PROBE' },
    receipt: 'e'.repeat(64),
    receiptKind: 'hmac-sha256',
  };
  const r = shieldObservationToReceipt(observation, identity, '2026-10-05T18:00:00.000Z');
  assert.equal(r.state, 'verified');
  assert.equal(r.check, 'shield_event');
  assert.equal(r.authority.canAuthorize, false);
});

test('unauthenticated Shield digest remains inferred', () => {
  const observation = {
    event: { service: 'portfolio-api', verdict: 'AUTOMATION' },
    receipt: 'f'.repeat(64),
    receiptKind: 'sha256-unauthenticated',
  };
  const r = shieldObservationToReceipt(observation, identity, '2026-10-05T18:00:00.000Z');
  assert.equal(r.state, 'inferred');
});

const approval = () => ({
  kind: 'founder_approval',
  approvalId: 'APPROVAL-001',
  repository: identity.source.repository,
  commitSha: identity.source.commitSha,
});

test('a newer pass supersedes an old failure for the same check (history is not deleted)', () => {
  const receipts = [
    receipt({ id: 'SEC-010', check: 'focused_test', state: 'failed', evidenceRefs: [], observedAt: '2026-10-05T17:00:00.000Z' }),
    receipt({ id: 'SEC-011', check: 'focused_test', observedAt: '2026-10-05T18:00:00.000Z' }),
  ];
  assert.equal(isGovernedActionEligible({ receipts, requiredChecks: ['focused_test'], currentIdentity: identity, authorization: approval() }), true);
});

test('a newer failure overrides an older pass for the same check', () => {
  const receipts = [
    receipt({ id: 'SEC-020', check: 'focused_test', observedAt: '2026-10-05T17:00:00.000Z' }),
    receipt({ id: 'SEC-021', check: 'focused_test', state: 'failed', evidenceRefs: [], observedAt: '2026-10-05T18:00:00.000Z' }),
  ];
  assert.equal(canCandidateProceed(receipts, ['focused_test'], identity), false);
  assert.equal(isGovernedActionEligible({ receipts, requiredChecks: ['focused_test'], currentIdentity: identity, authorization: approval() }), false);
});

test('a simultaneous failure is never hidden by a simultaneous pass', () => {
  const receipts = [
    receipt({ id: 'SEC-030', check: 'focused_test' }),
    receipt({ id: 'SEC-031', check: 'focused_test', state: 'failed', evidenceRefs: [] }),
  ];
  assert.equal(isGovernedActionEligible({ receipts, requiredChecks: ['focused_test'], currentIdentity: identity, authorization: approval() }), false);
});


test('privacy guard rejects raw conversation content and unsafe references in receipts', () => {
  for (const summary of ['user: private conversation\nassistant: response', 'member@example.org', '"role":"assistant"']) {
    assert.throws(() => receipt({ summary }), /private (?:conversation )?content is forbidden in evidence/);
  }
  assert.throws(() => receipt({ evidenceRefs: ['api_key=do-not-log-this'] }), /private content is forbidden in evidence/);
  assert.throws(() => receipt({ evidenceRefs: [{ role: 'user', content: 'private' }] }), /must contain only non-empty strings/);
  assert.throws(() => receipt({ identity: {
    ...identity, runtime: { ...identity.runtime, metadata: { cookie: 'do-not-log' } },
  } }), /raw sensitive field is forbidden in evidence/);
});
