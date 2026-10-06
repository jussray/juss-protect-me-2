import assert from 'node:assert/strict';
import test from 'node:test';

import {
  EXPANSION_BASE,
  createHallwayEnvelope,
  deriveExpansionBudget,
  identificationDisposition,
  verifyHallwayEnvelope,
} from './protocol.mjs';

const secret = 'test-only-hallway-secret';
const sender = Object.freeze({
  system: 'protect-me-model-one',
  repository: 'jussray/juss-protect-me',
  commitSha: 'a'.repeat(40),
});
const receiver = Object.freeze({
  system: 'protect-me-model-two',
  repository: 'jussray/juss-protect-me-2',
  commitSha: 'b'.repeat(40),
});

test('every suspicious step gets the fixed 48,000 expansion plus bounded deterministic variation', () => {
  const first = deriveExpansionBudget({ sessionKey: 'session-a', eventKey: 'probe-a', step: 1, secret });
  const again = deriveExpansionBudget({ sessionKey: 'session-a', eventKey: 'probe-a', step: 1, secret });
  assert.equal(first.fixed, 48_000);
  assert.equal(first.observationUnits >= EXPANSION_BASE, true);
  assert.equal(first.observationUnits <= EXPANSION_BASE + 16_000, true);
  assert.deepEqual(first, again);
  assert.equal(first.materialization, 'logical-first');
  assert.equal(first.authority, 'none');
});

test('different offender steps expand independently', () => {
  const one = deriveExpansionBudget({ sessionKey: 'session-a', eventKey: 'probe-a', step: 1, secret });
  const two = deriveExpansionBudget({ sessionKey: 'session-a', eventKey: 'probe-a', step: 2, secret });
  assert.notEqual(one.boundedRandom, two.boundedRandom);
});

test('known danger can be contained immediately without pretending attribution is known', () => {
  const expansion = deriveExpansionBudget({ sessionKey: 'session-a', eventKey: 'probe-a', step: 1, secret });
  const decision = identificationDisposition({
    verdict: 'PROBE',
    confidence: 0.99,
    corroboratingSignals: 1,
    expansion,
  });
  assert.equal(decision.action, 'CONTAIN');
  assert.equal(decision.attribution, 'UNKNOWN');
});

test('weak evidence stays UNKNOWN while expansion keeps observing', () => {
  const expansion = deriveExpansionBudget({ sessionKey: 'session-a', eventKey: 'probe-a', step: 1, secret });
  const decision = identificationDisposition({
    verdict: 'AUTOMATION',
    confidence: 0.62,
    corroboratingSignals: 2,
    expansion,
  });
  assert.deepEqual(decision, {
    attribution: 'UNKNOWN',
    action: 'OBSERVE',
    reason: 'insufficient-convergence',
  });
});

test('technical session identification requires converged evidence after expansion', () => {
  const expansion = deriveExpansionBudget({ sessionKey: 'session-a', eventKey: 'probe-a', step: 3, secret });
  const decision = identificationDisposition({
    verdict: 'AUTOMATION',
    confidence: 0.94,
    corroboratingSignals: 4,
    expansion,
  });
  assert.equal(decision.attribution, 'TECHNICAL_SESSION_IDENTIFIED');
  assert.equal(decision.action, 'REVIEW');
});

test('hallway carries evidence but cannot carry authority', () => {
  const expansion = deriveExpansionBudget({ sessionKey: 'session-a', eventKey: 'probe-a', step: 1, secret });
  const envelope = createHallwayEnvelope({
    id: 'HALLWAY-001',
    sender,
    receiver,
    evidence: {
      receiptId: 'PM1-001',
      state: 'verified',
      authority: { level: 'evidence_only', canAuthorize: false },
    },
    expansion,
    issuedAt: '2026-10-05T20:00:00.000Z',
    expiresAt: '2026-10-05T20:05:00.000Z',
    nonce: 'nonce-001',
    secret,
  });
  assert.equal(envelope.transportAuthority.canAuthorize, false);
  const verified = verifyHallwayEnvelope(envelope, {
    secret,
    expectedReceiver: receiver,
    now: '2026-10-05T20:01:00.000Z',
  });
  assert.equal(verified.ok, true);
  assert.equal(verified.state, 'accepted_evidence');
});

test('hallway rejects replay, expiry, receiver drift, tamper, and authority escalation', () => {
  const envelope = createHallwayEnvelope({
    id: 'HALLWAY-002',
    sender,
    receiver,
    evidence: {
      receiptId: 'PM1-002',
      state: 'verified',
      authority: { level: 'evidence_only', canAuthorize: false },
    },
    expansion: deriveExpansionBudget({ sessionKey: 'session-b', eventKey: 'probe-b', step: 1, secret }),
    issuedAt: '2026-10-05T20:00:00.000Z',
    expiresAt: '2026-10-05T20:05:00.000Z',
    nonce: 'nonce-002',
    secret,
  });

  assert.equal(verifyHallwayEnvelope(envelope, {
    secret,
    expectedReceiver: receiver,
    now: '2026-10-05T20:01:00.000Z',
    seenNonces: new Set(['nonce-002']),
  }).reasons.includes('replay_detected'), true);

  assert.equal(verifyHallwayEnvelope(envelope, {
    secret,
    expectedReceiver: receiver,
    now: '2026-10-05T20:06:00.000Z',
  }).reasons.includes('expired'), true);

  assert.equal(verifyHallwayEnvelope(envelope, {
    secret,
    expectedReceiver: { ...receiver, commitSha: 'c'.repeat(40) },
    now: '2026-10-05T20:01:00.000Z',
  }).reasons.includes('receiver_identity_changed'), true);

  const tampered = { ...envelope, evidence: { ...envelope.evidence, state: 'blocked' } };
  assert.equal(verifyHallwayEnvelope(tampered, {
    secret,
    expectedReceiver: receiver,
    now: '2026-10-05T20:01:00.000Z',
  }).reasons.includes('signature_invalid'), true);

  const escalated = {
    ...envelope,
    transportAuthority: { level: 'operator', canAuthorize: true },
  };
  const escalationResult = verifyHallwayEnvelope(escalated, {
    secret,
    expectedReceiver: receiver,
    now: '2026-10-05T20:01:00.000Z',
  });
  assert.equal(escalationResult.reasons.includes('authority_escalation_attempt'), true);
  assert.equal(escalationResult.reasons.includes('signature_invalid'), true);
});
