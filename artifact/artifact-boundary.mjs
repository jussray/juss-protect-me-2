export const ARTIFACT_BOUNDARY_SCHEMA = 'protect-me/artifact-boundary@v1';

export const ARTIFACT_SOURCES = Object.freeze([
  'user',
  'retrieval',
  'web',
  'email',
  'ticket',
  'tool_output',
  'file',
  'ocr',
  'image',
]);

export const ARTIFACT_SIGNALS = Object.freeze([
  'instruction_override',
  'role_impersonation',
  'secret_exfiltration',
  'tool_invocation',
  'approval_bypass',
  'policy_evasion',
  'encoded_payload',
  'prompt_leak_request',
]);

const SOURCE_SET = new Set(ARTIFACT_SOURCES);
const SHA256 = /^[0-9a-f]{64}$/i;

const SIGNAL_PATTERNS = Object.freeze([
  ['instruction_override', /\b(ignore|disregard|override|forget)\b.{0,80}\b(previous|prior|system|developer|instructions?)\b/i],
  ['role_impersonation', /\b(system message|developer message|admin instruction|root access)\b/i],
  ['secret_exfiltration', /\b(export|send|upload|exfiltrate|reveal)\b.{0,120}\b(secret|token|api key|password|credential|database)\b/i],
  ['tool_invocation', /\b(call|invoke|run|execute)\b.{0,80}\b(api|tool|command|function|terminal)\b/i],
  ['approval_bypass', /\b(without|skip|bypass)\b.{0,80}\b(approval|confirmation|review|authorization)\b/i],
  ['policy_evasion', /\b(do not mention|hide this|keep this secret|do not log)\b/i],
  ['encoded_payload', /\b(base64|rot13|hex encoded|decode this)\b/i],
  ['prompt_leak_request', /\b(show|reveal|print|repeat)\b.{0,80}\b(system prompt|hidden prompt|developer instructions)\b/i],
]);

const SIGNAL_WEIGHTS = Object.freeze({
  instruction_override: 0.35,
  role_impersonation: 0.25,
  secret_exfiltration: 0.7,
  tool_invocation: 0.25,
  approval_bypass: 0.6,
  policy_evasion: 0.4,
  encoded_payload: 0.15,
  prompt_leak_request: 0.35,
});

function clean(value) {
  return String(value ?? '').trim();
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function bytesToHex(buffer) {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function artifactContentHash(content) {
  const bytes = new TextEncoder().encode(String(content ?? ''));
  return bytesToHex(await crypto.subtle.digest('SHA-256', bytes));
}

export async function createArtifact({ id, source, content, uri, authorId }) {
  const normalizedContent = typeof content === 'string' ? content : JSON.stringify(stable(content));
  return Object.freeze({
    id: clean(id),
    source: clean(source),
    content: normalizedContent,
    contentHash: await artifactContentHash(normalizedContent),
    ...(uri ? { uri: clean(uri) } : {}),
    ...(authorId ? { authorId: clean(authorId) } : {}),
  });
}

export async function normalizeToolOutputArtifact({ id, result, uri, authorId }) {
  return createArtifact({ id, source: 'tool_output', content: result, uri, authorId });
}

export async function validateArtifact(artifact) {
  const errors = [];
  const id = clean(artifact?.id);
  const source = clean(artifact?.source);
  const content = typeof artifact?.content === 'string' ? artifact.content : '';
  const contentHash = clean(artifact?.contentHash).toLowerCase();

  if (!id) errors.push('artifact id is required');
  if (id.length > 160) errors.push('artifact ' + (id || '<unknown>') + ' id exceeds 160 characters');
  if (!SOURCE_SET.has(source)) errors.push('artifact ' + (id || '<unknown>') + ' has unsupported source');
  if (!content.trim()) errors.push('artifact ' + (id || '<unknown>') + ' content is required');
  if (content.length > 50_000) errors.push('artifact ' + (id || '<unknown>') + ' content exceeds 50000 characters');
  if (!SHA256.test(contentHash)) {
    errors.push('artifact ' + (id || '<unknown>') + ' contentHash must be sha256');
  } else if (await artifactContentHash(content) !== contentHash) {
    errors.push('artifact ' + (id || '<unknown>') + ' contentHash does not match content');
  }

  if (artifact?.uri) {
    try {
      const parsed = new URL(artifact.uri);
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
        errors.push('artifact ' + (id || '<unknown>') + ' uri must be credential-free https');
      }
    } catch {
      errors.push('artifact ' + (id || '<unknown>') + ' uri is invalid');
    }
  }

  if (artifact?.authorId && clean(artifact.authorId).length > 300) {
    errors.push('artifact ' + (id || '<unknown>') + ' authorId exceeds 300 characters');
  }

  return errors;
}

export function classifyArtifact(artifact) {
  const signals = SIGNAL_PATTERNS
    .filter(([, pattern]) => pattern.test(artifact.content))
    .map(([signal]) => signal);
  const uniqueSignals = [...new Set(signals)];
  const score = Math.min(1, uniqueSignals.reduce((total, signal) => total + SIGNAL_WEIGHTS[signal], 0));

  // Direct user text may legitimately contain instructions. Retrieved/tool/file content
  // receives stricter thresholds because quoted material must never gain authority.
  const externalSource = artifact.source !== 'user';
  const excludeThreshold = externalSource ? 0.65 : 0.9;
  const quarantineThreshold = externalSource ? 0.35 : 0.6;
  const disposition = score >= excludeThreshold ? 'exclude'
    : score >= quarantineThreshold ? 'quarantine'
      : 'allow';

  return Object.freeze({
    artifactId: clean(artifact.id),
    source: artifact.source,
    contentHash: clean(artifact.contentHash).toLowerCase(),
    score,
    signals: Object.freeze(uniqueSignals),
    disposition,
  });
}

export async function evaluateArtifactBoundary(artifacts = []) {
  const errors = [];
  const ids = new Set();
  const validForClassification = [];

  for (const artifact of artifacts) {
    const artifactErrors = await validateArtifact(artifact);
    errors.push(...artifactErrors);
    const id = clean(artifact?.id);
    if (ids.has(id)) errors.push('duplicate artifact id: ' + id);
    ids.add(id);
    if (artifactErrors.length === 0) validForClassification.push(artifact);
  }

  const risks = validForClassification.map(classifyArtifact);
  const quarantinedArtifactIds = risks.filter((risk) => risk.disposition === 'quarantine').map((risk) => risk.artifactId);
  const excludedArtifactIds = risks.filter((risk) => risk.disposition === 'exclude').map((risk) => risk.artifactId);
  const uniqueErrors = [...new Set(errors)];

  return Object.freeze({
    schema: ARTIFACT_BOUNDARY_SCHEMA,
    observed: artifacts.length > 0,
    artifactCount: artifacts.length,
    risks: Object.freeze(risks),
    quarantinedArtifactIds: Object.freeze(quarantinedArtifactIds),
    excludedArtifactIds: Object.freeze(excludedArtifactIds),
    errors: Object.freeze(uniqueErrors),
    plannerInputAllowed: uniqueErrors.length === 0
      && quarantinedArtifactIds.length === 0
      && excludedArtifactIds.length === 0,
    toolOutputReentryRequired: true,
  });
}
