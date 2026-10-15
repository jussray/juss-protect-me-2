import { assertPrivateContentAbsent } from '../evidence/privacy.mjs';
const annot = Object.freeze({ readOnlyHint: true, destructiveHint: false, openWorldHint: false });
const STATES = Object.freeze(['verified','inferred','unknown','blocked','failed','stale']);
function screenKeys(args) {
  if (!args || !Array.isArray(args.keys) || args.keys.length > 32 || Object.keys(args).some(k=>k!=='keys')) throw new Error('invalid input');
  let blockedCount = 0;
  for (const key of args.keys) {
    if (typeof key !== 'string' || !/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(key)) throw new Error('invalid key');
    try { assertPrivateContentAbsent({ [key]: 'placeholder' }); }
    catch { blockedCount++; }
  }
  return { state:blockedCount?'BLOCKED':'NO_KNOWN_SENSITIVE_FIELD',
    checked:args.keys.length,blockedCount,guarantee:false,inputReflected:false };
}
function assessGate(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args) ||
      !Array.isArray(args.checks) || args.checks.length > 20 ||
      !Array.isArray(args.requiredChecks) || args.requiredChecks.length > 20 ||
      Object.keys(args).some(x=>!['checks','requiredChecks'].includes(x))) throw new Error('bad input');
  const names = new Set(), mapped = new Map();
  for (const c of args.checks) {
    if (!c || typeof c.name !== 'string' || !/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(c.name) ||
        !STATES.includes(c.state) || typeof c.identityMatches !== 'boolean' ||
        Object.keys(c).some(x=>!['name','state','identityMatches'].includes(x)) ||
        names.has(c.name)) throw new Error('invalid check');
    names.add(c.name); mapped.set(c.name,c);
  }
  const required = new Set();
  for (const name of args.requiredChecks) {
    if (typeof name !== 'string' || !/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(name) || required.has(name)) throw new Error('invalid requirement');
    required.add(name);
  }
  const bad = args.checks.some(c=>c.state!=='verified'||!c.identityMatches);
  const complete = required.size>0 && [...required].every(name=>mapped.get(name)?.state==='verified'&&mapped.get(name)?.identityMatches);
  return { inputReportedOnly:true, independentProof:false, ownerApprovalGranted:false,
    advisoryState:complete&&!bad?'REVIEW_CANDIDATE':'BLOCKED_OR_UNVERIFIED',
    canAuthorizeMergeOrDeploy:false,checks:args.checks.length,required:required.size };
}
export const mcpApplication = Object.freeze({
  name:'juss-protect-me-2',
  tools:[
    {name:'protect_me_2_status',title:'Protect Me 2 status',
      description:'Report infrastructure security scope. Cannot independently read repos, chat history, or runtime.',
      annotations:annot,inputSchema:{type:'object',properties:{},additionalProperties:false}},
    {name:'protect_me_2_gate_readiness',title:'Evidence gate dry-run',
      description:'Dry-run with status metadata only. Input-reported results are never independent proof or authorization.',
      annotations:annot,inputSchema:{type:'object',additionalProperties:false,required:['checks','requiredChecks'],
        properties:{
          checks:{type:'array',maxItems:20,items:{type:'object',additionalProperties:false,required:['name','state','identityMatches'],
            properties:{name:{type:'string'},state:{type:'string',enum:STATES},identityMatches:{type:'boolean'}}}},
          requiredChecks:{type:'array',maxItems:20,items:{type:'string'}}
        }}},
    {name:'protect_me_2_evidence_keys',title:'Evidence field-name screening',
      description:'Screen field names only; never send private values or raw chat transcripts.',
      annotations:annot,inputSchema:{type:'object',additionalProperties:false,required:['keys'],
        properties:{keys:{type:'array',maxItems:32,items:{type:'string',maxLength:64}}}}},
  ],
  handlers:{
    protect_me_2_status(args) {
      if (!args || typeof args!=='object'||Array.isArray(args)||Object.keys(args).length) throw new Error('bad input');
      return {system:'Model Two',status:'READ_ONLY_ADAPTER',chatHistoryAccess:false,automatedEnforcement:false,
        independentRuntimeVerification:false,canAuthorizeMergeOrDeploy:false};
    },
    protect_me_2_gate_readiness:assessGate,
    protect_me_2_evidence_keys:screenKeys,
  },
});
