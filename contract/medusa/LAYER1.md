# Medusa Layer 1: Offline authority scoping

This module implements the **permission model only** for the existing Medusa A–D security-review toolkit. It makes **no network connections**, runs no sensors, does not classify threats, does not execute an actuator, and cannot independently authorize a deployment. This is not a claim of live protection.

## Compatibility and trust boundary

- Python 3.10+ on POSIX (file locking via `fcntl`), `cryptography==46.0.4` for Ed25519 signatures.
- Medusa A–D remain separately executable, standard-library-only and offline.
- `MEDUSA_TRUSTED_SIGNERS` points to an **externally authorized, protected** JSON trust root. This module never creates a signer or decides who should be trusted. Key custody and identity verification are **outside** this module. Never add private keys to repositories.
- `MEDUSA_GRANTS_DIR` points to a private directory (0700 recommended). Grants are exclusive-create, non-overwriting files (0600); revocations are separate signed records. A local chained Ed25519-signed audit log records issue/revoke; this is **not independently anchored**. A privileged attacker who rewrites the whole trust store and log may defeat it, and tail truncation of a valid log cannot be detected without an external head anchor.

## Trust file shape (example; placeholder key will NOT work)

```json
{
  "signers": [
    {
      "decider": "alice",
      "public_key_b64": "REPLACE_WITH_32_BYTE_ED25519_PUBLIC_KEY_BASE64",
      "authority": {
        "action_classes": ["quarantine_file", "block_deploy", "log_only"],
        "target_scopes": ["/srv/apps"],
        "excluded_paths": ["/srv/apps/secrets"],
        "max_blast_radius": 5,
        "min_evidence_tag": "VERIFIED",
        "min_detection_severity": "High",
        "expires_at": "2026-12-01T00:00:00Z",
        "can_delegate": true,
        "max_delegation_depth": 2
      }
    },
    { "decider": "bob", "public_key_b64": "REPLACE_WITH_BOBS_PUBLIC_KEY_BASE64" }
  ]
}
```

This illustration is not an endorsement of the sample expiry, scope, or deciders. A separately verified owner must provision the real trust root and keys.

## Commands (offline)

```bash
python3 contract/medusa/authority_grant.py issue \
  --decider alice --key /private/alice-ed25519.pem \
  --action-class quarantine_file --target-scope /srv/apps/payments \
  --blast-radius 2 --severity High --hours 6 \
  --grant-id example-grant
python3 contract/medusa/authority_grant.py verify example-grant
python3 contract/medusa/authority_grant.py audit
python3 contract/medusa/authority_grant.py revoke example-grant \
  --decider alice --key /private/alice-ed25519.pem
python3 contract/medusa/authority_grant.py list
```

The commands are not runnable until an authorized signer has been configured. `verify` checks the current grant, parent chain, local audit and revocation, but does not emit an execution token or override the existing A–D release HOLD.

## Invariants and deliberate restrictions

1. A signed grant binds the **specific named decider** to their own Ed25519 signing key. Identity trust itself comes from the external, tightly controlled signer configuration.
2. Root grant capabilities are bounded by the signer's explicit allowed classes, scopes, maximum blast radius, severity/evidence thresholds, delegation rights and expiry. Delegation is verified **before issuance** and again on each verification. Revoked ancestors invalidate their descendants.
3. Severity minimum is monotonic (`High` → `Critical` narrows; the reverse widens). Automatic grants require `VERIFIED` evidence. Source signatures and hash identity **do not by themselves establish truth**.
4. Path scopes are absolute, normalized and component-separated, and parents cannot permit children to enter excluded areas. An actuator must independently validate the target's actual filesystem identity at action time, using opened handles and current configuration to prevent symlink/TOCTOU bypass.
5. Only `log_only`, `block_deploy`, and `quarantine_file` are structurally auto-grantable **for future integration**. Actual reversibility has NOT been proven for any actuator. `revoke_token`, `isolate_host`, `delete_file`, `encrypt_file`, `transfer_ownership` and `reject_request` are manual-only; expanding this registry requires independent review and proof of compensating action.
6. Grants expire and are checked at verification time; future detection/action layers must independently verify signed detection timestamps, the grant at detection time **and again immediately before action**. No user-supplied timestamp may independently establish authority.
7. An undo token is not produced in Layer 1 because no actuator exists. This layer never claims otherwise. An actuator MUST fail closed if it cannot precompute and record an independently verified compensating action.
8. Signed audit rows protect local integrity; there is no external immutable anchor, real-time monitoring, or production response. A missing, altered or revoked grant is blocked.

## Verification

```bash
python3 -m unittest discover -s contract/medusa -p 'test_authority_grant*.py' -v
```

The tests are synthetic and deliberately do not probe live systems. Running them does **not** prove that A–D is deployable or that any real-world security action is safe. Keep Medusa offline and the release gate on HOLD until separate authorized integration/real-path proof exists.
