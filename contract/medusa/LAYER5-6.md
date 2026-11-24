# Medusa Layer 5–6: opt-in local config integrity

Status: LAB ONLY / NO AUTOMATIC ACTUATION.

This extends the existing canonical signed Layer 2 bus and Layer 3
detector. It does not replace their files or modify the existing inert
Layer 4 guard. It monitors only explicitly listed local config files,
hashes each file without following symlinks, compares with signed prior
observations, and emits signed change events. File contents and original
pathnames never enter the evidence bus. First observations are baselines,
not evidence of compromise.

The supervisor connects sensor -> authenticated event bus -> rules ->
signed detector feedback in a bounded lab invocation. It never quarantines,
restarts services, revokes accounts, acts on customer data, or auto-deploys.

## Run

Provision MEDUSA_TRUSTED_SENSORS outside the repository as protected
JSON with independently registered public keys for config-1 and
detect-1, and provide their distinct private keys (mode 0600).
Set MEDUSA_BUS_DIR to a private 0700 directory.

Run from the repo root:

    MEDUSA_LAB_MODE=1 python3 contract/medusa/medusa_daemon.py \
      --path /absolute/path/to/approved-local-config \
      --sensor-key /private/config-1.pem \
      --rules contract/medusa/detection/rules.config.json \
      --detect-key /private/detect-1.pem

Without the detect key, the supervisor reports findings but does not
append signed detection feedback. Repeat using explicit --cycles
(1..10) and --interval-s (1..300) for bounded lab checks only.
Do not configure a production scheduler yet.

## Fail-closed boundaries

- External sensor registration and key custody are mandatory. Missing or
  altered trust files block the run.
- Symlink, hardlink, oversized, non-regular, replaced or racing files fail.
  No silent resync, repair, enrollment, or secret disclosure.
- The signed bus provides local integrity and prefix checks, not
  external time, off-host custody, or proof of sensor truth.
- Layer 4 continues to return HOLD. No authorization or real filesystem
  response is generated from a finding.
- A changed/missing config is suspicious, not proof of malicious intent.
- This is a local opt-in file-integrity sensor, not complete endpoint
  monitoring, process tracing, production containment or autonomous recovery.

## Tests

    python3 -m unittest discover -s contract/medusa -p 'test_config_runtime.py' -v

The active npm test command on this branch includes this test. Future
release checks must also cover longer-lived concurrency, event budgets,
trusted-head external anchoring, crash recovery, and safe rollback before
any executable actuator is considered.
