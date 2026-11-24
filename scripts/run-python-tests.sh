#!/usr/bin/env bash
set -euo pipefail
python_bin=python3
check_dependency() {
  "$1" -c 'from importlib.metadata import version; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey; assert version("cryptography") == "46.0.4"' >/dev/null 2>&1
}
if ! check_dependency "$python_bin"; then
  test_venv=$(mktemp -d)
  trap 'rm -rf -- "$test_venv"' EXIT
  python3 -m venv "$test_venv"
  python_bin="$test_venv/bin/python"
  "$python_bin" -m pip install --disable-pip-version-check 'cryptography==46.0.4'
  check_dependency "$python_bin"
fi
"$python_bin" gate/test_worlds_gate.py
"$python_bin" contract/scripts/test_preflight.py
"$python_bin" -m unittest discover -s contract/medusa -p 'test_medusa*.py' -q
"$python_bin" -m unittest discover -s contract/medusa -p 'test_authority_grant*.py' -q
"$python_bin" -m unittest discover -s contract/medusa/detection -p 'test_detect*.py' -q
"$python_bin" -m unittest discover -s contract/medusa -p 'test_eventbus.py' -q
"$python_bin" -m unittest discover -s contract/medusa/detection -p 'test_bus_adapter.py' -q
"$python_bin" -m unittest discover -s contract/medusa/actuator -p 'test_actuator_guard.py' -q
"$python_bin" -m unittest discover -s contract/medusa -p 'test_config_runtime.py' -q
