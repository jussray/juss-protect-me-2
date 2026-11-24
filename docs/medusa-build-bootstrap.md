# Python test bootstrap

The default npm test command retains the full existing Node test list and all nine Python test invocations. The Python wrapper reuses the current interpreter if cryptography 46.0.4 and its Ed25519 import are available. Otherwise it creates an isolated temporary virtual environment, installs the pinned dependency, and executes every Python test through that interpreter. Setup and test failures remain fatal. No production dependency, deployment authorization, security gate, or archive is changed.

Local proof: Bash syntax passed; mocked interpreter checks passed for installed dependency, missing dependency (including pinned install invocation and all nine suites), and propagation of a failing test exit code. Actual dependency installation and complete test execution on the new Git commit remain to be verified by CI.
