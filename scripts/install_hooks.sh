#!/bin/sh
set -e

HOOK_PATH=".git/hooks/pre-commit"

echo "[install_hooks] Installing pre-commit validation hook to ${HOOK_PATH}..."
cat <<'HOOK' > "${HOOK_PATH}"
#!/bin/sh
set -e

echo "[pre-commit] Checking Python syntax across control plane..."
python3 -m compileall -q core harnesses scripts tests

echo "[pre-commit] Running full test suite under -W error::ResourceWarning..."
python3 -W error::ResourceWarning -m unittest discover -s tests -v

echo "[pre-commit] All invariants and bounds passed cleanly."
HOOK

chmod +x "${HOOK_PATH}"
echo "[install_hooks] Pre-commit hook installed successfully."
