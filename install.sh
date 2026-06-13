#!/usr/bin/env sh
# Comprehensive installer for cognis-digital/kycaml (Linux / macOS).
# Tries pipx -> uv -> pip (git+https) -> from source. Not on PyPI; installs from GitHub.
set -eu
REPO="kycaml"
URL="git+https://github.com/cognis-digital/kycaml.git"
GITURL="https://github.com/cognis-digital/kycaml.git"
say() { printf '\033[1;35m[%s]\033[0m %s\n' "$REPO" "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
if ! have python3 && ! have python; then
  say "Python 3.9+ is required but was not found. Install Python first."; exit 1
fi
if have pipx; then say "Installing with pipx..."; pipx install "$URL" && { say "Done. Run: kycaml --help"; exit 0; }; fi
if have uv; then say "Installing with uv..."; uv tool install "$URL" && { say "Done. Run: kycaml --help"; exit 0; }; fi
if have pip3 || have pip; then PIP="$(command -v pip3 || command -v pip)"; say "Installing with pip..."; "$PIP" install --user "$URL" && { say "Done. Run: kycaml --help"; exit 0; }; fi
say "Falling back to a source clone."
TMP="$(mktemp -d)"; git clone --depth 1 "$GITURL" "$TMP/$REPO"
say "Cloned to $TMP/$REPO — run: cd $TMP/$REPO && python3 -m pip install ."
