#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
g++ -std=c++11 -g -O1 -ffunction-sections -fdata-sections -fsanitize=address,undefined -fno-omit-frame-pointer -I src -I src/common test/cms/regression.cpp src/openssl.cpp src/common/log.cpp -Wl,--gc-sections -lcrypto -o "$work/regression"
python3 - "$work" <<'PYTHON'
from pathlib import Path
import sys
root=Path(sys.argv[1])
(root/'primary').write_bytes(b'Synthetic primary directory\x00' + bytes(range(256)))
(root/'alternate').write_bytes(b'Synthetic alternate directory\x00' + bytes(reversed(range(256))))
PYTHON
ASAN_OPTIONS=detect_leaks=0 "$work/regression" "$work/primary" "$work/alternate" "$work/signed.der" 2
ASAN_OPTIONS=detect_leaks=1 "$work/regression" helper
