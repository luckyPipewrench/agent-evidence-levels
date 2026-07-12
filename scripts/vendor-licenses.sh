#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Vendor the exact, canonical full license texts into LICENSE (Apache-2.0) and
# LICENSE-SPEC (CC BY 4.0). Run once before a public release so the repository
# ships the verbatim upstream legal text rather than a hand-copied approximation.
#
# Usage: scripts/vendor-licenses.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
apache_url="https://www.apache.org/licenses/LICENSE-2.0.txt"
ccby_url="https://creativecommons.org/licenses/by/4.0/legalcode.txt"

fetch() { curl -fsSL "$1"; }

echo "Vendoring Apache-2.0 -> LICENSE"
{
  echo "Apache License 2.0 applies to the reference checker, fixtures, scripts, and all"
  echo "code and data in this repository. SPDX-License-Identifier: Apache-2.0"
  echo
  fetch "$apache_url"
} > "$root/LICENSE"

echo "Vendoring CC BY 4.0 -> LICENSE-SPEC"
{
  echo "Creative Commons Attribution 4.0 International applies to SPEC.md and the"
  echo "normative specification text. SPDX-License-Identifier: CC-BY-4.0"
  echo
  fetch "$ccby_url"
} > "$root/LICENSE-SPEC"

echo "Done. Verify LICENSE and LICENSE-SPEC now contain the full canonical texts."
