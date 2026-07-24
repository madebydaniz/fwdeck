#!/usr/bin/env bash
# Local preview of the website exactly as pages.yml deploys it
# (site/ references assets/ which only exists in the assembled artifact).
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf _site && mkdir -p _site
cp -r site/* _site/
cp -r assets _site/assets
echo "assembled _site/ — open _site/index.html"
command -v open >/dev/null && open _site/index.html
