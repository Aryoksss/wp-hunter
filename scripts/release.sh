#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if [[ -z "$version" ]]; then
  echo "usage: scripts/release.sh <version>   e.g. scripts/release.sh 2.2.0" >&2
  exit 2
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must look like X.Y.Z (got '$version')" >&2
  exit 2
fi

tag="v$version"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]]; then
  echo "error: release must run from main" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is not clean" >&2
  exit 1
fi
if git rev-parse "$tag" >/dev/null 2>&1; then
  echo "error: tag $tag already exists" >&2
  exit 1
fi

python -m pip install -e ".[dev]" >/dev/null

echo "==> checking"
python -m ruff check wp_hunter tests
python -m ruff format --check wp_hunter tests
python -m mypy wp_hunter
python -m compileall -q wp_hunter tests
python -m unittest discover -s tests

echo "==> bumping to $version"
python - "$version" <<'PY'
import re
import sys

version = sys.argv[1]

with open("pyproject.toml", encoding="utf-8") as fh:
    text = fh.read()
text = re.sub(r'^version = "[^"]*"', f'version = "{version}"', text, count=1, flags=re.M)
with open("pyproject.toml", "w", encoding="utf-8") as fh:
    fh.write(text)

with open("wp_hunter/__init__.py", "w", encoding="utf-8") as fh:
    fh.write(f'__version__ = "{version}"\n')

for name in ("README.md", "README.id.md"):
    with open(name, encoding="utf-8") as fh:
        text = fh.read()
    text = re.sub(
        r"wp_hunter-[0-9]+\.[0-9]+\.[0-9]+-py3-none-any\.whl",
        f"wp_hunter-{version}-py3-none-any.whl",
        text,
    )
    with open(name, "w", encoding="utf-8") as fh:
        fh.write(text)

print(f"bumped pyproject.toml, wp_hunter/__init__.py, README.md, README.id.md to {version}")
PY

echo "==> building"
rm -rf build dist wp_hunter.egg-info
python -m build

echo "==> committing"
git add -A
git commit -m "release: $tag"
git push origin main

echo "==> tagging"
git tag -a "$tag" -m "WP Hunter $tag"
git push origin "$tag"

echo "==> publishing GitHub release"
gh release create "$tag" \
  --title "WP Hunter $tag" \
  --generate-notes \
  "dist/wp_hunter-${version}-py3-none-any.whl" \
  "dist/wp_hunter-${version}.tar.gz"

echo
echo "released $tag"
