#!/usr/bin/env bash
# Builds the Wazuh Android agent.
#
# Usage:
#   ./build_app.sh            debug APK
#   ./build_app.sh --release  release APK, tag v<versionName>, GitHub Release
#
# --release uploads the Gradle APK and a second copy named wazuh-agent-release.apk.
# The website links to that stable name:
# https://github.com/skuilplek/wazuh-android-agent/releases/latest/download/wazuh-agent-release.apk

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

GRADLE_FILE="app/build.gradle.kts"
STABLE_NAME="wazuh-agent-release.apk"

usage() {
  cat <<'EOF'
Usage: ./build_app.sh [--release]

  ./build_app.sh            Build the debug APK.
  ./build_app.sh --release  Build the release APK, tag v<versionName> on the
                            current commit, and publish a GitHub Release.
EOF
}

read_version() {
  version_name="$(sed -n 's/^[[:space:]]*versionName = "\(.*\)"/\1/p' "$GRADLE_FILE")"
  version_code="$(sed -n 's/^[[:space:]]*versionCode = \(.*\)/\1/p' "$GRADLE_FILE")"
  if [[ -z "$version_name" || -z "$version_code" ]]; then
    echo "Could not read versionName and versionCode from ${GRADLE_FILE}." >&2
    exit 1
  fi
}

if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

case "${1:-}" in
  "")
    release=0
    ;;
  --release)
    release=1
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

read_version

if [[ "$release" -eq 0 ]]; then
  ./gradlew :app:assembleDebug
  echo "Debug APK: app/build/outputs/apk/debug/wazuh-agent-${version_name}-debug.apk"
  exit 0
fi

if ! git symbolic-ref -q HEAD >/dev/null; then
  echo "Detached HEAD. Check out a branch before --release." >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash before --release." >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "gh is not authenticated. Run gh auth login." >&2
  exit 1
fi

tag="v${version_name}"

if git show-ref --verify --quiet "refs/tags/${tag}"; then
  echo "Tag ${tag} already exists. Bump versionName in ${GRADLE_FILE}." >&2
  exit 1
fi

git fetch --tags origin

if git show-ref --verify --quiet "refs/tags/${tag}"; then
  echo "Tag ${tag} already exists on origin. Bump versionName in ${GRADLE_FILE}." >&2
  exit 1
fi

./gradlew :app:assembleRelease

versioned_apk="app/build/outputs/apk/release/wazuh-agent-${version_name}-release.apk"
if [[ ! -f "$versioned_apk" ]]; then
  echo "Expected release APK at ${versioned_apk}." >&2
  exit 1
fi

stable_apk="app/build/outputs/apk/release/${STABLE_NAME}"
cp "$versioned_apk" "$stable_apk"

echo "Pushing $(git rev-parse --abbrev-ref HEAD) and publishing ${tag}."
git push origin HEAD

gh release create "$tag" \
  "$versioned_apk" \
  "$stable_apk" \
  --target "$(git rev-parse HEAD)" \
  --title "$tag" \
  --notes "App version ${version_name}+${version_code}." \
  --generate-notes
