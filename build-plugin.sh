#!/usr/bin/env bash
# Build and test the plugin in a JDK 21 Gradle container (only Docker needed); the zip lands in dist/.
# Target another Elasticsearch version with: ES_VERSION=9.5.5 ./build-plugin.sh
# S2S_SAMPLES=<dir> also runs the tests that decode sample forwarder request bodies from <dir>.
set -euo pipefail
cd "$(dirname "$0")"
# gradle.properties has the default version; ES_VERSION overrides it for this build only
version_arg=()
[ -z "${ES_VERSION:-}" ] || version_arg=("-PesVersion=${ES_VERSION}")
samples=()
[ -z "${S2S_SAMPLES:-}" ] || samples=(-v "$(cd "$S2S_SAMPLES" && pwd)":/samples)
rm -rf plugin/build/distributions
docker volume create ingest-splunk-forwarders-gradle-cache >/dev/null
# a fresh named volume is root-owned; hand it to the calling user
docker run --rm -v ingest-splunk-forwarders-gradle-cache:/cache --entrypoint chown gradle:8-jdk21 "$(id -u):$(id -g)" /cache
docker run --rm -u "$(id -u):$(id -g)" -e GRADLE_USER_HOME=/cache \
  -v "$PWD":/work -v ingest-splunk-forwarders-gradle-cache:/cache "${samples[@]}" -w /work/plugin \
  gradle:8-jdk21 gradle --no-daemon -q "${version_arg[@]}" ${S2S_SAMPLES:+-Ds2s.samples=/samples} "${@:-test}" bundlePlugin
mkdir -p dist && rm -f dist/*.zip
cp plugin/build/distributions/*.zip dist/
ls -l dist/*.zip
