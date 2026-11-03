#!/bin/sh
# Baut die Agent-Pakete dieser Installation (Container agent-build: ohne Netz, ohne Signierschlüssel). Hat sich der
# Code seit dem letzten Release nicht geändert, bleibt <stage> leer und agent-sign hat nichts zu tun.
set -eu
src=/src stage=/stage releases=/releases

find "$stage" -mindepth 1 -delete
plan=$(ll-release plan "$src" "$releases")
case "$plan" in
    unchanged*) echo "Agent unchanged, still v${plan#unchanged }."; exit 0 ;;
esac
version=${plan%% *}
source=${plan#* }
pub=$(cat "$releases/release.pub")

work=$(mktemp -d)
cp -r "$src/packaging" "$work/"
mkdir -p "$work/build" "$stage/dist"
for arch in amd64 arm64; do
    GOOS=linux GOARCH=$arch go build -C "$src" -trimpath -o "$stage/dist/lablantern-agent-linux-$arch" \
        -ldflags "-s -w -X main.AgentVersion=$version -X lablantern/agent/internal/release.publicKeyB64=$pub" \
        ./cmd/lablantern-agent
    cp "$stage/dist/lablantern-agent-linux-$arch" "$work/build/lablantern-agent"
    for pkg in deb rpm; do
        (cd "$work" && ARCH=$arch VERSION=$version nfpm package -f packaging/nfpm.yaml -p $pkg \
            -t "$stage/dist/lablantern-agent-linux-$arch.$pkg" >/dev/null)
    done
done
printf '{"version": "%s", "source": "%s"}\n' "$version" "$source" > "$stage/plan.json"
echo "Built agent $version."
