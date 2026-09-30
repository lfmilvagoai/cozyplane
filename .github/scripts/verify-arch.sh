#!/usr/bin/env bash
# Assert that every advertised leg of a multi-arch image really was built for
# that architecture.
#
# Why this exists: a platform ARG with a default value is NOT filled in by
# BuildKit (docker/buildx#510), so `ARG TARGETARCH=amd64` made GOARCH resolve to
# amd64 on BOTH legs. The index still advertised linux/arm64, and the arm64 leg
# shipped x86-64 binaries plus x86-64 CNI plugins -- an arm64 node got
# `exec format error` and a broken /opt/cni/bin. The build itself cannot fail on
# this, hence a check against the published artifact.
#
# crane rather than `docker create --platform`: the local image store keys by
# digest and refuses to hold two platforms for one digest ("cannot overwrite
# digest"), so the second leg is unverifiable that way. crane streams each leg
# straight out of the registry and never runs it, so no emulation is needed --
# the kpr job has no QEMU set up at all.
#
# Usage: verify-arch.sh <image-ref> <path-of-a-binary-in-the-image, no leading />
set -uo pipefail

ref=${1:?image ref (name@sha256:... or name:tag)}
bin=${2:?path of one binary inside the image, without a leading slash}
rc=0

for arch in amd64 arm64; do
	case $arch in
	amd64) want='x86-64' ;;
	arm64) want='ARM aarch64' ;;
	esac

	got=$(crane export --platform "linux/$arch" "$ref" - | tar -xO "$bin" | file -b -)
	if [ -z "$got" ]; then
		echo "FAIL linux/$arch  could not read $bin out of $ref"
		rc=1
	elif [ "${got#*"$want"}" != "$got" ]; then
		echo "ok   linux/$arch  $bin: $got"
	else
		echo "FAIL linux/$arch  $bin: expected $want, got: $got"
		rc=1
	fi
done

if [ $rc -ne 0 ]; then
	echo "::error::$ref advertises a platform it was not built for -- check that every stage reading TARGETARCH declares it BARE (no default value)"
fi
exit $rc
