#!/bin/sh

# AdGuard Home MikroTik Container Build Script
#
# Builds a single-platform container image of AdGuard Home and exports it as a
# Docker-format .tar file that can be imported into MikroTik RouterOS v7+.
#
# Supports both Docker and Podman.  Podman is auto-detected and used with
# --format docker-archive because MikroTik does NOT accept OCI format.
#
# Usage:
#
#   # Build for ARM 32-bit (hAP ac², RB3011, RB2011, etc.)
#   make build-mikrotik TARGET_ARCH=arm
#
#   # Build for ARM 64-bit (RB5009, CCR2004, CCR2116, etc.)
#   make build-mikrotik TARGET_ARCH=arm64
#
#   # Build for x86_64 (CHR, RB1100AHx4, etc.)
#   make build-mikrotik TARGET_ARCH=amd64
#
#   # Build for hEX Refresh (EN7562CT CPU, arm32v5 only)
#   make build-mikrotik TARGET_ARCH=armv5

verbose="${VERBOSE:-0}"

if [ "$verbose" -gt '0' ]; then
	set -x
else
	set +x
fi

set -e -f -u

# The target architecture for MikroTik.
target_arch="${TARGET_ARCH:-arm64}"
readonly target_arch

channel="${CHANNEL:-development}"
readonly channel
export CHANNEL="$channel"

dist_dir="${DIST_DIR:-dist}"
readonly dist_dir

commit="${REVISION:-$(git rev-parse --short HEAD)}"
readonly commit

if [ "${VERSION:-}" = 'v0.0.0' ] || [ "${VERSION:-}" = '' ]; then
	version="$(sh ./scripts/make/version.sh)"
else
	version="$VERSION"
fi
readonly version

build_date="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
readonly build_date

# Map the friendly architecture name to Go build parameters and platform.
case "$target_arch" in
'amd64' | 'x86' | 'x86_64')
	goos='linux'
	goarch='amd64'
	goarm=''
	target_variant=''
	docker_platform='linux/amd64'
	binary_name="AdGuardHome_linux_amd64_"
	;;
'arm64')
	goos='linux'
	goarch='arm64'
	goarm=''
	target_variant=''
	docker_platform='linux/arm64'
	binary_name="AdGuardHome_linux_arm64_"
	;;
'armv5' | 'arm32v5')
	goos='linux'
	goarch='arm'
	goarm='5'
	target_variant='v5'
	docker_platform='linux/arm/v5'
	binary_name="AdGuardHome_linux_arm_v5"
	;;
'armv6' | 'arm32v6')
	goos='linux'
	goarch='arm'
	goarm='6'
	target_variant='v6'
	docker_platform='linux/arm/v6'
	binary_name="AdGuardHome_linux_arm_v6"
	;;
'armv7' | 'arm' | 'arm32' | 'arm32v7')
	goos='linux'
	goarch='arm'
	goarm='7'
	target_variant='v7'
	docker_platform='linux/arm/v7'
	binary_name="AdGuardHome_linux_arm_v7"
	;;
*)
	echo "unsupported architecture '$target_arch'" 1>&2
	echo "supported values: amd64, arm64, arm, armv5, armv6, armv7" 1>&2
	exit 1
	;;
esac
readonly goos goarch goarm target_variant docker_platform binary_name

# Auto-detect container engine: prefer podman if available, fallback to docker.
container_engine=''
if command -v podman >/dev/null 2>&1; then
	container_engine='podman'
elif command -v docker >/dev/null 2>&1; then
	container_engine='docker'
else
	echo 'ERROR: Neither podman nor docker found.' 1>&2
	echo 'Install one of them and retry.' 1>&2
	exit 1
fi
readonly container_engine

echo "Building AdGuard Home for MikroTik"
echo "  target:    ${target_arch}"
echo "  platform:  ${docker_platform}"
echo "  version:   ${version}"
echo "  channel:   ${channel}"
echo "  engine:    ${container_engine}"

# Step 1: Build the Go binary for the target platform.
echo ''
echo '=== Step 1: Building Go binary ==='

go="${GO:-go}"
readonly go

gomips="${GOMIPS:-}"
export GOMIPS
readonly GOMIPS

CGO_ENABLED='0'
export CGO_ENABLED
readonly CGO_ENABLED

if [ "$goarm" != '' ]; then
	GOARM="$goarm"
	export GOARM
	readonly GOARM
fi

GOOS="$goos"
GOARCH="$goarch"
export GOOS GOARCH
readonly GOOS GOARCH

go_build_dir="${dist_dir}/AdGuardHome_${goos}_${goarch}"
if [ "${goarm:-}" != '' ]; then
	go_build_dir="${go_build_dir}_${goarm}"
fi
readonly go_build_dir

mkdir -p "${go_build_dir}/AdGuardHome"

committime="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
readonly committime

version_pkg='github.com/AdguardTeam/AdGuardHome/internal/version'
ldflags="-s -w"
ldflags="${ldflags} -X ${version_pkg}.version=${version}"
ldflags="${ldflags} -X ${version_pkg}.channel=${channel}"
ldflags="${ldflags} -X ${version_pkg}.committime=${committime}"
if [ "${goarm:-}" != '' ]; then
	ldflags="${ldflags} -X ${version_pkg}.goarm=${goarm}"
fi
readonly ldflags

if [ "${NEXTAPI:-0}" -eq '0' ]; then
	tags_flags=''
else
	tags_flags='--tags=next'
fi
readonly tags_flags

"$go" build \
	--ldflags "$ldflags" \
	$tags_flags \
	--trimpath \
	-o "${go_build_dir}/AdGuardHome/AdGuardHome" \
	;

echo "  Binary built: ${go_build_dir}/AdGuardHome/AdGuardHome"

# Step 2: Copy the binary into the build context.
echo ''
echo '=== Step 2: Preparing build context ==='

dist_docker="${dist_dir}/docker"
readonly dist_docker

mkdir -p "$dist_docker"
cp "${go_build_dir}/AdGuardHome/AdGuardHome" \
	"${dist_docker}/${binary_name}"

echo "  Copied to: ${dist_docker}/${binary_name}"

# Step 3: Build the container image.
echo ''
echo '=== Step 3: Building container image ==='

image_name="adguardhome-mikrotik-${target_arch}"
readonly image_name

"$container_engine" build \
	--build-arg BUILD_DATE="$build_date" \
	--build-arg DIST_DIR="$dist_dir" \
	--build-arg TARGETARCH="$goarch" \
	--build-arg TARGETOS="$goos" \
	--build-arg TARGETVARIANT="$target_variant" \
	--build-arg VCS_REF="$commit" \
	--build-arg VERSION="$version" \
	--platform "$docker_platform" \
	--tag "$image_name" \
	-f ./docker/build.Dockerfile \
	.

echo "  Image built: ${image_name}"

# Step 4: Export as Docker-format tar (MikroTik does NOT accept OCI format).
#
# Docker 29.x defaults `save` to OCI format (blobs/ + oci-layout), and Podman
# defaults the same way unless --format docker-archive is used.  MikroTik
# RouterOS requires Docker Archive format (manifest.json + config.json +
# layer.tar + repositories).
#
# Strategy:
#   1. Save with whichever engine is available (may produce OCI).
#   2. Detect OCI by presence of "oci-layout" in the tar.
#   3. If OCI, run oci2docker.py to convert.
echo ''
echo '=== Step 4: Exporting for MikroTik (Docker Archive format) ==='

script_dir="$(dirname "$0")"
readonly script_dir

oci_tmp="${dist_dir}/mikrotik-oci-tmp.tar"
output_file="${dist_dir}/adguardhome-mikrotik-${target_arch}.tar"
readonly oci_tmp output_file

if [ "$container_engine" = 'podman' ]; then
	podman save --format docker-archive --output "$output_file" "$image_name" 2>/dev/null && \
		echo '  Podman exported Docker Archive directly.' || \
		{
			echo '  Podman --format failed, saving OCI then converting...'
			podman save --output "$oci_tmp" "$image_name"
			need_convert='1'
		}
else
	docker save --output "$oci_tmp" "$image_name"
	if tar tf "$oci_tmp" 2>/dev/null | grep -q '^oci-layout$'; then
		echo '  Detected OCI format, converting to Docker Archive...'
		need_convert='1'
	else
		echo '  Already Docker Archive format.'
		mv "$oci_tmp" "$output_file"
		need_convert='0'
	fi
fi

if [ "${need_convert:-0}" -eq '1' ]; then
	python3 "${script_dir}/oci2docker.py" "$oci_tmp" "$output_file" "$image_name"
fi

rm -f "$oci_tmp"

echo ''
echo "Done! Upload ${output_file} to your MikroTik router and run:"
echo ''
echo "  /container/add \\"
echo "    file=adguardhome-mikrotik-${target_arch}.tar \\"
echo "    interface=veth1 \\"
echo "    root-dir=docker/AdGuardHome \\"
echo "    mountlists=AdGuardHome \\"
echo "    logging=yes \\"
echo "    start-on-boot=yes \\"
echo "    name=AdGuardHome"
echo ''
