#!/bin/bash -e

# A script for building binary releases for various platforms.

if [[ "$0" != "./scripts/build-release.sh" ]]; then
	1>&2 echo "Script must be run at root of filesystem"
	exit 1
fi

VERSION="$1"

if [[ "$VERSION" != v* ]]; then
	1>&2 echo "No version specified as argument"
	exit 1
fi

mkdir -p bin
rm -f bin/*.zip
rm -f bin/*.tar.gz

function build {
	TEMP_DIR="$( mktemp -d )"
	GOOS="$1"
	GOARCH="$2"

	export CGO_ENABLED=0

	BIN_NAME="log4jscanner"
	if [[ "$1" == "windows" ]]; then
	  BIN_NAME="log4jscanner.exe"
	fi

	GOOS="$GOOS" GOARCH="$GOARCH" go build -o "${TEMP_DIR}/log4jscanner/${BIN_NAME}"

	if [[ "$1" == "windows" ]]; then
		TARGET="${PWD}/bin/log4jscanner-${VERSION}-${GOOS}-${GOARCH}.zip"
		cd "$TEMP_DIR"
		zip -r "$TARGET" ./
		cd -
	else
		tar \
			--group=root \
			--owner=root \
			-czvf \
			"${PWD}/bin/log4jscanner-${VERSION}-${GOOS}-${GOARCH}.tar.gz" \
			-C "$TEMP_DIR" \
			"./"
	fi
	rm -rf "$TEMP_DIR"
}

build darwin amd64
build darwin arm64
build linux amd64
build linux arm64
build windows amd64
