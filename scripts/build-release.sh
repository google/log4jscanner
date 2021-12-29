#!/bin/bash -e

# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# A script for building binary releases for various platforms.

if [[ "$0" != "./scripts/build-release.sh" ]]; then
	1>&2 echo "Script must be run at root of filesystem"
	exit 1
fi

VERSION="$1"

if [[ "$GITHUB_REF_TYPE" == "tag" ]]; then
	VERSION="$GITHUB_REF_NAME"
fi

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

# NOTE: When adding new releases, also update .github/workflows/release.yaml.

build darwin amd64
build darwin arm64
build linux amd64
build linux arm64
build windows amd64
