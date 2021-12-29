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

# https://docs.github.com/en/actions/learn-github-actions/environment-variables

if [[ "$GITHUB_TOKEN" == "" ]]; then
	2>&1 echo "GITHUB_TOKEN not present"
	exit 1
fi

if [[ "$GITHUB_REF_NAME" == "" ]]; then
	2>&1 echo "GITHUB_REF_NAME not present"
	exit 1
fi

if [[ "$GITHUB_API_URL" == "" ]]; then
	2>&1 echo "GITHUB_API_URL not present"
	exit 1
fi

if [[ "$GITHUB_REPOSITORY" == "" ]]; then
	2>&1 echo "GITHUB_REPOSITORY not present"
	exit 1
fi

if [[ "$1" == "" ]]; then
	2>&1 echo "No files to upload"
	exit 1
fi 

AUTH_HEADER="Authorization: token ${GITHUB_TOKEN}"

TEMP_DIR="$( mktemp -d )"

# https://docs.github.com/en/rest/reference/releases#get-a-release-by-tag-name

curl -sSL \
	--fail \
	--header "$AUTH_HEADER" \
	-o "${TEMP_DIR}/out" \
	"${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/releases/tags/${GITHUB_REF_NAME}" 

RELEASE_ID="$( jq '.id' < "${TEMP_DIR}/out" )"

echo "Release ID: ${RELEASE_ID}"

# https://docs.github.com/en/rest/reference/releases#upload-a-release-asset

for FILE in ${1}/*
do
	echo $FILE
	NAME="${FILE#$1}"
	if [[ "$NAME" != "/" && "$NAME" != "" ]]; then
	    echo "Uploading: ${NAME}"
		RELEASE_URL="https://uploads.github.com/repos/${GITHUB_REPOSITORY}/releases/${RELEASE_ID}/assets?name=${NAME}"
		echo "Upload URL: ${RELEASE_URL}"
		curl -sSL \
			-o - \
			-XPOST \
			--fail \
			--header "$AUTH_HEADER" \
			--header "Content-Type: application/octet-stream" \
			--upload-file "$FILE" \
			"$RELEASE_URL"
	fi
done

rm -rf "$TEMP_DIR"
