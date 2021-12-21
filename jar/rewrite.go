// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jar

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"strings"
)

var skipSuffixes = [...]string{
	// Skip copying the file over to the new jar so that the new jar is immune.
	"JndiLookup.class",
	// Remove signing keys from the JAR.
	".RSA",
	// Remove any signatures from the JAR.
	".SF",
}

// Rewrite attempts to remove any JndiLookup.class files from a JAR.
func Rewrite(w io.Writer, zr *zip.Reader) error {
	zw := zip.NewWriter(w)
	for _, zipItem := range zr.File {
		skip := false
		for _, suffix := range skipSuffixes {
			if strings.HasSuffix(zipItem.Name, suffix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		if exts[path.Ext(zipItem.Name)] {
			// Nested jar! Recur on it to ensure that nested jars are immune
			nestedReader, err := zipItem.Open()
			if err != nil {
				return fmt.Errorf("failed to open nested zip %q for auto-mitigation: %v; skipping", zipItem.Name, err)
			}
			b, err := ioutil.ReadAll(nestedReader)
			if err != nil {
				return fmt.Errorf("failed to read nested zip %q for auto-mitigation: %v; skipping", zipItem.Name, err)
			}
			nestedReaderAt := bytes.NewReader(b)
			nestedZipReader, err := zip.NewReader(nestedReaderAt, int64(len(b)))
			if err != nil {
				if err == zip.ErrFormat {
					// Not a zip file.
					goto copyFile
				}
				return fmt.Errorf("failed to create nested zip %q reader for auto-mitigation: %v; skipping", zipItem.Name, err)
			}
			writer, err := zw.CreateHeader(&zipItem.FileHeader)
			if err != nil {
				return fmt.Errorf("failed to create nested zip %q item for auto-mitigation: %v", zipItem.Name, err)
			}
			if err := Rewrite(writer, nestedZipReader); err != nil {
				return fmt.Errorf("rewriting nested zip %s: %v", zipItem.Name, err)
			}
			continue
		}

	copyFile:
		if zipItem.Mode().IsDir() {
			// Copy() only works on files.
			if _, err := zw.CreateRaw(&zipItem.FileHeader); err != nil {
				return fmt.Errorf("failed to copy zip directory %s: %v", zipItem.Name, err)
			}
		} else {
			if err := zw.Copy(zipItem); err != nil {
				return fmt.Errorf("failed to copy zip file %s: %v", zipItem.Name, err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("finalize writer: %v", err)
	}
	return nil
}
