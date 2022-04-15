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
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWalker(t *testing.T) {
	tempDir := t.TempDir()
	files := []string{
		"arara.jar",
		"arara.jar.patched",
		"arara.signed.jar",
		"arara.signed.jar.patched",
		"bad_jar_in_jar_in_jar.jar",
		"bad_jar_in_jar_in_jar.jar.patched",
		"bad_jar_in_jar.jar",
		"bad_jar_in_jar.jar.patched",
		"bad_jar_with_invalid_jar.jar",
		"bad_jar_with_invalid_jar.jar.patched",
		"good_jar_in_jar_in_jar.jar",
		"good_jar_in_jar.jar",
		"good_jar_with_invalid_jar.jar",
		"helloworld.jar",
		"helloworld.signed.jar",
		"log4j-core-2.12.1.jar",
		"log4j-core-2.12.1.jar.patched",
		"log4j-core-2.14.0.jar",
		"log4j-core-2.14.0.jar.patched",
		"log4j-core-2.15.0.jar",
		"log4j-core-2.15.0.jar.patched",
		"log4j-core-2.16.0.jar",
		"log4j-core-2.1.jar",
		"log4j-core-2.1.jar.patched",
		"notarealjar.jar",
		"safe1.jar",
		"safe1.signed.jar",
		"similarbutnotvuln.jar",
		"vuln-class.jar",
		"vuln-class.jar.patched",
	}
	for _, file := range files {
		src := testdataPath(file)
		dest := filepath.Join(tempDir, file)
		cpFile(t, dest, src)
	}

	got := []string{}
	want := []string{
		"arara.jar",
		"arara.signed.jar",
		"bad_jar_in_jar.jar",
		"bad_jar_in_jar_in_jar.jar",
		"bad_jar_with_invalid_jar.jar",
		"log4j-core-2.1.jar",
		"log4j-core-2.12.1.jar",
		"log4j-core-2.14.0.jar",
		"log4j-core-2.15.0.jar",
		"vuln-class.jar",
	}
	for i, p := range want {
		want[i] = filepath.Join(tempDir, p)
	}
	w := Walker{
		HandleError: func(path string, err error) {
			t.Errorf("processing %s: %v", path, err)
		},
		HandleReport: func(path string, r *Report) {
			got = append(got, path)
		},
	}
	if err := w.Walk(tempDir); err != nil {
		t.Fatalf("walking filesystem: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("walking filesystem returned diff (-want, +got): %s", diff)
	}
}

func TestWalkerRewrite(t *testing.T) {
	tempDir := t.TempDir()
	files := []string{
		"arara.jar",
		"arara.jar.patched",
		"arara.signed.jar",
		"arara.signed.jar.patched",
		"bad_jar_in_jar_in_jar.jar",
		"bad_jar_in_jar_in_jar.jar.patched",
		"bad_jar_in_jar.jar",
		"bad_jar_in_jar.jar.patched",
		"bad_jar_with_invalid_jar.jar",
		"bad_jar_with_invalid_jar.jar.patched",
		"good_jar_in_jar_in_jar.jar",
		"good_jar_in_jar.jar",
		"good_jar_with_invalid_jar.jar",
		"helloworld.jar",
		"helloworld.signed.jar",
		"log4j-core-2.12.1.jar",
		"log4j-core-2.12.1.jar.patched",
		"log4j-core-2.14.0.jar",
		"log4j-core-2.14.0.jar.patched",
		"log4j-core-2.15.0.jar",
		"log4j-core-2.15.0.jar.patched",
		"log4j-core-2.16.0.jar",
		"log4j-core-2.1.jar",
		"log4j-core-2.1.jar.patched",
		"notarealjar.jar",
		"safe1.jar",
		"safe1.signed.jar",
		"similarbutnotvuln.jar",
		"vuln-class.jar",
		"vuln-class.jar.patched",
	}
	for _, file := range files {
		src := testdataPath(file)
		dest := filepath.Join(tempDir, file)
		cpFile(t, dest, src)
	}

	got := []string{}
	want := []string{
		"arara.jar",
		"arara.signed.jar",
		"bad_jar_in_jar.jar",
		"bad_jar_in_jar_in_jar.jar",
		"bad_jar_with_invalid_jar.jar",
		"log4j-core-2.1.jar",
		"log4j-core-2.12.1.jar",
		"log4j-core-2.14.0.jar",
		"log4j-core-2.15.0.jar",
		"vuln-class.jar",
	}
	for i, p := range want {
		want[i] = filepath.Join(tempDir, p)
	}
	w := Walker{
		Rewrite: true,
		HandleError: func(path string, err error) {
			t.Errorf("processing %s: %v", path, err)
		},
		HandleRewrite: func(path string, r *Report) {
			got = append(got, path)
		},
	}
	if err := w.Walk(tempDir); err != nil {
		t.Fatalf("walking filesystem: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("walking filesystem returned diff (-want, +got): %s", diff)
	}
	got = []string{}
	want = []string{}
	w.HandleError = func(path string, err error) {
		t.Errorf("processing after rewrite %s: %v", path, err)
	}

	if err := w.Walk(tempDir); err != nil {
		t.Fatalf("walking filesystem: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("walking filesystem after rewrite returned diff (-want, +got): %s", diff)
	}
}

// TestNonDefaultParser verifies that Walker can be configured with a
// non-default Parser by scanning a large JAR file with two
// configurations: one where Parser.MaxBytes is larger than the file
// size and one where Parser.MaxBytes is smaller than the file
// size. It ensures that the first case succeeds and the second fails.
func TestNonDefaultParser(t *testing.T) {
	jar := "400mb_jar_in_jar.jar"

	tempDir := t.TempDir()
	src := testdataPath(jar)
	dest := filepath.Join(tempDir, jar)
	cpFile(t, dest, src)

	tests := []struct {
		desc     string
		maxBytes int64
		wantErr  bool
	}{
		{
			desc:     "MaxBytes > JAR size",
			maxBytes: 4 << 30, // 4GiB
			wantErr:  false,
		},
		{
			desc:     "MaxBytes < JAR size",
			maxBytes: 4 << 20, // 4MiB
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			var gotErr error

			p := &Parser{MaxBytes: tc.maxBytes}
			w := &Walker{
				Parser: p,
				HandleError: func(path string, err error) {
					if err != nil && strings.HasSuffix(path, filepath.FromSlash("/"+jar)) {
						gotErr = err
					}
				},
			}
			if err := w.Walk(tempDir); err != nil {
				t.Errorf("Walk returned unexpected error: %v", err)
			}

			if tc.wantErr && gotErr == nil {
				t.Error("Parser failed to generate expected error when scanning JARs > MaxBytes, got nil, want error")
			} else if !tc.wantErr && gotErr != nil {
				t.Errorf("Parser generated unexpected error when scanning JARs <= MaxBytes, got %v, want nil error", gotErr)
			}
		})
	}
}
