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
	"testing"
)

var testdataPath = func(p string) string {
	return filepath.Join("testdata", p)
}

func TestParse(t *testing.T) {
	testCases := []struct {
		filename string
		wantBad  bool
	}{
		{"arara.jar", true},
		{"arara.jar.patched", false},
		{"arara.signed.jar", true},
		{"arara.signed.jar.patched", false},
		{"log4j-core-2.12.1.jar", true},
		{"log4j-core-2.12.1.jar.patched", false},
		{"log4j-core-2.14.0.jar", true},
		{"log4j-core-2.14.0.jar.patched", false},
		{"log4j-core-2.15.0.jar", true},
		{"log4j-core-2.15.0.jar.patched", false},
		{"log4j-core-2.16.0.jar", false},
		{"log4j-core-2.1.jar", true},
		{"log4j-core-2.1.jar.patched", false},
		{"safe1.jar", false},
		{"safe1.signed.jar", false},
		// Archive contains a malformed directory that causes archive/zip to
		// return an error.
		// See https://go.dev/issues/50390
		{"selenium-api-3.141.59.jar", false},
		// Test case where it contains a JndiLookupOther.class file that shouldn't be detected as vulnerable
		{"similarbutnotvuln.jar", false},
		{"vuln-class.jar", true},
		{"vuln-class-executable", true},
		{"vuln-class.jar.patched", false},
		{"good_jar_in_jar.jar", false},
		{"good_jar_in_jar_in_jar.jar", false},
		{"bad_jar_in_jar.jar", true},
		{"bad_jar_in_jar.jar.patched", false},
		{"bad_jar_in_jar_in_jar.jar", true},
		{"bad_jar_in_jar_in_jar.jar.patched", false},
		{"bad_jar_with_invalid_jar.jar", true},
		{"bad_jar_with_invalid_jar.jar.patched", false},
		{"good_jar_with_invalid_jar.jar", false},
		{"helloworld-executable", false},
		{"helloworld.jar", false},
		{"helloworld.signed.jar", false},
	}
	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			p := testdataPath(tc.filename)
			zr, _, err := OpenReader(p)
			if err != nil {
				t.Fatalf("zip.OpenReader failed: %v", err)
			}
			defer zr.Close()
			report, err := Parse(&zr.Reader)
			if err != nil {
				t.Fatalf("Scan() returned an unexpected error, got %v, want nil", err)
			}
			got := report.Vulnerable
			if tc.wantBad != got {
				t.Errorf("checkJAR() returned unexpected value, got bad=%t, want bad=%t", got, tc.wantBad)
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	filename := "safe1.jar"
	p := testdataPath(filename)
	zr, _, err := OpenReader(p)
	if err != nil {
		b.Fatalf("zip.OpenReader failed: %v", err)
	}
	defer zr.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := Parse(&zr.Reader)
		if err != nil {
			b.Errorf("Scan() returned an unexpected error, got %v, want nil", err)
		}
	}
}

func TestYARARule(t *testing.T) {
	data := []byte{
		0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e,
		0x00, 0x00, 0x00,
		0x28, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
		0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69,
		0x6e, 0x67, 0x3b, 0x4c, 0x6a, 0x61, 0x76, 0x61,
		0x78, 0x2f, 0x6e, 0x61, 0x6d, 0x69, 0x6e, 0x67,
		0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
		0x3b, 0x29, 0x56,
	}
	if !matchesLog4JYARARule(data) {
		t.Errorf("expected to match YARA rule")
	}
	data2 := append(make([]byte, 1000), []byte{
		0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x28, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
		0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69,
		0x6e, 0x67, 0x3b, 0x4c, 0x6a, 0x61, 0x76, 0x61,
		0x78, 0x2f, 0x6e, 0x61, 0x6d, 0x69, 0x6e, 0x67,
		0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
		0x3b, 0x29, 0x56,
	}...)
	if matchesLog4JYARARule(data2) {
		t.Errorf("unexpected match on YARA rule")
	}
}
