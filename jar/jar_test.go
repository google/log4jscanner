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
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var testdataPath = func(p string) string {
	return filepath.Join("testdata", p)
}

func TestParse(t *testing.T) {
	testCases := []struct {
		filename string
		wantBad  bool
	}{
		{"400mb.jar", false},
		{"400mb_jar_in_jar.jar", false},
		{"arara.jar", true},
		{"arara.jar.patched", false},
		{"arara.signed.jar", true},
		{"arara.signed.jar.patched", false},
		{"log4j-core-2.12.1.jar", true},
		{"log4j-core-2.12.1.jar.patched", false},
		// log4j 2.12.2 is not affected by log4shell.
		// See: https://logging.apache.org/log4j/2.x/security.html
		{"log4j-core-2.12.2.jar", false},
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

		// Ensure robustness to zip bombs from
		// https://www.bamsoftware.com/hacks/zipbomb/.
		{"zipbombs/zbsm_in_jar.jar", false},
		{"zipbombs/zbsm.jar", false},
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

func TestMaxBytes(t *testing.T) {
	p := testdataPath("400mb_jar_in_jar.jar")
	zr, _, err := OpenReader(p)
	if err != nil {
		t.Fatalf("zip.OpenReader failed: %v", err)
	}
	defer zr.Close()

	c := &Parser{MaxBytes: 4 << 20 /* 4MiB */}
	if r, err := c.Parse(&zr.Reader); err == nil {
		t.Errorf("Parse() = %+v, want error", r)
	}
}

func TestMaxDepth(t *testing.T) {
	p := testdataPath("bad_jar_in_jar_in_jar.jar")
	zr, _, err := OpenReader(p)
	if err != nil {
		t.Fatalf("zip.OpenReader failed: %v", err)
	}
	defer zr.Close()

	c := &Parser{MaxDepth: 1}
	if r, err := c.Parse(&zr.Reader); err == nil {
		t.Errorf("Parse() = %+v, want error", r)
	}
}

// TestFileError verifies that FileError is invoked with correct paths when an error is encountered
// while processing a JAR file.  The test then verifies that scanning continues and successfully
// identifies a vulnerable log4j later in the JAR file.  corrupt.jar contains a file that will be
// read by checkJAR (decoy/JndiManager.class) before encountering other vulnerable log4j files.  The
// decoy file triggers an error because it has an unsupported compression algorithm.
// corrupt_jar_in_jar.jar is similar, except that it contains corrupt.jar before vuln-class.jar.
func TestFileError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		file string
		// want is the expected path provided to FileError
		want string
	}{
		{
			file: "corrupt.jar",
			want: filepath.Join("corrupt.jar", "decoy", "JndiManager.class"),
		},
		{
			file: "corrupt_jar_in_jar.jar",
			want: filepath.Join("corrupt_jar_in_jar.jar", "corrupt.jar", "decoy", "JndiManager.class"),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			p := testdataPath(tc.file)
			zr, _, err := OpenReader(p)
			if err != nil {
				t.Fatalf("OpenReader failed: %v", err)
			}
			defer zr.Close()

			var got []string
			pr := &Parser{
				Name: tc.file,
				FileError: func(path string, err error) error {
					t.Logf("FileError(%q, %v)", path, err)
					got = append(got, path)
					return nil
				},
			}

			r, err := pr.Parse(&zr.Reader)
			if err != nil {
				t.Fatalf("Parse() = %+v, want nil error", err)
			}
			if !r.Vulnerable {
				t.Error("Parse() returned not vulnerable, want vulnerable")
			}

			if diff := cmp.Diff([]string{tc.want}, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Parse() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestInfiniteRecursion ensures that Parse does not get stuck in an
// infinitely recursive zip.
func TestInfiniteRecursion(t *testing.T) {
	// Using infinite r.zip from https://research.swtch.com/zip.
	p := testdataPath("zipbombs/r.zip")
	zr, _, err := OpenReader(p)
	if err != nil {
		t.Fatalf("zip.OpenReader failed: %v", err)
	}
	defer zr.Close()
	report, err := Parse(&zr.Reader)
	if err == nil {
		t.Errorf("Parse() failed to return error on infintely recursive zip, got %+v, want error", report)
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

func BenchmarkParseParallel(b *testing.B) {
	filename := "safe1.jar"
	p := testdataPath(filename)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		zr, _, err := OpenReader(p)
		if err != nil {
			b.Fatalf("zip.OpenReader failed: %v", err)
		}
		defer zr.Close()
		for pb.Next() {
			_, err := Parse(&zr.Reader)
			if err != nil {
				b.Errorf("Scan() returned an unexpected error, got %v, want nil", err)
			}
		}
	})
}

func TestLog4jPattern(t *testing.T) {
	tests := []struct {
		input     []byte
		matchType int
	}{
		{append([]byte{0x0, 0x1}, []byte("isJndiEnabled")...), 0},
		{[]byte{
			0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e,
			0x00, 0x00, 0x00,
			0x28, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
			0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69,
			0x6e, 0x67, 0x3b, 0x4c, 0x6a, 0x61, 0x76, 0x61,
			0x78, 0x2f, 0x6e, 0x61, 0x6d, 0x69, 0x6e, 0x67,
			0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
			0x3b, 0x29, 0x56,
		}, 1},
		{append(make([]byte, 1000), []byte{
			0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x28, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
			0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69,
			0x6e, 0x67, 0x3b, 0x4c, 0x6a, 0x61, 0x76, 0x61,
			0x78, 0x2f, 0x6e, 0x61, 0x6d, 0x69, 0x6e, 0x67,
			0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
			0x3b, 0x29, 0x56,
		}...), -1},
		{append([]byte("isJndiEnabled"), []byte{
			0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e,
			0x00, 0x00, 0x00,
			0x28, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
			0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69,
			0x6e, 0x67, 0x3b, 0x4c, 0x6a, 0x61, 0x76, 0x61,
			0x78, 0x2f, 0x6e, 0x61, 0x6d, 0x69, 0x6e, 0x67,
			0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
			0x3b, 0x29, 0x56,
			// Some random bytes.
			0xff, 0xff, 0xff,
		}...), 2},
		{append([]byte{
			0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e,
			0x00, 0x00, 0x00,
			0x28, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c,
			0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69,
			0x6e, 0x67, 0x3b, 0x4c, 0x6a, 0x61, 0x76, 0x61,
			0x78, 0x2f, 0x6e, 0x61, 0x6d, 0x69, 0x6e, 0x67,
			0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
			0x3b, 0x29, 0x56,
			// Some random bytes.
			0x15, 0x7f, 0xa5,
		}, []byte("isJndiEnabled")...), 3},
	}
	for _, test := range tests {
		br := newByteReader(bytes.NewReader(test.input), make([]byte, 16))
		matches := log4jPattern.FindReaderSubmatchIndex(br)
		if matches == nil && test.matchType >= 0 {
			t.Error("expected match")
			continue
		}
		switch test.matchType {
		case 0:
			if matches[(test.matchType+1)*2] < 0 {
				t.Error("expected match of 2.16 only")
			}
		case 1:
			if matches[(test.matchType+1)*2] < 0 {
				t.Error("expected match of YARA rule only")
			}
		case 2:
			if matches[(test.matchType+1)*2] < 0 {
				t.Error("expected match of 2.16 then YARA rule")
			}
		case 3:
			if matches[(test.matchType+1)*2] < 0 {
				t.Error("expected match of YARA rule then then 2.16")
			}
		default:
			if matches != nil {
				t.Error("unexpected match")
			}
		}
	}
}

func TestByteReader(t *testing.T) {
	check := func(buf []byte, f func() io.Reader, expect []byte, expectErr error) {
		t.Helper()

		br := newByteReader(f(), buf)
		i := 0
		for {
			b, err := br.ReadByte()
			if err != nil {
				if err != expectErr {
					t.Errorf("expected error %v, got %v", expectErr, err)
				}
				if br.Err() != err {
					t.Errorf("Err method result %v didn't match final error %v", br.Err(), err)
				}
				break
			}
			if b != expect[i] {
				t.Errorf("read unexpected value %d at index %d", b, i)
				break
			}
			i++
		}
		if i != len(expect) {
			t.Errorf("expected to read %d bytes, read %d bytes instead", len(expect), i)
		}
	}
	// Intentionally reuse a buffer to see how it deals with
	// a dirty buffer.
	buf := make([]byte, 8192)

	small := []byte("hello world")
	newSmallReader := func() io.Reader {
		return bytes.NewReader(small)
	}
	check(buf[:5], newSmallReader, small, io.EOF)
	check(buf[:1], newSmallReader, small, io.EOF)
	check(buf[:103], newSmallReader, small, io.EOF)

	large := bytes.Repeat(small, 1001)
	newLargeReader := func() io.Reader {
		return bytes.NewReader(large)
	}
	check(buf[:1], newLargeReader, large, io.EOF)
	check(buf[:1041], newLargeReader, large, io.EOF)
	check(buf[:], newLargeReader, large, io.EOF)

	const failAfter = 105
	bad := fmt.Errorf("this is bad")
	newBadReader := func() io.Reader {
		return newFaultReader(bytes.NewReader(large), bad, failAfter)
	}
	check(buf[:4], newBadReader, large[:failAfter], bad)
	check(buf[:1], newBadReader, large[:failAfter], bad)
	check(buf[:971], newBadReader, large[:failAfter], bad)
}

type faultReader struct {
	io.Reader
	fault error
	after int

	read int
}

func newFaultReader(r io.Reader, fault error, after int) *faultReader {
	return &faultReader{r, fault, after, 0}
}

func (f *faultReader) Read(b []byte) (int, error) {
	if f.read >= f.after {
		return 0, f.fault
	}
	n, err := f.Reader.Read(b)
	f.read += n
	if f.read >= f.after {
		return f.after - (f.read - n), f.fault
	}
	return n, err
}
