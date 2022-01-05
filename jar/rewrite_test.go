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
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"

	"testing"

	"github.com/google/go-cmp/cmp"
)

func cpFile(t *testing.T, dest, src string) {
	t.Helper()
	dir := filepath.Dir(dest)
	if _, err := os.Stat(dir); err != nil {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("creating destination directory: %v", err)
		}
	}

	r, err := os.Open(src)
	if err != nil {
		t.Fatalf("open file %s: %v", src, err)
	}
	defer r.Close()

	ri, err := r.Stat()
	if err != nil {
		t.Fatalf("stat file %s: %v", src, err)
	}
	w, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, ri.Mode())
	if err != nil {
		t.Fatalf("open destination file %s: %v", src, err)
	}
	defer w.Close()
	if _, err := io.Copy(w, r); err != nil {
		t.Fatalf("copying file contents: %v", err)
	}
}

func autoMitigateJAR(path string) error {
	r, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open flie: %v", err)
	}
	defer r.Close()
	info, err := r.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %v", err)
	}

	f, err := os.CreateTemp("", "")
	if err != nil {
		return fmt.Errorf("create temp: %v", err)
	}
	defer f.Close()
	if err := RewriteJAR(f, r, info.Size()); err != nil {
		return fmt.Errorf("rewriting zip: %v", err)
	}

	// Files must be closed before rename works on Windows.
	r.Close()
	f.Close()

	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("renaming file: %v", err)
	}
	return nil
}

func checkJARs(t *testing.T, expectRemoved func(name string) bool, before, after *zip.Reader) {
	var i, j int
	for i < len(before.File) && j < len(after.File) {
		beforeFile := before.File[i]
		afterFile := after.File[j]
		if expectRemoved(path.Base(beforeFile.Name)) {
			// Skip files that are meant to be removed in before.
			i++
			continue
		}
		i++
		j++
		if expectRemoved(path.Base(afterFile.Name)) {
			// ensure they were removed in after.
			t.Errorf("found class that was meant to be removed at %q", afterFile.Name)
		}
		if beforeFile.Name != afterFile.Name {
			t.Fatalf("found unexpected differing filenames %q %q", beforeFile.Name, afterFile.Name)
		}
		name := beforeFile.Name
		if beforeFile.Mode().IsDir() != afterFile.Mode().IsDir() {
			t.Fatalf("filemode for %s did not match, got=%v, want=%v", name, afterFile.Mode(), beforeFile.Mode())
		}

		if beforeFile.Mode().IsDir() {
			// Don't attempt to read a directory.
			continue
		}

		bf, err := beforeFile.Open()
		if err != nil {
			t.Fatalf("failed to open before file: %v", err)
		}
		bb, err := io.ReadAll(bf)
		if err != nil {
			t.Fatalf("failed to read all before file: %v", err)
		}
		bf.Close()
		af, err := afterFile.Open()
		if err != nil {
			t.Fatalf("failed to open after file: %v", err)
		}
		ab, err := io.ReadAll(af)
		if err != nil {
			t.Fatalf("failed to read all after file: %v", err)
		}
		af.Close()

		// If we find zip files make sure we open them up.
		if exts[path.Ext(name)] {
			var bFailed, aFailed bool
			bz, err := zip.NewReader(bytes.NewReader(bb), int64(len(bb)))
			if err != nil {
				bFailed = true
			}
			az, err := zip.NewReader(bytes.NewReader(ab), int64(len(ab)))
			if err != nil {
				aFailed = true
			}
			if !aFailed && !bFailed {
				checkJARs(t, expectRemoved, bz, az)
				continue
			} else if aFailed && bFailed {
				// might not be a valid zip, so carry on
			} else {
				t.Fatalf("between before and after zip file %q one succeeds but the other fails", name)
			}
		}
		// Finally just compare the files to make sure they match.
		if diff := cmp.Diff(beforeFile.FileHeader, afterFile.FileHeader); diff != "" {
			t.Fatalf("headers for %q don't match (-before, +after): %s", name, diff)
		}
		if !bytes.Equal(bb, ab) {
			t.Errorf("contents %q for files don't match", name)
		}
	}

	if i != len(before.File) {
		t.Error("files left over in before zip")
	}
	if j != len(after.File) {
		t.Error("files left over in after zip")
	}
}

func TestAutoMitigateJAR(t *testing.T) {
	for _, tc := range []string{
		"arara.jar",
		"bad_jar_in_jar.jar",
		"bad_jar_in_jar_in_jar.jar",
		"bad_jar_with_invalid_jar.jar",
		"vuln-class.jar",
		"vuln-class-executable",
	} {
		tc := tc
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			src := testdataPath(tc)
			dest := filepath.Join(t.TempDir(), tc)

			cpFile(t, dest, src)

			if err := autoMitigateJAR(dest); err != nil {
				t.Fatalf("autoMitigateJar(%s) failed: %v", dest, err)
			}

			before, _, err := OpenReader(src)
			if err != nil {
				t.Fatalf("zip.OpenReader(%q) failed: %v", src, err)
			}
			defer before.Close()
			after, _, err := OpenReader(dest)
			if err != nil {
				t.Fatalf("zip.OpenReader(%q) failed: %v", dest, err)
			}
			defer after.Close()
			checkJARs(t, func(name string) bool {
				return path.Base(name) == "JndiLookup.class"
			}, &before.Reader, &after.Reader)
		})
	}
}

func TestAutoMitigateExecutable(t *testing.T) {
	for _, tc := range []string{
		"helloworld-executable",
		"vuln-class-executable",
	} {
		tc := tc
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			src := testdataPath(tc)
			dest := filepath.Join(t.TempDir(), tc)

			cpFile(t, dest, src)

			if err := autoMitigateJAR(dest); err != nil {
				t.Fatalf("autoMitigateJar(%s) failed: %v", dest, err)
			}

			sf, err := os.Open(src)
			if err != nil {
				t.Fatalf("open file %s: %v", src, err)
			}
			defer sf.Close()
			info, err := sf.Stat()
			if err != nil {
				t.Fatalf("stat file %s: %v", src, err)
			}

			_, offset, err := NewReader(sf, info.Size())
			if err != nil {
				t.Fatalf("new jar reader %s: %v", src, err)
			}
			if offset <= 0 {
				t.Errorf("expected offset for executable %s: got=%d", src, offset)
			}

			df, err := os.Open(dest)
			if err != nil {
				t.Fatalf("open file %s: %v", dest, err)
			}
			defer df.Close()

			got := make([]byte, offset)
			want := make([]byte, offset)
			if _, err := io.ReadFull(sf, want); err != nil {
				t.Fatalf("reading prefix from file %s: %v", src, err)
			}
			if _, err := io.ReadFull(df, got); err != nil {
				t.Fatalf("reading prefix from file %s: %v", dest, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("prefix did not match after rewrite, got=%q, want=%q", got, want)
			}
		})
	}
}
func TestAutoMitigate(t *testing.T) {
	for _, tc := range []string{
		"arara.jar",
		"bad_jar_in_jar.jar",
		"bad_jar_in_jar_in_jar.jar",
		"bad_jar_with_invalid_jar.jar",
		"vuln-class.jar",
		"vuln-class-executable",
	} {
		tc := tc
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			src := testdataPath(tc)
			dest := filepath.Join(t.TempDir(), tc)

			cpFile(t, dest, src)

			if err := autoMitigateJAR(dest); err != nil {
				t.Fatalf("autoMitigateJar(%s) failed: %v", dest, err)
			}

			before, _, err := OpenReader(src)
			if err != nil {
				t.Fatalf("zip.OpenReader(%q) failed: %v", src, err)
			}
			defer before.Close()
			after, _, err := OpenReader(dest)
			if err != nil {
				t.Fatalf("zip.OpenReader(%q) failed: %v", dest, err)
			}
			defer after.Close()
			checkJARs(t, func(name string) bool {
				return path.Base(name) == "JndiLookup.class"
			}, &before.Reader, &after.Reader)
		})
	}
}

func TestAutoMitigateSignedJAR(t *testing.T) {
	testCases := []string{
		"arara.signed.jar",
		"safe1.signed.jar",
		"helloworld.signed.jar",
	}
	for _, name := range testCases {
		t.Run(name, func(t *testing.T) {
			src := testdataPath(name)
			dest := filepath.Join(t.TempDir(), name)

			cpFile(t, dest, src)

			if err := autoMitigateJAR(dest); err != nil {
				t.Fatalf("autoMitigateJar(%s) failed: %v", dest, err)
			}

			before, _, err := OpenReader(src)
			if err != nil {
				t.Fatalf("zip.OpenReader(%q) failed: %v", src, err)
			}
			defer before.Close()
			after, _, err := OpenReader(dest)
			if err != nil {
				t.Fatalf("zip.OpenReader(%q) failed: %v", dest, err)
			}
			defer after.Close()
			checkJARs(t, func(name string) bool {
				return name == "JndiLookup.class" ||
					name == "SERVER.SF" ||
					name == "SERVER.RSA"
			}, &before.Reader, &after.Reader)
		})
	}
}

func TestAutoMitigatedJarsAreCorrectlyFormed(t *testing.T) {
	if _, err := exec.LookPath("zipinfo"); err != nil {
		t.Skip("zipinfo not available, skipping test")
	}

	testCases := []string{
		"arara.jar",
		"shadow-6.1.0.jar",
		"arara.signed.jar",
		"bad_jar_in_jar_in_jar.jar",
		"bad_jar_in_jar.jar",
		"good_jar_in_jar_in_jar.jar",
		"good_jar_in_jar.jar",
		"helloworld.jar",
		"helloworld.signed.jar",
		"log4j-core-2.12.1.jar",
		"log4j-core-2.14.0.jar",
		"log4j-core-2.15.0.jar",
		"log4j-core-2.16.0.jar",
		"log4j-core-2.1.jar",
		"safe1.jar",
		"safe1.signed.jar",
		"emptydir.zip",
		"emptydirs.zip",
	}
	for _, name := range testCases {
		t.Run(name, func(t *testing.T) {
			// Set up
			src := testdataPath(name)
			dest := filepath.Join(t.TempDir(), name)

			cpFile(t, dest, src)

			// Mitigate
			if err := autoMitigateJAR(dest); err != nil {
				t.Fatalf("autoMitigateJar(%s) failed: %v", dest, err)
			}

			// Check that the jars were actually mitigated
			before, err := zip.OpenReader(src)
			if err != nil {
				t.Fatalf("zip.OpenReader(%q) failed: %v", src, err)
			}
			defer before.Close()
			after, err := zip.OpenReader(dest)
			if err != nil {
				t.Fatalf("zip.OpenReader(%q) failed: %v", dest, err)
			}
			defer after.Close()
			checkJARs(t, func(name string) bool {
				return name == "JndiLookup.class" ||
					name == "SERVER.SF" ||
					name == "SERVER.RSA"
			}, &before.Reader, &after.Reader)

			// Check that they are well formed
			out, err := exec.Command("zipinfo", "-v", dest).Output()
			if err != nil {
				t.Fatalf("zipinfo command failed for dest %s: %v", dest, err)
			}
			match, err := regexp.MatchString(`There are an extra -\d+ bytes preceding this file`, string(out))
			if err != nil {
				t.Fatalf("regex failed: %v", err)
			}
			if match {
				t.Fatalf("mitigated jar %s is malformed:\n%v", dest, string(out))
			}
		})
	}
}
