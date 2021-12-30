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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// IsJAR determines if a given ZIP reader is a JAR.
func IsJAR(zr *zip.Reader) bool {
	// Optimization: Scan file header for the JAR-specific dir META-INF, bail
	// if it's not present (it must not be a jar).
	// In practice, JARs seem to have their META-INF directory at the beginning
	// of the central directory structure.
	// Jar files missing that directory still get loaded, so we also check for
	// class files and nested jars.
	for _, fh := range zr.File {
		isDir := fh.FileInfo().IsDir()
		if (isDir && strings.HasPrefix(fh.Name, "META-INF")) ||
			(isDir && strings.HasPrefix(fh.Name, "WEB-INF")) ||
			(!isDir && strings.HasSuffix(fh.Name, ".class")) ||
			(!isDir && strings.HasSuffix(fh.Name, ".jar")) {
			return true
		}
	}
	return false
}

// Walker implements a filesystem walker to scan for log4j vulnerable JARs
// and optional rewrite them.
type Walker struct {
	// Rewrite indicates if the Walker should rewrite JARs in place as it
	// iterates through the filesystem.
	Rewrite bool
	// SkipDir, if provided, allows the walker to skip certain directories
	// as it scans.
	SkipDir func(path string, de fs.DirEntry) bool
	// HandleError can be used to handle errors for a given directory or
	// JAR file.
	HandleError func(path string, err error)
	// HandleReport is called when a JAR is determined vulnerable. If Rewrite
	// is provided, this is called before the Rewrite occurs.
	HandleReport func(path string, r *Report)
	// HandleRewrite is called when a JAR is rewritten successfully.
	HandleRewrite func(path string, r *Report)
}

// Walk attempts to scan a directory for vulnerable JARs.
func (w *Walker) Walk(dir string) error {
	fsys := os.DirFS(dir)
	wk := walker{w, fsys, dir}

	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			wk.handleError(p, err)
			return nil
		}
		if wk.skipDir(p, d) {
			return fs.SkipDir
		}
		if err := wk.visit(p, d); err != nil {
			wk.handleError(p, err)
		}
		return nil
	})
}

type walker struct {
	*Walker
	fs  fs.FS
	dir string
}

func (w *walker) filepath(path string) string {
	return filepath.Join(w.dir, path)
}

func (w *walker) handleError(path string, err error) {
	if w.HandleError == nil {
		return
	}
	w.HandleError(w.filepath(path), err)
}

func (w *walker) handleReport(path string, r *Report) {
	if w.HandleReport == nil {
		return
	}
	w.HandleReport(w.filepath(path), r)
}

func (w *walker) handleRewrite(path string, r *Report) {
	if w.HandleRewrite == nil {
		return
	}
	w.HandleRewrite(w.filepath(path), r)
}

func (w *walker) skipDir(path string, d fs.DirEntry) bool {
	if w.SkipDir == nil {
		return false
	}
	return w.SkipDir(w.filepath(path), d)
}

func (w *walker) visit(p string, d fs.DirEntry) error {
	if d.IsDir() || !d.Type().IsRegular() {
		return nil
	}
	if !exts[path.Ext(p)] {
		return nil
	}
	f, err := w.fs.Open(p)
	if err != nil {
		return fmt.Errorf("open: %v", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat: %v", err)
	}
	ra, ok := f.(io.ReaderAt)
	if !ok {
		return fmt.Errorf("file doesn't implement reader at: %T", f)
	}
	zr, _, err := NewReader(ra, info.Size())
	if err != nil {
		if err == zip.ErrFormat {
			// Not a JAR.
			return nil
		}
		return fmt.Errorf("opennig file as a ZIP archive: %v", err)
	}
	if !IsJAR(zr) {
		return nil
	}
	r, err := Parse(zr)
	if err != nil {
		return fmt.Errorf("scanning jar: %v", err)
	}

	if !r.Vulnerable {
		return nil
	}
	w.handleReport(p, r)

	if !w.Rewrite {
		return nil
	}

	dest := w.filepath(p)
	// Ensure temp file is created in the same directory as the file we want to
	// rewrite to improve the chances of ending up on the same filesystem. On
	// Linux, os.Rename() doesn't work across filesystems.
	//
	// https://github.com/google/log4jscanner/issues/18
	tf, err := os.CreateTemp(filepath.Dir(dest), ".log4jscanner")
	if err != nil {
		return fmt.Errorf("creating temp file: %v", err)
	}
	defer os.Remove(tf.Name()) // Attempt to clean up temp file no matter what.
	defer tf.Close()

	if err := RewriteJAR(tf, ra, info.Size()); err != nil {
		return fmt.Errorf("failed to rewrite %s: %v", p, err)
	}

	// Files must be closed for rewrite to work on Windows.
	f.Close()
	tf.Close()
	if err := os.Chmod(tf.Name(), info.Mode()); err != nil {
		return fmt.Errorf("chmod file: %v", err)
	}

	uid, gid, ok, err := fileOwner(info)
	if err != nil {
		return fmt.Errorf("determining file owner: %v", err)
	}
	if ok {
		if err := os.Chown(tf.Name(), int(uid), int(gid)); err != nil {
			return fmt.Errorf("changing ownership of temporary file: %v", err)
		}
	}
	if err := os.Rename(tf.Name(), dest); err != nil {
		return fmt.Errorf("overwriting %s: %v", p, err)
	}
	w.handleRewrite(p, r)
	return nil
}
