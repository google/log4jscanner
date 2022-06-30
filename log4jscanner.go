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

// The log4jscanner tool scans a set of directories for log4j vulnerable JARs.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/google/log4jscanner/jar"
)

func usage() {
	fmt.Fprint(os.Stderr, `Usage: log4jscanner [flag] [directories]

A log4j vulnerability scanner. The scanner walks the provided directories
attempting to find vulnerable JARs. Paths of vulnerable JARs are printed
to stdout.

Flags:

    -s, --skip     Glob pattern to skip when scanning (e.g. '/var/run/*'). May
                   be provided multiple times.
    -f, --force    Don't skip network and userland filesystems. (smb,nfs,afs,fuse)
    -w, --rewrite  Rewrite vulnerable JARs as they are detected.
    -v, --verbose  Print verbose logs to stderr.
    -b, --backup   Make a backup of the scanned files

`)
}

var skipDirs = map[string]bool{
	".hg":          true,
	".git":         true,
	"node_modules": true,
	".idea":        true,
	".svn":         true,
	".p4root":      true,

	// TODO(ericchiang): expand
}

func main() {
	var (
		rewrite bool
		w       bool
		verbose bool
		v       bool
		force   bool
		f       bool
		backup  bool
		b       bool
		toSkip  []string
	)
	appendSkip := func(dir string) error {
		toSkip = append(toSkip, dir)
		return nil
	}

	flag.BoolVar(&rewrite, "rewrite", false, "")
	flag.BoolVar(&w, "w", false, "")
	flag.BoolVar(&verbose, "verbose", false, "")
	flag.BoolVar(&v, "v", false, "")
	flag.BoolVar(&force, "force", false, "")
	flag.BoolVar(&f, "f", false, "")
	flag.BoolVar(&b, "b", false, "")
	flag.BoolVar(&backup, "backup", false, "")
	flag.Func("s", "", appendSkip)
	flag.Func("skip", "", appendSkip)
	flag.Usage = usage
	flag.Parse()
	dirs := flag.Args()
	if len(dirs) == 0 {
		usage()
		os.Exit(1)
	}
	if f {
		force = f
	}
	if v {
		verbose = v
	}
	if w {
		rewrite = w
	}
	if b {
		backup = b
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	logf := func(format string, v ...interface{}) {
		if verbose {
			log.Printf(format, v...)
		}
	}
	seen := 0
	walker := jar.Walker{
		Rewrite: rewrite,
		Backup:  backup,
		SkipDir: func(path string, d fs.DirEntry) bool {
			seen++
			if seen%5000 == 0 {
				logf("Scanned %d files", seen)
			}
			if !d.IsDir() {
				return false
			}
			for _, pattern := range toSkip {
				if ok, err := filepath.Match(pattern, path); err == nil && ok {
					return true
				}
			}
			if skipDirs[filepath.Base(path)] {
				return true
			}
			ignore, err := ignoreDir(path, force)
			if err != nil {
				log.Printf("Error scanning %s: %v", path, err)
			}
			return ignore
		},
		HandleError: func(path string, err error) {
			log.Printf("Error: scanning %s: %v", path, err)
		},
		HandleReport: func(path string, r *jar.Report) {
			if !rewrite {
				fmt.Println(path)
			}
		},
		HandleRewrite: func(path string, r *jar.Report) {
			if rewrite {
				fmt.Println(path)
			}
		},
	}

	for _, dir := range dirs {
		logf("Scanning %s", dir)
		if err := walker.Walk(dir); err != nil {
			log.Printf("Error: walking %s: %v", dir, err)
		}
	}
}
