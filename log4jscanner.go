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

    -w, --rewrite  Rewrite vulnerable JARs as they are detected.
    -v, --verbose  Print verbose logs to stderr.

`)
}

var skipDirs = map[string]bool{
	".hg":          true,
	".git":         true,
	"node_modules": true,

	// TODO(ericchiang): expand
}

func main() {
	var (
		rewrite bool
		w       bool
		verbose bool
		v       bool
	)
	flag.BoolVar(&rewrite, "rewrite", false, "")
	flag.BoolVar(&w, "w", false, "")
	flag.BoolVar(&verbose, "verbose", false, "")
	flag.BoolVar(&v, "v", false, "")
	flag.Usage = usage
	flag.Parse()
	dirs := flag.Args()
	if len(dirs) == 0 {
		usage()
		os.Exit(1)
	}
	if v {
		verbose = v
	}
	if w {
		rewrite = w
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
		SkipDir: func(path string, d fs.DirEntry) bool {
			seen++
			if seen%5000 == 0 {
				logf("Scanned %d files", seen)
			}
			if !d.IsDir() {
				return false
			}
			if skipDirs[filepath.Base(path)] {
				return true
			}
			return false
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
