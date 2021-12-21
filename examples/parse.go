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

// The parse tool demonstrates how to use the Parse API.
package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"runtime"

	"github.com/google/log4jscanner/jar"
)

const pathToJARFile = "../jar/testdata/vuln-class.jar"

// fileDir returns the directory for this source file.
func fileDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

func main() {
	rc, err := zip.OpenReader(filepath.Join(fileDir(), pathToJARFile))
	if err != nil {
		if errors.Is(err, zip.ErrFormat) {
			// File isn't a ZIP file.
			return
		}
		log.Fatalf("opening class: %v", err)
	}
	defer rc.Close()

	if !jar.IsJAR(&rc.Reader) {
		// ZIP file isn't a JAR file.
		return
	}

	result, err := jar.Parse(&rc.Reader)
	if err != nil {
		log.Fatalf("parzing zip file: %v", err)
	}
	if result.Vulnerable {
		fmt.Println("File is vulnerable")
	}
}
