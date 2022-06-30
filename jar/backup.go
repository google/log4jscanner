// Copyright 2022 Google LLC
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
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// backupFile makes copies JARs file in the backup folder
func backupFile(jarPath string, jarSource string, jarFile string) error {
	pathdst := filepath.Join(jarPath, "backup")

	err := makeDirIfNotExist(pathdst)
	if err != nil {
		return err
	}

	jarDst := pathdst + "/" + jarFile + ".bak"

	_, err = copyJars(jarSource, jarDst)
	if err != nil {
		return err
	}
	return nil
}

// makeDirIfNotExist make folder to copies file from
// directory to scan
func makeDirIfNotExist(src string) error {
	if _, err := os.Stat(src); os.IsNotExist(err) {
		err := os.Mkdir(src, os.ModePerm)
		if err != nil {
			return fmt.Errorf("creating backup directory: %v", err)
		}
	}
	return nil
}

func copyJars(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if m := sourceFileStat.Mode(); !m.IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file: %s", src, m)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}
