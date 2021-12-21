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

//go:build linux || darwin

package jar

import (
	"fmt"
	"io/fs"
	"syscall"
)

func fileOwner(fi fs.FileInfo) (uid, gid uint32, ok bool, err error) {
	if fi.Sys() == nil {
		err = fmt.Errorf("failed to get system-specific stat info")
		return
	}
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		err = fmt.Errorf("failed to get system-specific stat info: expected *syscall.Stat_t, got %T", fi.Sys())
		return
	}
	return s.Uid, s.Gid, true, nil
}
