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

//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

var toIgnore = map[int64]bool{
	unix.CGROUP_SUPER_MAGIC: true,
	unix.BPF_FS_MAGIC:       true,
	unix.DEBUGFS_MAGIC:      true,
	unix.DEVPTS_SUPER_MAGIC: true,
	unix.PROC_SUPER_MAGIC:   true,
	unix.SECURITYFS_MAGIC:   true,
	unix.SYSFS_MAGIC:        true,
	unix.TRACEFS_MAGIC:      true,
}

func ignoreDir(path string) (bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false, fmt.Errorf("determining filesystem of %s: %v", path, err)
	}
	return toIgnore[stat.Type], nil
}
