package jar

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func BackupFiles(jar string) {
	pathdst := filepath.Join(".", "backup")
	if _, err := os.Stat(pathdst); os.IsNotExist(err) {
		err := os.Mkdir(pathdst, os.ModePerm)
		if err != nil {
			fmt.Errorf("create backup %v", err)
		}
	}

	jarSplit := strings.Split(jar, "/")

	if len(jarSplit) == 3 {
		pathdst = pathdst + "/" + jarSplit[2] + ".bak"
	}

	if len(jarSplit) == 4 {
		pathdst = pathdst + "/" + jarSplit[3] + ".bak"
	}

	_, err := copyJars(jar, pathdst)
	if err != nil {
		fmt.Errorf("copy file %v ", err)
	}
}

func copyJars(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
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
