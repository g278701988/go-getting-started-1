package common

import (
	"errors"
	"log"
	"os"
	"path/filepath"
)

// CurrentPath from Current execute path
func CurrentPath() string {
	var dirAbsPath string
	ex, err := os.Executable()
	if err == nil {
		dirAbsPath = filepath.Dir(ex)
		return dirAbsPath
	}

	exReal, err := filepath.EvalSymlinks(ex)
	if err != nil {
		return ""
	}
	dirAbsPath = filepath.Dir(exReal)
	return dirAbsPath
}
func AppendToFile(path string, bytes []byte) error {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Error closing file: %s\n", err)
		}
	}()
	if _, err := f.Write(bytes); err != nil {
		return err
	}

	return nil
}
func IsFileNotExist(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0666)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Error closing file: %s\n", err)
		}
	}()
	return false

}
