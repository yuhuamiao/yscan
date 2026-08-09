//go:build !linux

package planner

import (
	"fmt"
	"os"
	"runtime"
)

func openNucleiTemplateFile(path string) (*os.File, error) {
	return nil, fmt.Errorf("secure nuclei template opening is unsupported on %s: %s", runtime.GOOS, path)
}
