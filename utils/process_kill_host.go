//go:build !tinygo && !wasip1 && !wasip2 && !js

package utils

import (
	"fmt"
	"os"
	"syscall"
)

func KillProcess(pid int) error {
	if pid == -1 {
		return nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process with pid %d: %w", pid, err)
	}
	if err := process.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to send SIGKILL to process with pid %d: %w", pid, err)
	}

	return nil
}
