//go:build tinygo || wasip1 || wasip2 || js

package utils

func KillProcess(pid int) error {
	_ = pid
	return nil
}
