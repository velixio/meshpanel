//go:build unix

package hsconfig

import (
	"os"
	"syscall"
)

// copyOwner keeps the original file's group so headscale can still read it
// after an atomic replace. Changing the owner needs root and is skipped.
func copyOwner(name string, st os.FileInfo) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(name, -1, int(s.Gid))
	}
}
