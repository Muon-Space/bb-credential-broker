//go:build unix

package egressauthd

import "golang.org/x/sys/unix"

// extraOpenFlags returns O_NOFOLLOW on Unix so writeActionFile never follows
// a symlink when materialising a per-action helper file. golang.org/x/sys/unix
// provides the constant on every Unix GOOS; the std syscall package does not
// export it portably (it is absent on Windows), which is why this is split
// behind a build tag.
func extraOpenFlags() int { return unix.O_NOFOLLOW }
