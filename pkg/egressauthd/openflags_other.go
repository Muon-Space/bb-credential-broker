//go:build !unix

package egressauthd

// extraOpenFlags is a no-op on platforms without O_NOFOLLOW (e.g. Windows).
// egress-authd is a Linux-only sidecar; this stub exists solely so the
// package compiles in the cross-platform release build matrix. The
// symlink-follow guard is therefore Unix-only, which is the only platform
// the sidecar ever runs writeActionFile on.
func extraOpenFlags() int { return 0 }
