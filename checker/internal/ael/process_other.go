// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package ael

import "os/exec"

// boundSubprocessLifetime keeps the deadline effective where process groups are
// not available. Run still stops waiting once WaitDelay elapses, so a hung
// child cannot block emission, though it is not signalled as a group.
func boundSubprocessLifetime(command *exec.Cmd) {
	command.WaitDelay = subprocessWaitDelay
}

// reapSubprocessGroup cannot signal a group on this platform.
//
// Stated rather than silently skipped: where process groups are unavailable a
// descendant that outlives its parent is not terminated here, so the mutation
// check is the thing standing between such a descendant and a signed package
// rather than a second line behind this one. The deadline still holds, because
// WaitDelay stops Run waiting on an inherited pipe.
func reapSubprocessGroup(command *exec.Cmd) {}
