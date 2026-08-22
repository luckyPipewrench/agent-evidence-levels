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
