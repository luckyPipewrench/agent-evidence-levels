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
// This is resource hygiene, not integrity, and the distinction matters because
// the earlier design made it load-bearing. The checker now runs against a
// disposable replica and the emitter writes every packaged byte itself, so a
// descendant that outlives its parent has nothing in the signed package to
// reach whether it is terminated or not. What is lost here is the tidy-up: such
// a descendant may keep running and consuming resources until the operator
// notices it.
func reapSubprocessGroup(command *exec.Cmd) {}
