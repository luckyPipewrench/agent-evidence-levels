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
// This is resource and availability hygiene, not the integrity proof. The
// emitter's final byte bindings refuse a pre-signing change and the validator
// rejects a later one, but an unreaped descendant can still consume resources
// or make an otherwise honest emission fail.
func reapSubprocessGroup(command *exec.Cmd) {}
