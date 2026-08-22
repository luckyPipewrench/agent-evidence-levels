// SPDX-License-Identifier: Apache-2.0

//go:build unix

package ael

import (
	"os/exec"
	"syscall"
)

// boundSubprocessLifetime makes a cancelled command take its children with it.
//
// exec.CommandContext kills only the process it started. A shell wrapper's
// children inherit the output pipe, so killing the shell alone leaves Run
// blocked reading a pipe the grandchild still holds, and the deadline has no
// effect at all: a script running `sleep 300` under a two-second timeout still
// took the full five minutes. Putting the command in its own process group and
// signalling the group closes both the hang and the orphan.
//
// WaitDelay is the backstop. If something still holds the pipe after the
// signal, Run closes the descriptors and returns rather than waiting forever.
func boundSubprocessLifetime(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = subprocessWaitDelay
}

// reapSubprocessGroup signals the group after the command has been waited on.
//
// Cancel above runs only when the context ends. A command that exits zero was
// never cancelled, so anything it spawned into the group kept running with the
// emitter privileges and could write into the staging package between the
// mutation check and signing. Signalling the group on every return closes that
// window. A missing group is the ordinary case and the error is discarded.
func reapSubprocessGroup(command *exec.Cmd) {
	if command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
}
