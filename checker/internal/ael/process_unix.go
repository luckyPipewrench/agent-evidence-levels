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
