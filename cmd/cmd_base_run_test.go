package cmdbase

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/GiGurra/boa/pkg/boa"
	"github.com/spf13/cobra"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

func failingCmd(rawArgs []string) boa.CmdT[boa.NoParams] {
	return boa.CmdT[boa.NoParams]{
		Use:     "testcli",
		RawArgs: rawArgs,
		SubCmds: boa.SubCmds(
			boa.CmdT[boa.NoParams]{
				Use:   "boom",
				Short: "fail on purpose",
				RunFuncE: func(p *boa.NoParams, cmd *cobra.Command, args []string) error {
					return fmt.Errorf("kaboom")
				},
			},
		),
	}
}

func TestRun_RuntimeErrorDoesNotPrintUsage(t *testing.T) {
	oldExit := osExit
	t.Cleanup(func() { osExit = oldExit })
	exitCode := 0
	osExit = func(code int) { exitCode = code }

	stderr := captureStderr(t, func() {
		Run(failingCmd([]string{"boom"}))
	})

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr, "Error: kaboom") {
		t.Fatalf("stderr = %q, want Error: kaboom", stderr)
	}
	if strings.Contains(stderr, "Usage:") || strings.Contains(stderr, "Available Commands") {
		t.Fatalf("stderr dumped help on runtime error: %q", stderr)
	}
}

func TestRun_UserInputErrorDoesNotPrintUsage(t *testing.T) {
	oldExit := osExit
	t.Cleanup(func() { osExit = oldExit })
	exitCode := 0
	osExit = func(code int) { exitCode = code }

	stderr := captureStderr(t, func() {
		Run(failingCmd([]string{"boom", "--no-such-flag"}))
	})

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr, "Error:") {
		t.Fatalf("stderr = %q, want Error:", stderr)
	}
	if strings.Contains(stderr, "Usage:") || strings.Contains(stderr, "Available Commands") {
		t.Fatalf("stderr dumped help on user input error: %q", stderr)
	}
}

func TestRun_HelpStillPrints(t *testing.T) {
	oldExit := osExit
	t.Cleanup(func() { osExit = oldExit })
	osExit = func(code int) {
		t.Fatalf("os.Exit(%d) called for --help", code)
	}

	stdout := captureStdout(t, func() {
		Run(failingCmd([]string{"--help"}))
	})

	if !strings.Contains(stdout, "Available Commands") {
		t.Fatalf("stdout = %q, want help text", stdout)
	}
}
