package internal

import "testing"

func TestRunCommand(t *testing.T) {
	if err := RunCommand("true"); err != nil {
		t.Errorf("RunCommand(true) = %v", err)
	}
	if err := RunCommand(""); err == nil {
		t.Error("RunCommand empty: expected error")
	}
	if err := RunCommand("false"); err == nil {
		t.Error("RunCommand false: expected error")
	}
}
