package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteSelftest(t *testing.T) {
	var buf bytes.Buffer
	writeSelftest(&buf)

	out := buf.String()
	if !strings.Contains(out, selftestMarker) {
		t.Errorf("expected selftest marker %q, got %q", selftestMarker, out)
	}
	if !strings.Contains(out, selftestRuntime) {
		t.Errorf("expected runtime %q", selftestRuntime)
	}
}

func TestParseArgs_Selftest(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseArgs([]string{"--selftest"}, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.selftest {
		t.Error("expected selftest flag to be true")
	}
}

func TestParseArgs_Empty(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseArgs([]string{}, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.selftest || cfg.listenPort != "" || cfg.control != "" {
		t.Errorf("expected zero config, got %+v", cfg)
	}
}

func TestParseArgs_UnknownFlag(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseArgs([]string{"--unknown"}, &stderr)
	if err == nil {
		t.Error("expected error for unknown flag")
	}
}

func TestParseArgs_ListenIncomplete(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseArgs([]string{"--listen", "8443"}, &stderr)
	if err == nil {
		t.Error("expected error for incomplete listen args")
	}
}

func TestParseArgs_ListenComplete(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseArgs([]string{
		"--listen", "8443",
		"--control", supportedControlSing,
		"--duration-ms", "10000",
		"--cert", "cert.pem",
		"--key", "key.pem",
	}, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.listenPort != "8443" {
		t.Errorf("expected listenPort 8443, got %s", cfg.listenPort)
	}
	if cfg.durationMS != 10000 {
		t.Errorf("expected durationMS 10000, got %d", cfg.durationMS)
	}
}

func TestParseArgs_Hy2Control(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseArgs([]string{
		"--listen", "8443",
		"--control", supportedControlHy2,
		"--duration-ms", "10000",
		"--cert", "cert.pem",
		"--key", "key.pem",
	}, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.control != supportedControlHy2 {
		t.Errorf("expected control %q, got %q", supportedControlHy2, cfg.control)
	}
}

func TestRun_Selftest(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := run([]string{"--selftest"}, &stdout, &stderr)
	if rc != 0 {
		t.Errorf("expected exit 0, got %d", rc)
	}
	if !strings.Contains(stdout.String(), selftestMarker) {
		t.Error("expected selftest marker in stdout")
	}
}

func TestRun_EmptyArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := run([]string{}, &stdout, &stderr)
	if rc != 2 {
		t.Errorf("expected exit 2 for empty args, got %d", rc)
	}
}

func TestRun_UnsupportedControl(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := run([]string{
		"--listen", "8443",
		"--control", "bbr2-unknown",
		"--duration-ms", "10000",
		"--cert", "cert.pem",
		"--key", "key.pem",
	}, &stdout, &stderr)
	if rc != 2 {
		t.Errorf("expected exit 2 for unsupported control, got %d", rc)
	}
}

func TestRun_Hy2Control(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := run([]string{
		"--listen", "8443",
		"--control", supportedControlHy2,
		"--duration-ms", "10000",
		"--cert", "cert.pem",
		"--key", "key.pem",
	}, &stdout, &stderr)
	// hy2 should be accepted (rc != 2 means no unsupported-control error)
	if rc == 2 {
		t.Errorf("hy2 control rejected: %s", stderr.String())
	}
}

func TestParseArgs_GoogleControl(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseArgs([]string{
		"--listen", "8443",
		"--control", supportedControlGoogle,
		"--duration-ms", "10000",
		"--cert", "cert.pem",
		"--key", "key.pem",
	}, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.control != supportedControlGoogle {
		t.Errorf("expected control %q, got %q", supportedControlGoogle, cfg.control)
	}
}

func TestRun_GoogleControl(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := run([]string{
		"--listen", "8443",
		"--control", supportedControlGoogle,
		"--duration-ms", "10000",
		"--cert", "cert.pem",
		"--key", "key.pem",
	}, &stdout, &stderr)
	if rc == 2 {
		t.Errorf("google control rejected: %s", stderr.String())
	}
}

func TestWriteUsage(t *testing.T) {
	var buf bytes.Buffer
	writeUsage(&buf)
	out := buf.String()
	if !strings.Contains(out, "--selftest") {
		t.Error("expected usage to mention --selftest")
	}
	if !strings.Contains(out, "--listen") {
		t.Error("expected usage to mention --listen")
	}
}

func TestLogServedSummary_NotServed(t *testing.T) {
	var state runtimeState
	var buf bytes.Buffer
	logServedSummary(&buf, &state, "test", "profile")
	if buf.Len() != 0 {
		t.Error("expected no output when not served")
	}
}

func TestLogServedSummary_ServedOnce(t *testing.T) {
	var state runtimeState
	state.served.Store(true)
	state.requestsStarted.Add(5)

	var buf bytes.Buffer
	logServedSummary(&buf, &state, "test-ctrl", "test-profile")

	out := buf.String()
	if !strings.Contains(out, "test-ctrl") {
		t.Errorf("expected output to contain control, got %q", out)
	}

	// second call should be silent
	buf.Reset()
	logServedSummary(&buf, &state, "test-ctrl", "test-profile")
	if buf.Len() != 0 {
		t.Error("expected second log call to be silent")
	}
}

func TestControlList(t *testing.T) {
	list := controlList()
	if len(list) < 3 {
		t.Errorf("expected at least 2 controls, got %d: %v", len(list), list)
	}
	hasSing := false
	hasHy2 := false
	hasGoogle := false
	for _, c := range list {
		if c == supportedControlSing {
			hasSing = true
		}
		if c == supportedControlHy2 {
			hasHy2 = true
		}
		if c == supportedControlGoogle {
			hasGoogle = true
		}
	}
	if !hasSing {
		t.Error("missing sing control in control list")
	}
	if !hasHy2 {
		t.Error("missing hy2 control in control list")
	}
	if !hasGoogle {
		t.Error("missing google control in control list")
	}
}
