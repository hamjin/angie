package go_control_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
)

func TestSelftestMarker(t *testing.T) {
	cmd := exec.Command("go", "run", "./cmd/control_h3_server", "--selftest")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("selftest command failed: %v\n%s", err, out)
	}

	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := "go-control-binary:control_h3_server:bbr1-sing-control:bbr1-hy2-control:bbr1-google-control:selftest-ok"
	if len(got) == 0 || got[0] != want {
		t.Fatalf("unexpected selftest marker: got %q want %q", got, want)
	}

	for _, wantLine := range []string{
		"runtime=go-source-profile",
		"source_fidelity=source",
		"source_equivalence=source-equivalent",
		"truthful_control_runtime=1",
	} {
		if !slices.Contains(got, wantLine) {
			t.Fatalf("missing selftest metadata line %q in %q", wantLine, got)
		}
	}
}

func TestListenModeServesHTTP3(t *testing.T) {
	t.Parallel()

	port := freeUDPPort(t)
	certFile, keyFile := writeSelfSignedCert(t)

	cmd := exec.Command(
		"go",
		"run",
		"./cmd/control_h3_server",
		"--listen", port,
		"--control", "bbr1-sing-control",
		"--duration-ms", "1200",
		"--cert", certFile,
		"--key", keyFile,
	)
	cmd.Dir = "."
	outputCh := make(chan []byte, 1)
	go func() {
		out, _ := cmd.CombinedOutput()
		outputCh <- out
	}()

	waitForServer(t, port)

	body, headers := fetchControl(t, port, "/bbr1-sing-control")
	if len(body) != 256*1024 {
		t.Fatalf("unexpected body length: got %d want %d", len(body), 256*1024)
	}
	if headers.Get("x-angie-cc-control") != "bbr1-sing-control" {
		t.Fatalf("unexpected control header: got %q", headers.Get("x-angie-cc-control"))
	}
	if headers.Get("x-angie-cc-profile") != "sing" {
		t.Fatalf("unexpected profile header: got %q", headers.Get("x-angie-cc-profile"))
	}
	if headers.Get("x-angie-cc-runtime") != "go-source-profile" {
		t.Fatalf("unexpected runtime header: got %q", headers.Get("x-angie-cc-runtime"))
	}

	select {
	case out := <-outputCh:
		got := string(out)
		if !strings.Contains(got, "control H3 server listening port="+port+" control=bbr1-sing-control") {
			t.Fatalf("missing listen log in output: %q", got)
		}
		if !strings.Contains(got, "serve exit reason=drain_complete") {
			t.Fatalf("missing drain_complete log in output: %q", got)
		}
		if !strings.Contains(got, "serve success") {
			t.Fatalf("missing serve success log in output: %q", got)
		}
		if !strings.Contains(got, "control H3 served control=bbr1-sing-control profile=sing requests=") {
			t.Fatalf("missing served summary log in output: %q", got)
		}
	case <-time.After(6 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("server did not exit after listen duration")
	}
}

func TestListenModeLogsServedSummaryBeforeProcessExit(t *testing.T) {
	t.Parallel()

	port := freeUDPPort(t)
	certFile, keyFile := writeSelfSignedCert(t)
	logFile := filepath.Join(t.TempDir(), "server.log")

	cmd := exec.Command(
		"go",
		"run",
		"./cmd/control_h3_server",
		"--listen", port,
		"--control", "bbr1-sing-control",
		"--duration-ms", "10000",
		"--cert", certFile,
		"--key", keyFile,
	)
	cmd.Dir = "."

	log, err := os.Create(logFile)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	t.Cleanup(func() {
		_ = log.Close()
	})
	cmd.Stdout = log
	cmd.Stderr = log

	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	waitForServer(t, port)
	body, _ := fetchControl(t, port, "/bbr1-sing-control")
	if len(body) != 256*1024 {
		t.Fatalf("unexpected body length: got %d want %d", len(body), 256*1024)
	}

	got := waitForLogContains(t, logFile,
		"control H3 served control=bbr1-sing-control profile=sing requests=", 2*time.Second)
	if strings.Contains(got, "serve exit reason=drain_complete") {
		t.Fatalf("served summary was written only after process drain: %q", got)
	}
}

func TestListenModeLogsServedSummaryWhenClientClosesEarly(t *testing.T) {
	t.Parallel()

	port := freeUDPPort(t)
	certFile, keyFile := writeSelfSignedCert(t)
	logFile := filepath.Join(t.TempDir(), "server.log")

	cmd := exec.Command(
		"go",
		"run",
		"./cmd/control_h3_server",
		"--listen", port,
		"--control", "bbr1-sing-control",
		"--duration-ms", "10000",
		"--cert", certFile,
		"--key", keyFile,
	)
	cmd.Dir = "."

	log, err := os.Create(logFile)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	t.Cleanup(func() {
		_ = log.Close()
	})
	cmd.Stdout = log
	cmd.Stderr = log

	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	waitForServer(t, port)
	fetchControlHeadersAndClose(t, port, "/bbr1-sing-control")

	waitForLogContains(t, logFile,
		"control H3 served control=bbr1-sing-control profile=sing requests=", 2*time.Second)
}

func TestFocusedDurationRunLogsCompletionAndExitsZero(t *testing.T) {
	if os.Getenv("ANGIE_GO_CONTROL_FOCUSED_SELFTEST") != "1" {
		t.Skip("set ANGIE_GO_CONTROL_FOCUSED_SELFTEST=1 to run focused-duration selftest")
	}

	port := freeUDPPort(t)
	certFile, keyFile := writeSelfSignedCert(t)
	logFile := filepath.Join(t.TempDir(), "server.log")

	cmd := exec.Command(
		"go",
		"run",
		"./cmd/control_h3_server",
		"--listen", port,
		"--control", "bbr1-sing-control",
		"--duration-ms", "31000",
		"--cert", certFile,
		"--key", keyFile,
	)
	cmd.Dir = "."

	log, err := os.Create(logFile)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	t.Cleanup(func() {
		_ = log.Close()
	})
	cmd.Stdout = log
	cmd.Stderr = log

	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	waitForServer(t, port)
	requests := fetchControlUntil(t, port, "/bbr1-sing-control", 30*time.Second)
	if requests == 0 {
		t.Fatal("focused selftest completed without control requests")
	}

	waitForLogContains(t, logFile,
		"control H3 served control=bbr1-sing-control profile=sing requests=", 2*time.Second)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			body, _ := os.ReadFile(logFile)
			t.Fatalf("server did not exit cleanly: %v\n%s", err, body)
		}
	case <-time.After(10 * time.Second):
		body, _ := os.ReadFile(logFile)
		t.Fatalf("server did not exit within focused wait window\n%s", body)
	}

	got, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	for _, needle := range []string{
		"control H3 served control=bbr1-sing-control profile=sing requests=",
		"serve exit reason=drain_complete",
		"serve success",
	} {
		if !strings.Contains(string(got), needle) {
			t.Fatalf("missing %q in focused log: %q", needle, got)
		}
	}
}

func TestListenModeRejectsWrongPath(t *testing.T) {
	t.Parallel()

	port := freeUDPPort(t)
	certFile, keyFile := writeSelfSignedCert(t)

	cmd := exec.Command(
		"go",
		"run",
		"./cmd/control_h3_server",
		"--listen", port,
		"--control", "bbr1-sing-control",
		"--duration-ms", "1200",
		"--cert", certFile,
		"--key", keyFile,
	)
	cmd.Dir = "."
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	waitForServer(t, port)

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}
	defer rt.Close()

	client := &http.Client{Transport: rt}
	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+port+"/wrong", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestListenModeRequiresKnownControl(t *testing.T) {
	cmd := exec.Command(
		"go",
		"run",
		"./cmd/control_h3_server",
		"--listen", "4433",
		"--control", "bad-control",
		"--duration-ms", "1000",
		"--cert", "cert.pem",
		"--key", "key.pem",
	)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected bad control to exit non-zero, output=%q", out)
	}

	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, `unsupported control "bad-control"`) {
		t.Fatalf("expected unsupported control marker, got %q", got)
	}
}

func waitForServer(t *testing.T, port string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rt := &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{http3.NextProtoH3},
			},
		}
		client := &http.Client{Transport: rt}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:"+port+"/wrong", nil)
		if err == nil {
			resp, doErr := client.Do(req)
			if doErr == nil {
				_ = resp.Body.Close()
				cancel()
				_ = rt.Close()
				return
			}
		}
		cancel()
		if err := rt.Close(); err != nil {
			t.Fatalf("close transport: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("server on UDP port %s did not become reachable", port)
}

func waitForLogContains(t *testing.T, path, needle string, timeout time.Duration) string {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var got string
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("read log: %v", err)
		}
		got = string(body)
		if strings.Contains(got, needle) {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("log %s missing %q within %s; got %q", path, needle, timeout, got)
	return got
}

func fetchControlHeadersAndClose(t *testing.T, port, path string) {
	t.Helper()

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}
	defer rt.Close()

	client := &http.Client{Transport: rt}
	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+port+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode, http.StatusOK)
	}

	_ = resp.Body.Close()
}

func fetchControlUntil(t *testing.T, port, path string, duration time.Duration) int {
	t.Helper()

	deadline := time.Now().Add(duration)
	requests := 0
	for time.Now().Before(deadline) {
		body, _ := fetchControl(t, port, path)
		if len(body) != 256*1024 {
			t.Fatalf("unexpected body length: got %d want %d", len(body), 256*1024)
		}
		requests++
	}

	return requests
}

func fetchControl(t *testing.T, port, path string) ([]byte, http.Header) {
	t.Helper()

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}
	defer rt.Close()

	client := &http.Client{Transport: rt}
	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+port+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return body, resp.Header
}

func freeUDPPort(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected addr type: %T", conn.LocalAddr())
	}

	return fmt.Sprintf("%d", addr.Port)
}

func writeSelfSignedCert(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certFile := filepath.Join(t.TempDir(), "cert.pem")
	keyFile := filepath.Join(t.TempDir(), "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certFile, keyFile
}
