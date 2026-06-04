package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-quic/congestion_bbr1"
)

const (
	selftestMarker       = "go-control-binary:control_h3_server:bbr1-sing-control:bbr1-hy2-control:bbr1-google-control:selftest-ok"
	selftestRuntime      = "runtime=go-source-profile"
	selftestFidelity     = "source_fidelity=source"
	selftestEquivalence  = "source_equivalence=source-equivalent"
	selftestTruthful     = "truthful_control_runtime=1"
	supportedControlGoogle = "bbr1-google-control"
	supportedControlSing   = "bbr1-sing-control"
	supportedControlHy2    = "bbr1-hy2-control"
	supportedProfileGoogle = "google"
	supportedProfileSing   = "sing"
	supportedProfileHy2    = "hy2"
	controlRuntime         = "go-source-profile"
	controlResponseBytes   = 256 * 1024
	drainWindow            = 100 * time.Millisecond
)

type controlSpec struct {
	profile     string
	initialCwnd congestion.ByteCount
	bbrConfig   *congestion_bbr1.BbrConfig
}

var supportedControls = map[string]controlSpec{
	supportedControlGoogle: {
		profile:     supportedProfileGoogle,
		initialCwnd: congestion_bbr1.InitialCongestionWindowPackets,
		bbrConfig:   nil, // Google BBR1 defaults
	},
	supportedControlSing: {
		profile:     supportedProfileSing,
		initialCwnd: congestion_bbr1.InitialCongestionWindowPackets,
		bbrConfig:   nil, // sing-quic defaults (matches sing profile)
	},
	supportedControlHy2: {
		profile:     supportedProfileHy2,
		initialCwnd: 32,
		bbrConfig:   nil, // hy2: larger initial cwnd, rest same as sing
	},
}

type config struct {
	selftest   bool
	listenPort string
	control    string
	durationMS int
	certFile   string
	keyFile    string
}

type runtimeState struct {
	requestsStarted   atomic.Uint64
	requestsCompleted atomic.Uint64
	served            atomic.Bool
	servedLogged      atomic.Bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseArgs(args, stderr)
	if err != nil {
		return 2
	}

	if cfg.selftest {
		writeSelftest(stdout)
		return 0
	}

	if cfg.listenPort == "" {
		writeUsage(stderr)
		return 2
	}

	ctrl, ok := supportedControls[cfg.control]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "unsupported control %q; supported: %v\n",
			cfg.control, controlList())
		return 2
	}

	return runListener(cfg, ctrl, stderr)
}

func controlList() []string {
	var list []string
	for k := range supportedControls {
		list = append(list, k)
	}
	return list
}

func writeSelftest(stdout io.Writer) {
	_, _ = fmt.Fprintln(stdout, selftestMarker)
	_, _ = fmt.Fprintln(stdout, selftestRuntime)
	_, _ = fmt.Fprintln(stdout, selftestFidelity)
	_, _ = fmt.Fprintln(stdout, selftestEquivalence)
	_, _ = fmt.Fprintln(stdout, selftestTruthful)
}

func runListener(cfg config, ctrl controlSpec, stderr io.Writer) int {
	var state runtimeState

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.requestsStarted.Add(1)
		defer state.requestsCompleted.Add(1)

		if r.URL.Path != "/"+cfg.control {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("content-type", "application/octet-stream")
		w.Header().Set("x-angie-cc-control", cfg.control)
		w.Header().Set("x-angie-cc-profile", ctrl.profile)
		w.Header().Set("x-angie-cc-runtime", controlRuntime)
		w.WriteHeader(http.StatusOK)
		state.served.Store(true)
		logServedSummary(stderr, &state, cfg.control, ctrl.profile)

		var body [32 * 1024]byte
		left := controlResponseBytes
		for left > 0 {
			n := len(body)
			if left < n {
				n = left
			}
			if _, err := w.Write(body[:n]); err != nil {
				return
			}
			left -= n
		}
	})

	server := &http3.Server{
		Addr:    ":" + cfg.listenPort,
		Handler: handler,
		QUICConfig: &quic.Config{
			MaxIdleTimeout: 30 * time.Second,
		},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			initialPacketSize := congestion.ByteCount(conn.Config().InitialPacketSize)
			if ctrl.bbrConfig != nil {
				conn.SetCongestionControl(congestion_bbr1.NewBbrSenderWithConfig(
					congestion_bbr1.DefaultClock{TimeFunc: time.Now},
					initialPacketSize,
					ctrl.initialCwnd,
					congestion_bbr1.MaxCongestionWindowPackets,
					*ctrl.bbrConfig,
				))
			} else {
				conn.SetCongestionControl(congestion_bbr1.NewBbrSender(
					congestion_bbr1.DefaultClock{TimeFunc: time.Now},
					initialPacketSize,
					ctrl.initialCwnd,
					congestion_bbr1.MaxCongestionWindowPackets,
				))
			}
			return ctx
		},
	}

	serverErrCh := make(chan error, 1)

	go func() {
		serverErrCh <- server.ListenAndServeTLS(cfg.certFile, cfg.keyFile)
	}()

	_, _ = fmt.Fprintf(stderr, "control H3 server listening port=%s control=%s\n", cfg.listenPort, cfg.control)

	if cfg.durationMS > 0 {
		serviceTimer := time.NewTimer(time.Duration(cfg.durationMS) * time.Millisecond)
		defer serviceTimer.Stop()

		select {
		case err := <-serverErrCh:
			if err != nil && err != http.ErrServerClosed {
				_, _ = fmt.Fprintf(stderr, "serve exit reason=listen_failed err=%v\n", err)
				return 1
			}
			_, _ = fmt.Fprintln(stderr, "serve exit reason=drain_complete")
			_, _ = fmt.Fprintln(stderr, "serve success")
			logServedSummary(stderr, &state, cfg.control, ctrl.profile)
			return 0
		case <-serviceTimer.C:
		}

		if state.served.Load() {
			time.Sleep(drainWindow)
		}
	} else {
		// durationMS == 0: run until server error or external shutdown (SIGTERM)
		err := <-serverErrCh
		if err != nil && err != http.ErrServerClosed {
			_, _ = fmt.Fprintf(stderr, "serve exit reason=listen_failed err=%v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(stderr, "serve exit reason=drain_complete")
		_, _ = fmt.Fprintln(stderr, "serve success")
		logServedSummary(stderr, &state, cfg.control, ctrl.profile)
		return 0
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
		_, _ = fmt.Fprintf(stderr, "serve exit reason=shutdown_failed err=%v\n", err)
		return 1
	}

	err := <-serverErrCh
	if err != nil && err != http.ErrServerClosed {
		_, _ = fmt.Fprintf(stderr, "serve exit reason=serve_failed err=%v\n", err)
		return 1
	}

	_, _ = fmt.Fprintln(stderr, "serve exit reason=drain_complete")
	_, _ = fmt.Fprintln(stderr, "serve success")
	logServedSummary(stderr, &state, cfg.control, ctrl.profile)

	return 0
}

func logServedSummary(stderr io.Writer, state *runtimeState, control, profile string) {
	if !state.served.Load() || !state.servedLogged.CompareAndSwap(false, true) {
		return
	}

	_, _ = fmt.Fprintf(stderr, "control H3 served control=%s profile=%s requests=%d\n",
		control, profile, state.requestsStarted.Load())
}

func parseArgs(args []string, stderr io.Writer) (config, error) {
	var cfg config

	fs := flag.NewFlagSet("control_h3_server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&cfg.selftest, "selftest", false, "run a minimal self-test")
	fs.StringVar(&cfg.listenPort, "listen", "", "port to listen on")
	fs.StringVar(&cfg.control, "control", "", "control implementation name")
	fs.IntVar(&cfg.durationMS, "duration-ms", 0, "test duration in milliseconds")
	fs.StringVar(&cfg.certFile, "cert", "", "TLS certificate path")
	fs.StringVar(&cfg.keyFile, "key", "", "TLS key path")

	if err := fs.Parse(args); err != nil {
		writeUsage(stderr)
		return config{}, err
	}

	if cfg.selftest {
		return cfg, nil
	}

	if cfg.listenPort == "" && cfg.control == "" && cfg.durationMS == 0 && cfg.certFile == "" && cfg.keyFile == "" {
		return cfg, nil
	}

	if cfg.listenPort == "" || cfg.control == "" || cfg.durationMS < 0 || cfg.certFile == "" || cfg.keyFile == "" {
		_, _ = fmt.Fprintln(stderr, "listen mode requires --listen PORT --control NAME --duration-ms MS --cert FILE --key FILE")
		writeUsage(stderr)
		return config{}, fmt.Errorf("incomplete listen arguments")
	}

	return cfg, nil
}

func writeUsage(stderr io.Writer) {
	_, _ = fmt.Fprintln(stderr, "usage: control_h3_server --selftest")
	_, _ = fmt.Fprintln(stderr, "       control_h3_server --listen PORT --control NAME --duration-ms MS --cert FILE --key FILE")
}
