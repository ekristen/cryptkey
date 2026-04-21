// Package passkey implements a provider that uses the WebAuthn PRF extension
// via the user's browser to derive a deterministic 32-byte secret from a
// passkey (platform authenticator, security key, or cross-device via phone).
//
// The browser handles all the UX — including showing a QR code for cross-device
// passkey flows (caBLE/hybrid transport). We just serve a localhost page that
// calls the WebAuthn API.
package passkey

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/ekristen/cryptkey/pkg/provider"
)

const maxRequestBodySize = 1 << 16 // 64 KiB

//go:embed static
var staticFiles embed.FS

const browserTimeout = 2 * time.Minute

// serverReadHeaderTimeout is the timeout for reading request headers on the
// local HTTP server used for browser communication.
const serverReadHeaderTimeout = 10 * time.Second

type Passkey struct{}

func (p *Passkey) Type() string                 { return "passkey" }
func (p *Passkey) Description() string          { return "Passkey via browser (Touch ID, Windows Hello, phone)" }
func (p *Passkey) InteractiveDerive() bool      { return true }
func (p *Passkey) DeriveTimeout() time.Duration { return 120 * time.Second }

func (p *Passkey) Enroll(ctx context.Context, id string) (*provider.EnrollResult, error) {
	silent := ctx.Value(provider.CtxSilent) != nil

	if !silent {
		progress := getProgressFunc(ctx)
		progress(fmt.Sprintf("Enrolling passkey provider %q", id))
	}

	prfSalt, createChallenge, assertChallenge, userHandle, err := generateEnrollRandoms()
	if err != nil {
		return nil, err
	}

	csrfHex, err := generateCSRFToken()
	if err != nil {
		return nil, err
	}

	resultCh := make(chan enrollResult, 1)

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(staticFiles))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/enroll.html", http.StatusFound)
	})

	mux.HandleFunc("GET /api/enroll-options", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"createChallenge": hex.EncodeToString(createChallenge),
			"assertChallenge": hex.EncodeToString(assertChallenge),
			"userId":          hex.EncodeToString(userHandle),
			"userName":        fmt.Sprintf("cryptkey/%s", id),
			"rpName":          "cryptkey",
			"rpId":            "localhost",
			"prfSalt":         hex.EncodeToString(prfSalt),
			"csrfToken":       csrfHex,
		})
	})

	port, cleanup, err := startLocalServer(ctx, mux)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	origin := fmt.Sprintf("http://localhost:%d", port)
	handleResultPost(mux, "POST /api/enroll-result", csrfHex, origin, resultCh)

	url := fmt.Sprintf("http://localhost:%d/", port)
	if !silent {
		emitOpeningBrowser(ctx, url)
		getProgressFunc(ctx)("Complete the passkey enrollment in your browser...")
	}
	openBrowser(ctx, url)

	result, err := waitForEnrollResult(ctx, resultCh, prfSalt)
	if err != nil {
		return nil, err
	}

	if !silent {
		progress := getProgressFunc(ctx)
		progress("Passkey enrolled successfully")
	}

	return result, nil
}

func (p *Passkey) Derive(ctx context.Context, params map[string]string) ([]byte, error) {
	silent := ctx.Value(provider.CtxSilent) != nil

	credIDHex, prfSaltHex, err := extractDeriveParams(params)
	if err != nil {
		return nil, err
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("passkey: generate challenge: %w", err)
	}

	csrfHex, err := generateCSRFToken()
	if err != nil {
		return nil, err
	}

	resultCh := make(chan assertResult, 1)

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(staticFiles))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/assert.html", http.StatusFound)
	})

	mux.HandleFunc("GET /api/assert-options", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"challenge":    hex.EncodeToString(challenge),
			"rpId":         "localhost",
			"credentialId": credIDHex,
			"prfSalt":      prfSaltHex,
			"csrfToken":    csrfHex,
		})
	})

	port, cleanup, err := startLocalServer(ctx, mux)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	origin := fmt.Sprintf("http://localhost:%d", port)
	handleResultPost(mux, "POST /api/assert-result", csrfHex, origin, resultCh)

	url := fmt.Sprintf("http://localhost:%d/", port)
	// Surface the URL on the derive command's waiting line (right-aligned
	// dim) as a fallback in case auto-browser-open below fails. Falls
	// through silently when the callback isn't set (e.g. enroll flow,
	// tests).
	if fn, ok := ctx.Value(provider.CtxUpdateWaitingDetail).(func(string)); ok {
		fn(url)
	}
	if !silent {
		emitOpeningBrowser(ctx, url)
		getProgressFunc(ctx)("Authenticate with your passkey in the browser...")
	}
	openBrowser(ctx, url)

	return waitForAssertResult(ctx, resultCh)
}

// --- Result types ---

type enrollResult struct {
	CredentialID string `json:"credentialId"`
	PRFOutput    string `json:"prfOutput"`
	Error        string `json:"error,omitempty"`
}

type assertResult struct {
	PRFOutput string `json:"prfOutput"`
	Error     string `json:"error,omitempty"`
}

// --- Helpers ---

// getProgressFunc returns the progress callback from context, or falls back to stderr.
func getProgressFunc(ctx context.Context) func(string) {
	if v := ctx.Value(provider.CtxProgressFunc); v != nil {
		if fn, ok := v.(func(string)); ok {
			return fn
		}
	}
	return func(msg string) {
		fmt.Fprintln(os.Stderr, msg)
	}
}

// emitOpeningBrowser prints the "Opening browser" line, using the dim-URL
// link helper when one is provided on the context so the URL stays visually
// subdued next to the instructional text.
func emitOpeningBrowser(ctx context.Context, url string) {
	if v := ctx.Value(provider.CtxProgressLink); v != nil {
		if fn, ok := v.(func(string, string)); ok {
			fn("Opening browser: ", url)
			return
		}
	}
	getProgressFunc(ctx)(fmt.Sprintf("Opening browser: %s", url))
}

// generateRand32 returns 32 cryptographically random bytes.
func generateRand32(label string) ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("passkey: generate %s: %w", label, err)
	}
	return b, nil
}

// generateEnrollRandoms creates the random values needed for enrollment.
func generateEnrollRandoms() (prfSalt, createChallenge, assertChallenge, userHandle []byte, err error) {
	prfSalt, err = generateRand32("prf salt")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	createChallenge, err = generateRand32("create challenge")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	assertChallenge, err = generateRand32("assert challenge")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	userHandle, err = generateRand32("user handle")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return prfSalt, createChallenge, assertChallenge, userHandle, nil
}

// generateCSRFToken creates a hex-encoded CSRF token for request validation.
func generateCSRFToken() (string, error) {
	token, err := generateRand32("csrf token")
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

// extractDeriveParams validates and extracts required parameters for derivation.
func extractDeriveParams(params map[string]string) (credIDHex, prfSaltHex string, err error) {
	credIDHex, ok := params["credential_id"]
	if !ok {
		return "", "", errors.New("passkey: missing credential_id in config")
	}
	prfSaltHex, ok = params["prf_salt"]
	if !ok {
		return "", "", errors.New("passkey: missing prf_salt in config")
	}
	return credIDHex, prfSaltHex, nil
}

// handleResultPost registers a POST handler that decodes a JSON request body
// into T and sends it to the provided channel. It validates the Origin header
// and CSRF token before processing. This is the generic handler used by both
// the enroll-result and assert-result endpoints.
func handleResultPost[T any](mux *http.ServeMux, pattern, csrfHex, origin string, ch chan<- T) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		csrfHeader := r.Header.Get("X-CSRF-Token")
		if !validateOrigin(r, origin) || subtle.ConstantTimeCompare([]byte(csrfHeader), []byte(csrfHex)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		var result T
		if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		select {
		case ch <- result:
		default:
		}
	})
}

// startLocalServer starts an HTTP server on a random localhost port and returns
// the port number and a cleanup function. Uses context-aware listener.
func startLocalServer(ctx context.Context, mux *http.ServeMux) (port int, cleanup func(), err error) {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("passkey: listen: %w", err)
	}

	port = listener.Addr().(*net.TCPAddr).Port

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() { _ = srv.Serve(listener) }()

	cleanup = func() {
		srv.Close()
		listener.Close()
	}
	return port, cleanup, nil
}

// waitForEnrollResult waits for the browser to post an enrollment result.
func waitForEnrollResult(
	ctx context.Context, resultCh <-chan enrollResult, prfSalt []byte,
) (*provider.EnrollResult, error) {
	select {
	case result := <-resultCh:
		if result.Error != "" {
			return nil, fmt.Errorf("passkey: browser reported: %s", result.Error)
		}
		if result.PRFOutput == "" {
			return nil, errors.New(
				"passkey: PRF extension not supported by this authenticator — " +
					"use a platform authenticator (Touch ID, Windows Hello) or " +
					"phone passkey; for hardware security keys use the fido2 provider instead",
			)
		}

		secret, err := decodePRFOutput(result.PRFOutput)
		if err != nil {
			return nil, err
		}

		return &provider.EnrollResult{
			Secret: secret,
			Params: map[string]string{
				"credential_id": result.CredentialID,
				"prf_salt":      hex.EncodeToString(prfSalt),
			},
		}, nil

	case <-time.After(browserTimeout):
		return nil, errors.New("passkey: timed out waiting for browser")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// waitForAssertResult waits for the browser to post an assertion result.
func waitForAssertResult(ctx context.Context, resultCh <-chan assertResult) ([]byte, error) {
	select {
	case result := <-resultCh:
		if result.Error != "" {
			return nil, fmt.Errorf("passkey: browser reported: %s", result.Error)
		}
		if result.PRFOutput == "" {
			return nil, errors.New("passkey: PRF output missing from assertion")
		}
		return decodePRFOutput(result.PRFOutput)

	case <-time.After(browserTimeout):
		return nil, errors.New("passkey: timed out waiting for browser")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// decodePRFOutput decodes and validates a hex-encoded 32-byte PRF output.
func decodePRFOutput(hexStr string) ([]byte, error) {
	secret, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("passkey: decode prf output: %w", err)
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("passkey: expected 32-byte PRF output, got %d", len(secret))
	}
	return secret, nil
}

// validateOrigin checks that the request Origin header exactly matches the
// expected localhost origin. This prevents cross-origin requests from other sites.
func validateOrigin(r *http.Request, expected string) bool {
	return r.Header.Get("Origin") == expected
}

func openBrowser(ctx context.Context, url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", url)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", url)
	}
	_ = cmd.Start()
}

func init() {
	provider.Register(&Passkey{})
}
