package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/plimsoll-protocol/plimsoll-indexer/internal/coverage"
)

const (
	docCheckLimit   = 100
	docFetchTimeout = 5 * time.Second
	docMaxBytes     = 10 * 1024 * 1024 // 10 MB
	docMaxRedirects = 2
)

// docCheckStore is the storage surface the doc checker needs.
type docCheckStore interface {
	ListPendingDocChecks(ctx context.Context, limit int) ([]coverage.DocCheckTask, error)
	SaveDocCheck(ctx context.Context, eventID, result string) error
}

// DocChecker fetches the reserve document at each report's doc_uri, hashes the
// content and compares it against the doc_hash posted on-chain. The result is
// written back as "match", "mismatch", or "unreachable".
//
// Security rules enforced on every fetch:
//   - HTTPS only; non-TLS URIs are recorded as "unreachable" without connecting.
//   - No connections to private or loopback IP ranges (SSRF guard).
//   - Response body capped at 10 MB; only that prefix is hashed.
//   - 5-second total timeout per document.
//   - At most 2 redirects; any redirect to a non-HTTPS URL is refused.
type DocChecker struct {
	Store  docCheckStore
	Log    *slog.Logger
	client *http.Client
}

// NewDocChecker returns a DocChecker with a constrained HTTP client.
func NewDocChecker(store docCheckStore, log *slog.Logger) *DocChecker {
	return &DocChecker{
		Store:  store,
		Log:    log,
		client: buildDocClient(),
	}
}

// Run checks every pending reserve document once. Call it on a ticker.
func (dc *DocChecker) Run(ctx context.Context) error {
	tasks, err := dc.Store.ListPendingDocChecks(ctx, docCheckLimit)
	if err != nil {
		return fmt.Errorf("list pending doc checks: %w", err)
	}
	var errs []error
	for _, task := range tasks {
		result, err := dc.checkDoc(ctx, task.DocURI, task.DocHash)
		if err != nil {
			errs = append(errs, fmt.Errorf("doc check %s: %w", task.EventID, err))
			continue
		}
		if err := dc.Store.SaveDocCheck(ctx, task.EventID, result); err != nil {
			errs = append(errs, fmt.Errorf("save doc check %s: %w", task.EventID, err))
			continue
		}
		dc.Log.Info("checked reserve document", "event_id", task.EventID, "result", result)
	}
	return errors.Join(errs...)
}

// checkDoc fetches uri, hashes the response body (up to docMaxBytes) and
// compares it to expectedHash. It returns "match", "mismatch", or
// "unreachable" and never surfaces transient network errors as Go errors:
// those are reported as "unreachable" after being logged.
func (dc *DocChecker) checkDoc(ctx context.Context, uri, expectedHash string) (string, error) {
	if uri == "" {
		return "unreachable", nil
	}
	// #nosec G107 -- URI is validated (HTTPS-only scheme; private-IP dialer)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		dc.Log.Debug("doc uri malformed", "uri", uri, "err", err)
		return "unreachable", nil
	}
	if req.URL.Scheme != "https" {
		dc.Log.Warn("skipping non-https doc uri", "uri", uri)
		return "unreachable", nil
	}

	resp, err := dc.client.Do(req)
	if err != nil {
		dc.Log.Debug("doc uri unreachable", "uri", uri, "err", err)
		return "unreachable", nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		dc.Log.Debug("doc uri returned non-2xx", "uri", uri, "status", resp.StatusCode)
		return "unreachable", nil
	}

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(resp.Body, docMaxBytes)); err != nil {
		dc.Log.Debug("doc uri read error", "uri", uri, "err", err)
		return "unreachable", nil
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got == expectedHash {
		return "match", nil
	}
	dc.Log.Info("doc hash mismatch", "uri", uri, "expected", expectedHash, "got", got)
	return "mismatch", nil
}

// privateRanges are IP blocks that must not be reached from a public service.
var privateRanges = func() []net.IPNet {
	blocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local IPv4
		"::1/128",
		"fc00::/7",  // unique local IPv6
		"fe80::/10", // link-local IPv6
		"0.0.0.0/8", // "this" network
	}
	var out []net.IPNet
	for _, b := range blocks {
		_, ipnet, err := net.ParseCIDR(b)
		if err != nil {
			panic("bad private range: " + b)
		}
		out = append(out, *ipnet)
	}
	return out
}()

// isPrivate reports whether addr is in a private or loopback range.
func isPrivate(addr net.Addr) bool {
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	default:
		host, _, _ := net.SplitHostPort(addr.String())
		ip = net.ParseIP(host)
	}
	if ip == nil {
		return true // fail closed: unparse-able address is treated as private
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// buildDocClient returns an *http.Client configured for safe document fetches.
func buildDocClient() *http.Client {
	dialer := &net.Dialer{Timeout: docFetchTimeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if isPrivate(conn.RemoteAddr()) {
				_ = conn.Close()
				return nil, fmt.Errorf("refusing connection to private address %s", conn.RemoteAddr())
			}
			return conn, nil
		},
		DisableKeepAlives: true,
	}
	return &http.Client{
		Timeout:   docFetchTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= docMaxRedirects {
				return http.ErrUseLastResponse
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect to non-https refused")
			}
			return nil
		},
	}
}
