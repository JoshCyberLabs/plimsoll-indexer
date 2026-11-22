package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plimsoll-protocol/plimsoll-indexer/internal/coverage"
)

// fakeDocStore satisfies docCheckStore for tests.
type fakeDocStore struct {
	tasks   []coverage.DocCheckTask
	saved   map[string]string // event_id -> result
	saveErr error
}

func (s *fakeDocStore) ListPendingDocChecks(_ context.Context, _ int) ([]coverage.DocCheckTask, error) {
	return s.tasks, nil
}

func (s *fakeDocStore) SaveDocCheck(_ context.Context, eventID, result string) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	if s.saved == nil {
		s.saved = make(map[string]string)
	}
	s.saved[eventID] = result
	return nil
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// newTestDocChecker returns a DocChecker that uses the given test server's
// TLS client, bypassing the private-IP guard so 127.0.0.1 is reachable.
func newTestDocChecker(store docCheckStore, client *http.Client) *DocChecker {
	return &DocChecker{
		Store:  store,
		Log:    discardLog(),
		client: client,
	}
}

// TestDocCheckerMatch proves that when a document's content hashes to the
// expected value the result is "match".
func TestDocCheckerMatch(t *testing.T) {
	content := []byte("reserve report content")
	hash := sha256hex(content)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	store := &fakeDocStore{tasks: []coverage.DocCheckTask{
		{EventID: "evt-1", DocURI: srv.URL + "/doc", DocHash: hash},
	}}
	dc := newTestDocChecker(store, srv.Client())

	if err := dc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.saved["evt-1"]; got != "match" {
		t.Errorf("want match, got %q", got)
	}
}

// TestDocCheckerMismatch proves that when the document content differs from
// the on-chain hash the result is "mismatch".
func TestDocCheckerMismatch(t *testing.T) {
	content := []byte("tampered content")
	wrongHash := strings.Repeat("00", 32)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	store := &fakeDocStore{tasks: []coverage.DocCheckTask{
		{EventID: "evt-2", DocURI: srv.URL + "/doc", DocHash: wrongHash},
	}}
	dc := newTestDocChecker(store, srv.Client())

	if err := dc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.saved["evt-2"]; got != "mismatch" {
		t.Errorf("want mismatch, got %q", got)
	}
}

// TestDocCheckerUnreachableServer proves that a connection failure stores
// "unreachable" and does not propagate the error to the caller.
func TestDocCheckerUnreachableServer(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	uri := srv.URL + "/doc"
	srv.Close() // close immediately so the fetch fails

	store := &fakeDocStore{tasks: []coverage.DocCheckTask{
		{EventID: "evt-3", DocURI: uri, DocHash: strings.Repeat("ab", 32)},
	}}
	dc := newTestDocChecker(store, srv.Client())

	if err := dc.Run(context.Background()); err != nil {
		t.Fatalf("want nil error from Run, got %v", err)
	}
	if got := store.saved["evt-3"]; got != "unreachable" {
		t.Errorf("want unreachable, got %q", got)
	}
}

// TestDocCheckerNonHttpsUri proves that a plain HTTP URI is refused without
// making a network connection.
func TestDocCheckerNonHttpsUri(t *testing.T) {
	store := &fakeDocStore{tasks: []coverage.DocCheckTask{
		{EventID: "evt-4", DocURI: "http://example.com/doc", DocHash: strings.Repeat("cc", 32)},
	}}
	dc := NewDocChecker(store, discardLog()) // production client, never dials

	if err := dc.Run(context.Background()); err != nil {
		t.Fatalf("want nil error from Run, got %v", err)
	}
	if got := store.saved["evt-4"]; got != "unreachable" {
		t.Errorf("want unreachable for http:// URI, got %q", got)
	}
}

// TestDocCheckerNon2xxStatus proves that a 4xx/5xx response is "unreachable".
func TestDocCheckerNon2xxStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // 404
	}))
	defer srv.Close()

	store := &fakeDocStore{tasks: []coverage.DocCheckTask{
		{EventID: "evt-5", DocURI: srv.URL + "/doc", DocHash: strings.Repeat("dd", 32)},
	}}
	dc := newTestDocChecker(store, srv.Client())

	if err := dc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.saved["evt-5"]; got != "unreachable" {
		t.Errorf("want unreachable for 404, got %q", got)
	}
}

// TestDocCheckerSizeCap proves that documents larger than 10 MB are hashed
// only up to the cap: a document whose first 10 MB hash to expectedHash will
// be "match" even when more bytes follow.
func TestDocCheckerSizeCap(t *testing.T) {
	const cap = docMaxBytes
	body := make([]byte, cap+1_000) // slightly over cap
	for i := range body {
		body[i] = 0x41 // 'A'
	}
	expectedHash := sha256hex(body[:cap])

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	store := &fakeDocStore{tasks: []coverage.DocCheckTask{
		{EventID: "evt-6", DocURI: srv.URL + "/doc", DocHash: expectedHash},
	}}
	dc := newTestDocChecker(store, srv.Client())

	if err := dc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.saved["evt-6"]; got != "match" {
		t.Errorf("want match (first 10 MB hashes correctly), got %q", got)
	}
}

// TestDocCheckerEmptyUriIsUnreachable proves that an empty doc_uri is
// recorded as "unreachable" without any network activity.
func TestDocCheckerEmptyUriIsUnreachable(t *testing.T) {
	store := &fakeDocStore{tasks: []coverage.DocCheckTask{
		{EventID: "evt-7", DocURI: "", DocHash: strings.Repeat("ee", 32)},
	}}
	dc := NewDocChecker(store, discardLog())

	if err := dc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.saved["evt-7"]; got != "unreachable" {
		t.Errorf("want unreachable for empty URI, got %q", got)
	}
}

// TestIsPrivate verifies the private-range check covers common internal
// addresses without blocking public ones.
func TestIsPrivate(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.0", false}, // just outside 172.16/12
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.0.1", true},
		{"::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:db8::1", false},
	}
	for _, tc := range cases {
		addr := &fakeAddr{ip: tc.ip}
		if got := isPrivate(addr); got != tc.want {
			t.Errorf("isPrivate(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// fakeAddr implements net.Addr for the IP-check test.
type fakeAddr struct{ ip string }

func (a *fakeAddr) Network() string { return "tcp" }
func (a *fakeAddr) String() string {
	if strings.Contains(a.ip, ":") {
		return "[" + a.ip + "]:443" // IPv6 must be bracketed
	}
	return a.ip + ":443"
}
