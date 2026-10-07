package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSplitString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   int // number of parts expected
	}{
		{"empty", "", 100, 1},
		{"short", "hello", 100, 1},
		{"exact", "hello", 5, 1},
		{"split two", "hello world", 6, 2},
		{"split many", strings.Repeat("a", 1000), 100, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitString(tt.input, tt.maxLen)
			if len(parts) != tt.want {
				t.Errorf("splitString() got %d parts, want %d", len(parts), tt.want)
			}
			// Verify we can reconstruct
			combined := strings.Join(parts, "")
			if combined != tt.input {
				t.Errorf("splitString() reconstructed = %q, want %q", combined, tt.input)
			}
		})
	}
}

func TestMultiPartCookieStore_SmallSession(t *testing.T) {
	store := NewMultiPartCookieStore([]byte("secret-key-that-is-at-least-32-bytes-long!!"))

	// Create a request/response
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	// Get a new session
	session, err := store.Get(req, "test-session")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Store a small value
	session.Values["url"] = "https://example.com/short"
	session.Options.MaxAge = 300

	// Save the session
	err = store.Save(req, rec, session)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Check that we got exactly one cookie (not split)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Errorf("Expected 1 cookie for small session, got %d", len(cookies))
	}
	if cookies[0].Name != "test-session" {
		t.Errorf("Cookie name = %q, want %q", cookies[0].Name, "test-session")
	}
}

func TestMultiPartCookieStore_LargeSession(t *testing.T) {
	store := NewMultiPartCookieStore([]byte("secret-key-that-is-at-least-32-bytes-long!!"))

	// Create a request/response
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	// Get a new session
	session, err := store.Get(req, "test-session")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Store a very long URL (like the Grafana URL that triggered the bug)
	longURL := "https://metrics.example.com/explore?schemaVersion=1&panes=" + strings.Repeat("A", 3000)
	session.Values["requestedURL"] = longURL
	session.Values[longURL] = 1 // failcount
	session.Values["state"] = "some-random-state-nonce"
	session.Options.MaxAge = 300

	// Save the session
	err = store.Save(req, rec, session)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Check that we got multiple cookies (split)
	cookies := rec.Result().Cookies()
	if len(cookies) < 2 {
		t.Errorf("Expected multiple cookies for large session, got %d", len(cookies))
	}

	// Verify cookie naming pattern
	foundParts := 0
	for _, c := range cookies {
		if strings.Contains(c.Name, "of") {
			foundParts++
		}
	}
	if foundParts < 2 {
		t.Errorf("Expected at least 2 multipart cookies, found %d", foundParts)
	}

	// Now verify we can read the session back
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}

	session2, err := store.Get(req2, "test-session")
	if err != nil {
		t.Fatalf("Get() on read-back error = %v", err)
	}

	if session2.IsNew {
		t.Error("Expected session to be loaded, but IsNew = true")
	}

	gotURL, ok := session2.Values["requestedURL"].(string)
	if !ok || gotURL != longURL {
		t.Errorf("Read back requestedURL = %q, want %q", gotURL, longURL)
	}
}

func TestMultiPartCookieStore_DeleteSession(t *testing.T) {
	store := NewMultiPartCookieStore([]byte("secret-key-that-is-at-least-32-bytes-long!!"))

	// Create a large session first
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	session, _ := store.Get(req, "test-session")
	session.Values["data"] = strings.Repeat("X", 5000)
	session.Options.MaxAge = 300
	store.Save(req, rec, session)

	cookies := rec.Result().Cookies()

	// Now delete the session
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()

	session2, _ := store.Get(req2, "test-session")
	session2.Options.MaxAge = -1 // Mark for deletion
	store.Save(req2, rec2, session2)

	// All cookies should be deleted (MaxAge = -1)
	deleteCookies := rec2.Result().Cookies()
	for _, c := range deleteCookies {
		if c.MaxAge != -1 {
			t.Errorf("Cookie %s should have MaxAge=-1 for deletion, got %d", c.Name, c.MaxAge)
		}
	}
}

func TestMultiPartCookieStore_PrefersMultipartOverStaleSingle(t *testing.T) {
	store := NewMultiPartCookieStore([]byte("secret-key-that-is-at-least-32-bytes-long!!"))

	// First write a small session (single cookie).
	req1 := httptest.NewRequest("GET", "/", nil)
	rec1 := httptest.NewRecorder()
	session1, err := store.Get(req1, "test-session")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	session1.Values["payload"] = "small"
	session1.Options.MaxAge = 300
	if err := store.Save(req1, rec1, session1); err != nil {
		t.Fatalf("Save(small) error = %v", err)
	}
	smallCookies := rec1.Result().Cookies()

	// Then write a large session (multipart), using prior cookies in the request.
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range smallCookies {
		req2.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	session2, err := store.Get(req2, "test-session")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	largeValue := strings.Repeat("X", 10000)
	session2.Values["payload"] = largeValue
	session2.Options.MaxAge = 300
	if err := store.Save(req2, rec2, session2); err != nil {
		t.Fatalf("Save(large) error = %v", err)
	}

	// Simulate a client that still sends a stale single cookie alongside new
	// multipart cookies: multipart must win.
	req3 := httptest.NewRequest("GET", "/", nil)
	for _, c := range smallCookies {
		if c.Name == "test-session" {
			req3.AddCookie(c)
		}
	}
	for _, c := range rec2.Result().Cookies() {
		if strings.Contains(c.Name, "of") {
			req3.AddCookie(c)
		}
	}

	session3, err := store.Get(req3, "test-session")
	if err != nil {
		t.Fatalf("Get() read-back error = %v", err)
	}
	got, ok := session3.Values["payload"].(string)
	if !ok {
		t.Fatalf("payload type = %T, want string", session3.Values["payload"])
	}
	if got != largeValue {
		t.Fatalf("payload len = %d, want %d", len(got), len(largeValue))
	}
}

func TestMultiPartCookieStore_GetReturnsErrorOnInvalidCookie(t *testing.T) {
	store := NewMultiPartCookieStore([]byte("secret-key-that-is-at-least-32-bytes-long!!"))

	req1 := httptest.NewRequest("GET", "/", nil)
	rec1 := httptest.NewRecorder()
	session1, err := store.Get(req1, "test-session")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	session1.Values["payload"] = "valid"
	session1.Options.MaxAge = 300
	if err := store.Save(req1, rec1, session1); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	validCookies := rec1.Result().Cookies()
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range validCookies {
		if c.Name == "test-session" {
			tampered := *c
			tampered.Value = c.Value + "tampered"
			req2.AddCookie(&tampered)
		}
	}

	session2, err := store.Get(req2, "test-session")
	if err == nil {
		t.Fatal("Get() error = nil, want decode error")
	}
	if session2 == nil {
		t.Fatal("Get() session is nil, want non-nil session")
	}
	if !session2.IsNew {
		t.Fatal("session.IsNew = false, want true for decode failure")
	}
}

func TestMultiPartCookieStore_GetReturnsErrorOnMissingMultipartPart(t *testing.T) {
	store := NewMultiPartCookieStore([]byte("secret-key-that-is-at-least-32-bytes-long!!"))

	req1 := httptest.NewRequest("GET", "/", nil)
	rec1 := httptest.NewRecorder()
	session1, err := store.Get(req1, "test-session")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	session1.Values["payload"] = strings.Repeat("X", 10000)
	session1.Options.MaxAge = 300
	if err := store.Save(req1, rec1, session1); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Drop one part from the request to force a reassembly error.
	req2 := httptest.NewRequest("GET", "/", nil)
	dropped := false
	for _, c := range rec1.Result().Cookies() {
		if strings.Contains(c.Name, "of") && !dropped {
			dropped = true
			continue
		}
		req2.AddCookie(c)
	}

	session2, err := store.Get(req2, "test-session")
	if err == nil {
		t.Fatal("Get() error = nil, want multipart read error")
	}
	if session2 == nil {
		t.Fatal("Get() session is nil, want non-nil session")
	}
	if !session2.IsNew {
		t.Fatal("session.IsNew = false, want true for read failure")
	}
}

func TestMultiPartCookieStore_GetNoCookieStillReturnsIsNew(t *testing.T) {
	store := NewMultiPartCookieStore([]byte("secret-key-that-is-at-least-32-bytes-long!!"))
	req := httptest.NewRequest("GET", "/", nil)

	session, err := store.Get(req, "test-session")
	if err != nil {
		t.Fatalf("Get() error = %v, want nil", err)
	}
	if !session.IsNew {
		t.Fatal("session.IsNew = false, want true when no cookie exists")
	}
}

func TestMultiPartCookieStore_NewNoCookieStillReturnsIsNew(t *testing.T) {
	store := NewMultiPartCookieStore([]byte("secret-key-that-is-at-least-32-bytes-long!!"))
	req := httptest.NewRequest("GET", "/", nil)

	session, err := store.New(req, "test-session")
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	if !session.IsNew {
		t.Fatal("session.IsNew = false, want true when no cookie exists")
	}
}

func TestMultiPartCookieStore_NewReturnsErrNoCookieOnlyInternally(t *testing.T) {
	store := NewMultiPartCookieStore([]byte("secret-key-that-is-at-least-32-bytes-long!!"))
	req := httptest.NewRequest("GET", "/", nil)

	_, err := store.readMultiPartCookie(req, "test-session")
	if err == nil || err != http.ErrNoCookie {
		t.Fatalf("readMultiPartCookie() error = %v, want %v", err, http.ErrNoCookie)
	}
}
