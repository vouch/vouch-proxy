/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package session

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// maxCookieSize is the maximum size of a single Set-Cookie header value.
// Browsers typically limit cookies to 4096 bytes, but this includes the
// cookie name, path, domain, and other attributes - not just the value.
// We use 3800 to leave ~300 bytes of headroom for this metadata.
const maxCookieSize = 3800

// MultiPartCookieStore is a session store that splits large session cookies
// into multiple parts, similar to how Vouch handles JWT cookies.
// This fixes https://github.com/vouch/vouch-proxy/issues/348
type MultiPartCookieStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
}

// NewMultiPartCookieStore creates a new MultiPartCookieStore with the given key pairs.
func NewMultiPartCookieStore(keyPairs ...[]byte) *MultiPartCookieStore {
	codecs := securecookie.CodecsFromPairs(keyPairs...)
	// Increase the max length for the securecookie encoder
	// We'll handle splitting into multiple cookies ourselves
	for _, codec := range codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			// Set a very high limit - we'll split the result into multiple cookies
			sc.MaxLength(0) // 0 means unlimited
		}
	}
	return &MultiPartCookieStore{
		Codecs: codecs,
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400,
		},
	}
}

// Get returns a session for the given name after adding it to the registry.
func (s *MultiPartCookieStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
func (s *MultiPartCookieStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true

	// Try to load existing session from cookies
	value, err := s.readMultiPartCookie(r, name)
	if errors.Is(err, http.ErrNoCookie) {
		return session, nil
	}
	if err != nil {
		return session, err
	}

	err = securecookie.DecodeMulti(name, value, &session.Values, s.Codecs...)
	if err == nil {
		session.IsNew = false
	}
	return session, err
}

// Save adds a single session to the response.
func (s *MultiPartCookieStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Delete if max-age is <= 0
	if session.Options.MaxAge <= 0 {
		s.deleteMultiPartCookie(w, r, session.Name(), session.Options)
		return nil
	}

	// Encode the session
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return err
	}

	// Write the cookie(s)
	return s.writeMultiPartCookie(w, r, session.Name(), encoded, session.Options)
}

// readMultiPartCookie reads a potentially multi-part cookie value
func (s *MultiPartCookieStore) readMultiPartCookie(r *http.Request, name string) (string, error) {
	cookies := r.Cookies()
	var singleValue string
	var hasSingle bool
	parts := make(map[int]string)
	var totalParts int

	partPattern := regexp.MustCompile(fmt.Sprintf(`^%s_(\d+)of(\d+)$`, regexp.QuoteMeta(name)))

	for _, cookie := range cookies {
		if cookie.Name == name {
			singleValue = cookie.Value
			hasSingle = true
			continue
		}
		matches := partPattern.FindStringSubmatch(cookie.Name)
		if matches != nil {
			partNum, err := strconv.Atoi(matches[1])
			if err != nil {
				return "", fmt.Errorf("invalid part number in cookie %q: %w", cookie.Name, err)
			}
			total, err := strconv.Atoi(matches[2])
			if err != nil {
				return "", fmt.Errorf("invalid total in cookie %q: %w", cookie.Name, err)
			}
			if totalParts == 0 {
				totalParts = total
			} else if totalParts != total {
				return "", fmt.Errorf("inconsistent multipart cookie totals for %q: got %d and %d", name, totalParts, total)
			}
			if partNum < 1 || partNum > total {
				return "", fmt.Errorf("invalid cookie part number %d for total %d", partNum, total)
			}
			parts[partNum] = cookie.Value
		}
	}

	if totalParts > 0 {
		// Reassemble parts in order. Prefer multipart if present so stale
		// single cookies don't override a newer multipart session.
		var combined strings.Builder
		for i := 1; i <= totalParts; i++ {
			if part, ok := parts[i]; ok {
				combined.WriteString(part)
			} else {
				return "", fmt.Errorf("missing cookie part %d of %d", i, totalParts)
			}
		}
		return combined.String(), nil
	}

	if hasSingle {
		return singleValue, nil
	}

	return "", http.ErrNoCookie
}

// writeMultiPartCookie writes a cookie, splitting into multiple parts if necessary
func (s *MultiPartCookieStore) writeMultiPartCookie(w http.ResponseWriter, r *http.Request, name, value string, options *sessions.Options) error {
	// First, clear any existing multi-part cookies (only the parts, not the main cookie)
	s.clearMultiPartCookieParts(w, r, name, options)

	// Calculate if we need to split
	testCookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	}

	if len(testCookie.String()) <= maxCookieSize {
		// Single cookie is fine
		http.SetCookie(w, testCookie)
		return nil
	}

	// Need to split - calculate available space for value per cookie
	emptyCookie := &http.Cookie{
		Name:     name + "_99of99", // Use longest possible name format
		Value:    "",
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	}
	maxValueLen := maxCookieSize - len(emptyCookie.String())
	if maxValueLen <= 0 {
		return fmt.Errorf("cookie metadata too large, no room for value")
	}

	// Ensure any previously-written single cookie is removed, otherwise it can
	// coexist in some clients and shadow the multipart cookie on read.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   -1,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	})

	// Split the value
	parts := splitString(value, maxValueLen)

	// Write each part
	for i, part := range parts {
		partName := fmt.Sprintf("%s_%dof%d", name, i+1, len(parts))
		http.SetCookie(w, &http.Cookie{
			Name:     partName,
			Value:    part,
			Path:     options.Path,
			Domain:   options.Domain,
			MaxAge:   options.MaxAge,
			Secure:   options.Secure,
			HttpOnly: options.HttpOnly,
			SameSite: options.SameSite,
		})
	}

	return nil
}

// clearMultiPartCookieParts clears only the multi-part cookie parts (not the main cookie)
// This is used when writing a new value to avoid leaving stale parts
func (s *MultiPartCookieStore) clearMultiPartCookieParts(w http.ResponseWriter, r *http.Request, name string, options *sessions.Options) {
	cookies := r.Cookies()
	partPattern := regexp.MustCompile(fmt.Sprintf(`^%s_\d+of\d+$`, regexp.QuoteMeta(name)))

	for _, cookie := range cookies {
		if partPattern.MatchString(cookie.Name) {
			http.SetCookie(w, &http.Cookie{
				Name:     cookie.Name,
				Value:    "",
				Path:     options.Path,
				Domain:   options.Domain,
				MaxAge:   -1,
				Secure:   options.Secure,
				HttpOnly: options.HttpOnly,
				SameSite: options.SameSite,
			})
		}
	}
}

// deleteMultiPartCookie deletes a cookie and any multi-part variants
func (s *MultiPartCookieStore) deleteMultiPartCookie(w http.ResponseWriter, r *http.Request, name string, options *sessions.Options) {
	// Delete the main cookie
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   -1,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	})

	// Also delete any multi-part cookies
	s.clearMultiPartCookieParts(w, r, name, options)
}

// splitString splits a string into parts of at most maxLen bytes,
// respecting UTF-8 character boundaries
func splitString(s string, maxLen int) []string {
	if len(s) == 0 {
		return []string{""}
	}
	if maxLen <= 0 {
		return []string{s}
	}

	var parts []string
	for len(s) > 0 {
		if len(s) <= maxLen {
			parts = append(parts, s)
			break
		}

		// Find a safe split point that doesn't break UTF-8
		splitAt := maxLen
		for splitAt > 0 && !utf8.RuneStart(s[splitAt]) {
			splitAt--
		}
		if splitAt == 0 {
			// Shouldn't happen with valid UTF-8, but fallback
			splitAt = maxLen
		}

		parts = append(parts, s[:splitAt])
		s = s[splitAt:]
	}
	return parts
}
