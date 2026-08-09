package main

// Server-side sessions, by hand.
//
// This is the baseline every later mechanism reacts against. The server
// remembers who you are; the browser only carries a meaningless id. That one
// decision is what buys instant revocation and costs server state.

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// cookieName is deliberately opaque. It must not leak what framework or
// language is behind it, and it must not carry meaning of its own.
const cookieName = "sid"

// session is what the server remembers. Note what is NOT here: nothing is sent
// to the browser except the id. Compare with a JWT, where all of this travels
// in the client's hands.
type session struct {
	ID              string
	Username        string // empty means anonymous (not logged in)
	CreatedAt       time.Time
	LastSeen        time.Time
	AuthenticatedAt time.Time
}

func (s *session) authenticated() bool { return s.Username != "" }

// store is the server-side memory. A real deployment puts this in Redis or a
// database so several app instances share it; the shape is the same.
//
// This being server-side is the whole point of the mechanism: deleting an entry
// here revokes the session instantly, everywhere, with no waiting for expiry.
type store struct {
	mu          sync.Mutex
	m           map[string]*session
	idleTimeout time.Duration
}

func newStore(idle time.Duration) *store {
	return &store{m: map[string]*session{}, idleTimeout: idle}
}

// create makes a new session with a fresh, unguessable id.
//
// The id is 32 bytes from crypto/rand. It carries no information and is not
// derived from anything about the user: it is a pure lookup key. Anything less
// than cryptographic randomness here means an attacker can guess a live
// session, which is the entire security of this mechanism.
func (st *store) create(username string) *session {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	s := &session{
		ID:        base64.RawURLEncoding.EncodeToString(randomBytes(32)),
		Username:  username,
		CreatedAt: now,
		LastSeen:  now,
	}
	if username != "" {
		s.AuthenticatedAt = now
	}
	st.m[s.ID] = s
	return s
}

// get returns the session for an id, dropping it if it has gone idle.
func (st *store) get(id string) (*session, bool) {
	if id == "" {
		return nil, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.m[id]
	if !ok {
		return nil, false
	}
	if time.Since(s.LastSeen) > st.idleTimeout {
		delete(st.m, id) // expiry is enforced on read, not by a sweeper
		return nil, false
	}
	s.LastSeen = time.Now()
	return s, true
}

// destroy removes a session. This is what "logout" actually is, and what a
// signed token cannot do.
func (st *store) destroy(id string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.m, id)
}

func (st *store) count() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.m)
}

// ------------------------------------------------------------------ cookies

// cookieOpts controls the attributes we set, so the chapter can turn them off
// one at a time and show what each one was actually preventing.
type cookieOpts struct {
	httpOnly bool
	secure   bool
	sameSite http.SameSite
}

func defaultCookieOpts() cookieOpts {
	return cookieOpts{
		// httpOnly: JavaScript cannot read the cookie. This is what stands
		// between an XSS bug and session theft.
		httpOnly: true,
		// secure: never sent over plain HTTP. Off here only because this lab
		// runs on http://localhost; in production this is not optional.
		secure: false,
		// sameSite Lax: the browser will not attach this cookie to most
		// cross-site requests, which removes the majority of CSRF. It does not
		// remove all of it - top-level GET navigations still carry the cookie.
		sameSite: http.SameSiteLaxMode,
	}
}

func (o cookieOpts) set(w http.ResponseWriter, id string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: o.httpOnly,
		Secure:   o.secure,
		SameSite: o.sameSite,
		MaxAge:   int(maxAge.Seconds()),
	})
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1, // tells the browser to delete it
	})
}

func cookieID(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means we must not continue
	}
	return b
}
