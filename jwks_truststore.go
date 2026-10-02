// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-keypont/gose/jose"
)

// maxJwksBytes bounds how much of a JWKS response is read. Real key sets are a few
// kilobytes; the cap keeps a hostile or misconfigured endpoint from handing us an
// unbounded body to parse.
const maxJwksBytes = 1 << 20 // 1 MiB

const (
	// DefaultJwksRefreshInterval is how long a fetched key set is trusted before the
	// next lookup re-fetches it. Keys are only ever learned by fetching, so without a
	// bound a key removed upstream stayed trusted until some unrelated lookup missed —
	// which a quiet deployment might never do. Set 0 to trust a fetched set forever.
	DefaultJwksRefreshInterval = 5 * time.Minute
	// DefaultJwksMinRefreshInterval is the minimum time between fetches triggered by
	// lookups the cache cannot answer. Every unknown kid used to cost one HTTP round
	// trip, so a stream of tokens with made-up kids was a request amplifier against
	// both the JWKS endpoint and this process.
	DefaultJwksMinRefreshInterval = 30 * time.Second
)

// ErrJwksStale is returned when the cached key set is older than the refresh interval
// and could not be refreshed — because the last attempt failed and the store is in its
// minimum-refresh cool-down. The stale key is not returned: a key removed upstream must
// stop verifying once the interval has elapsed, whether or not the endpoint is up.
var ErrJwksStale = errors.New("jwks: cached key set is stale and could not be refreshed")

// Interface wrapper to allow mocking of http client.
type httpClient interface {
	Do(req *http.Request) (resp *http.Response, err error)
}

// JwksTrustStore is an implementation of the TrustStore interface and can be used for accessing VerificationKeys.
//
// Keys are fetched from a JWKS URL on demand and cached. A lookup that the cache
// answers never touches the network or waits for anyone who is; a lookup that needs a
// fetch shares it with concurrent lookups, is rate-limited by the minimum refresh
// interval, and the whole set is re-fetched once it is older than the refresh interval
// so that upstream removals take effect.
type JwksTrustStore struct {
	// mu guards the cached state below it. It is never held across the network.
	mu           sync.Mutex
	url          string
	inputIssuers string //csv of issuers
	issuers      []string
	keys         []VerificationKey
	fetchedAt    time.Time // last successful fetch; zero before the first
	lastAttempt  time.Time // last fetch attempt, successful or not; zero before the first

	// fetchMu serialises fetches so that concurrent lookups needing one make a single
	// request and the rest re-check the cache once it lands.
	fetchMu sync.Mutex

	client             httpClient
	now                func() time.Time
	refreshInterval    time.Duration
	minRefreshInterval time.Duration
}

// JwksOption configures a JwksTrustStore at construction.
type JwksOption func(*JwksTrustStore)

// WithJwksRefreshInterval sets how long a fetched key set is trusted before the next
// lookup re-fetches it. 0 disables the periodic re-fetch. See DefaultJwksRefreshInterval.
func WithJwksRefreshInterval(d time.Duration) JwksOption {
	return func(store *JwksTrustStore) { store.refreshInterval = d }
}

// WithJwksMinRefreshInterval sets the minimum time between fetches triggered by lookups
// the cache cannot answer. See DefaultJwksMinRefreshInterval.
func WithJwksMinRefreshInterval(d time.Duration) JwksOption {
	return func(store *JwksTrustStore) { store.minRefreshInterval = d }
}

// Add this method is not supported on a JwksTrustStore instance and will always return an error.
func (store *JwksTrustStore) Add(_ string, _ jose.Jwk) error {
	return errors.New("read-only trust store")
}

// Remove this method is not supported on a JwksTrustStore instance and will always return false.
func (store *JwksTrustStore) Remove(_, _ string) bool {
	return false
}

// Get returns a verification key for the given issuer and key id. If no key is found nil is returned.
func (store *JwksTrustStore) Get(ctx context.Context, issuer, kid string) (vk VerificationKey, err error) {
	if !store.knownIssuer(issuer) {
		return nil, nil
	}
	if key, done, err := store.lookup(kid); done {
		return key, err
	}
	// The cache cannot answer: fetch. Serialise fetches, and re-check under the fetch
	// lock, because another goroutine may have refreshed the set while we waited for it.
	store.fetchMu.Lock()
	defer store.fetchMu.Unlock()
	if key, done, err := store.lookup(kid); done {
		return key, err
	}
	if err = store.refresh(ctx); err != nil {
		return nil, err
	}
	// Freshly fetched: the cache now answers one way or the other.
	key, _, err := store.lookup(kid)
	return key, err
}

// knownIssuer reports whether issuer is one this store vouches for.
func (store *JwksTrustStore) knownIssuer(issuer string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	//lazy instantiation of the issuer list
	if len(store.issuers) == 0 {
		store.issuers = strings.Split(store.inputIssuers, ",")
	}
	for _, issuerInStore := range store.issuers {
		if issuerInStore == issuer {
			return true
		}
	}
	return false
}

// lookup answers from the cache whenever the cache is entitled to answer, and reports
// done=false when a fetch should be attempted instead:
//
//   - a hit on a set no older than refreshInterval is returned;
//   - a hit on an older set is stale: a fetch is due, unless one was attempted within
//     minRefreshInterval, in which case the stale key is withheld with ErrJwksStale;
//   - a miss triggers a fetch, unless one was attempted within minRefreshInterval, in
//     which case the answer is simply "unknown" — this is what stops a stream of
//     made-up kids turning into a stream of requests.
func (store *JwksTrustStore) lookup(kid string) (key VerificationKey, done bool, err error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now()
	for _, candidate := range store.keys {
		if candidate.Kid() == kid {
			key = candidate
			break
		}
	}
	fresh := !store.fetchedAt.IsZero() &&
		(store.refreshInterval == 0 || now.Sub(store.fetchedAt) <= store.refreshInterval)
	coolingDown := !store.lastAttempt.IsZero() && now.Sub(store.lastAttempt) < store.minRefreshInterval
	switch {
	case key != nil && fresh:
		return key, true, nil
	case key != nil && coolingDown:
		return nil, true, ErrJwksStale
	case key == nil && coolingDown:
		return nil, true, nil
	default:
		return nil, false, nil
	}
}

// refresh fetches the key set and replaces the cache with it. The store's mutex is not
// held across the request, so lookups the cache can answer are never blocked by a slow
// or unreachable endpoint. Caller holds fetchMu.
func (store *JwksTrustStore) refresh(ctx context.Context) (err error) {
	store.mu.Lock()
	store.lastAttempt = store.now()
	store.mu.Unlock()

	var response *http.Response
	var req *http.Request
	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, store.url, nil); err != nil {
		return fmt.Errorf("error creating request for JWKS from %s: %w", store.url, err)
	}
	response, err = store.client.Do(req)
	if err != nil {
		return fmt.Errorf("error encountered retrieving JWKS from %s: %w", store.url, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("error encountered retrieving JWKS from %s: %d %s", store.url, response.StatusCode, response.Status)
	}
	// Bound the response: the body is remote input and parsing it is not free.
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxJwksBytes))
	var jwks jose.Jwks
	if err = decoder.Decode(&jwks); err != nil {
		return fmt.Errorf("error encountered retrieving JWKS from %s: invalid encoding", store.url)
	}
	keys := make([]VerificationKey, 0, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		key, keyErr := NewVerificationKey(jwk)
		if keyErr != nil {
			return fmt.Errorf("failed to load verification key from JWK: %w", keyErr)
		}
		keys = append(keys, key)
	}

	// Replace, never merge: a key absent from the new set is one the issuer withdrew.
	store.mu.Lock()
	store.keys = keys
	store.fetchedAt = store.now()
	store.mu.Unlock()
	return nil
}

// NewJwksKeyStore creates a new instance of a TrustStore and can be used to load verification keys.
func NewJwksKeyStore(issuerList, url string, opts ...JwksOption) *JwksTrustStore {
	store := &JwksTrustStore{
		url:          url,
		inputIssuers: issuerList,
		client: &http.Client{
			Timeout: time.Second * 30,
		},
		now:                time.Now,
		refreshInterval:    DefaultJwksRefreshInterval,
		minRefreshInterval: DefaultJwksMinRefreshInterval,
	}
	for _, opt := range opts {
		opt(store)
	}
	return store
}
