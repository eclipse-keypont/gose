// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/gose/jose"
)

const (
	// Extracted from https://www.googleapis.com/oauth2/v3/certs
	jwks = `
{
  "keys": [
    {
      "kid": "60f4060e58d75fd3f70beff88c794a775327aa31",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256",
      "n": "vFfCjiB67cRoJE-zyhZJyjDAUbdAd18Jt69ZkD4JTT8SJ6WviOR6Z5PV_mfF_LwxXy7UalFUZ4zCtWEyoHudcZV9s835-QPNPA2gZ55ChKNSlV3PJXnATf_87Ll50ewuIoe3eKzUFWBrPPB9-Q6SiRGN3STb2PTOXKgTnaUPi0fPwD5ZzhZOXTY67M0l-cX53WMliLguHpDUqbmlK_w4fBNXVWwlPtEhZag-FIavt3kH4hcNEj1hC-cju0_RHE7Dx6t3HFF3aGnsnqRPauAXIrVctLTQJVWDrpObRLOnpqDcoD4Y-cN2PaqLTK0vTnBTIAiP4sazDNCEOl-Zy1ul_w",
      "use": "sig"
    },
    {
      "kid": "df8d9ee403bcc7185ad51041194bd3433742d9aa",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256",
      "n": "nQgOafNApTMwKerFuGXDj8HZ7hUSFPUV4_SzYj79SF5giP0IfF6Ksnb5Jy0pQ_MXQ6XNuh6eZqCfAPXUwHtoxE29jpe6L6DGKPLTr8RTbNhdIsorc1yXiPcail58gftq1fmegZw0KO6QtBpKYnBWoZw4PJkuP8ZdGanA0btsZRRRYVmSOKuYDNHfVJlcrD4cqAOL3BPjWQIrZszwTVmw0FjiU9KfGtU0rDYnas-mZv1qfetZkTA3YPTqSspCNZDbGCVXpJnr4pai0E7lxFgDNDN2IDk955Pf8eG8oNCfqkHXfnWDrTlXP7SSrYmEaBPcmMKOHdjyrYPk0lWI8-urXw",
      "use": "sig"
    }
  ]
}`
)

type httpClientMock struct {
	mock.Mock
}

func (client *httpClientMock) Do(req *http.Request) (resp *http.Response, err error) {
	args := client.Called(req.URL.String())
	return args.Get(0).(*http.Response), args.Error(1)
}

// fakeClock lets a test move the store's notion of time without sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// jwksResponse builds a 200 response carrying body.
func jwksResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
}

// jwksOneKey is the jwks fixture with its second key withdrawn.
const jwksOneKey = `
{
  "keys": [
    {
      "kid": "60f4060e58d75fd3f70beff88c794a775327aa31",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256",
      "n": "vFfCjiB67cRoJE-zyhZJyjDAUbdAd18Jt69ZkD4JTT8SJ6WviOR6Z5PV_mfF_LwxXy7UalFUZ4zCtWEyoHudcZV9s835-QPNPA2gZ55ChKNSlV3PJXnATf_87Ll50ewuIoe3eKzUFWBrPPB9-Q6SiRGN3STb2PTOXKgTnaUPi0fPwD5ZzhZOXTY67M0l-cX53WMliLguHpDUqbmlK_w4fBNXVWwlPtEhZag-FIavt3kH4hcNEj1hC-cju0_RHE7Dx6t3HFF3aGnsnqRPauAXIrVctLTQJVWDrpObRLOnpqDcoD4Y-cN2PaqLTK0vTnBTIAiP4sazDNCEOl-Zy1ul_w",
      "use": "sig"
    }
  ]
}`

func TestJwksTrustStore_Add(t *testing.T) {
	store := NewJwksKeyStore("", "")
	err := store.Add("", &jose.PublicRsaKey{})
	assert.Error(t, err, "read-only trust store")
}

func TestJwksTrustStore_Remove(t *testing.T) {
	store := NewJwksKeyStore("", "")
	removed := store.Remove("", "")
	assert.False(t, removed)
}

func TestJwksTrustStore_GetWithSingleIssuer(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Do", "https://www.googleapis.com/oauth2/v3/certs").Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(jwks))),
		}, nil).Once()
	store := NewJwksKeyStore("https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs")
	store.client = mockedClient
	key, _ := store.Get(context.Background(), "https://accounts.google.com", "60f4060e58d75fd3f70beff88c794a775327aa31")
	assert.NotNil(t, key)
	require.Len(t, store.keys, 2)
	got, _ := store.Get(context.Background(), "https://accounts.google.com", "df8d9ee403bcc7185ad51041194bd3433742d9aa")
	assert.NotNil(t, got)
	mockedClient.AssertExpectations(t)
}

func TestJwksTrustStore_GetWithMultipleIssuer(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Do", "https://www.googleapis.com/oauth2/v3/certs").Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(jwks))),
		}, nil).Once()
	store := NewJwksKeyStore("https://accounts.google.com,https://accounts.thalesgroup.com", "https://www.googleapis.com/oauth2/v3/certs")
	store.client = mockedClient
	key, _ := store.Get(context.Background(), "https://accounts.google.com", "60f4060e58d75fd3f70beff88c794a775327aa31")
	assert.NotNil(t, key)
	require.Len(t, store.keys, 2)
	got, _ := store.Get(context.Background(), "https://accounts.thalesgroup.com", "df8d9ee403bcc7185ad51041194bd3433742d9aa")
	assert.NotNil(t, got)
	mockedClient.AssertExpectations(t)
}

func TestJwksTrustStore_GetHttpClientError(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Do", "https://www.googleapis.com/oauth2/v3/certs").Return(
		(*http.Response)(nil), errors.New("expected")).Times(2)
	store := NewJwksKeyStore("https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs")
	store.client = mockedClient
	clock := newFakeClock()
	store.now = clock.Now
	for i := 0; i < 2; i++ {
		// A second miss only re-fetches once the minimum refresh interval has passed.
		clock.Advance(DefaultJwksMinRefreshInterval)
		key, _ := store.Get(context.Background(), "https://accounts.google.com", "invalid")
		assert.Nil(t, key)
		require.Len(t, store.keys, 0)
	}
	mockedClient.AssertExpectations(t)
}

func TestJwksTrustStore_GetHttpError(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Do", "https://www.googleapis.com/oauth2/v3/certs").Return(
		&http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(bytes.NewReader([]byte(jwks))),
		}, nil).Times(2)
	store := NewJwksKeyStore("https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs")
	store.client = mockedClient
	clock := newFakeClock()
	store.now = clock.Now
	for i := 0; i < 2; i++ {
		// A second miss only re-fetches once the minimum refresh interval has passed.
		clock.Advance(DefaultJwksMinRefreshInterval)
		key, _ := store.Get(context.Background(), "https://accounts.google.com", "invalid")
		assert.Nil(t, key)
		require.Len(t, store.keys, 0)
	}
	mockedClient.AssertExpectations(t)
}

func TestJwksTrustStore_GetInvalidJwksEncoding(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Do", "https://www.googleapis.com/oauth2/v3/certs").Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte("invalid"))),
		}, nil).Times(2)
	store := NewJwksKeyStore("https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs")
	store.client = mockedClient
	clock := newFakeClock()
	store.now = clock.Now
	for i := 0; i < 2; i++ {
		// A second miss only re-fetches once the minimum refresh interval has passed.
		clock.Advance(DefaultJwksMinRefreshInterval)
		key, _ := store.Get(context.Background(), "https://accounts.google.com", "invalid")
		assert.Nil(t, key)
		require.Len(t, store.keys, 0)
	}
	mockedClient.AssertExpectations(t)
}

const (
	testJwksURL    = "https://www.googleapis.com/oauth2/v3/certs"
	testJwksIssuer = "https://accounts.google.com"
	testKidA       = "60f4060e58d75fd3f70beff88c794a775327aa31"
	testKidB       = "df8d9ee403bcc7185ad51041194bd3433742d9aa"
)

// TestJwksTrustStore_UnknownKidDoesNotFetchWithinCoolDown pins the request-amplification
// fix: every lookup of an unknown kid used to cost one HTTP round trip, so a stream of
// tokens with made-up kids became a stream of requests. Within the minimum refresh
// interval a miss is answered from the cache as "unknown"; once it has elapsed, one
// fetch is allowed again.
func TestJwksTrustStore_UnknownKidDoesNotFetchWithinCoolDown(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Do", testJwksURL).Return(jwksResponse(jwks), nil).Once()
	store := NewJwksKeyStore(testJwksIssuer, testJwksURL)
	store.client = mockedClient
	clock := newFakeClock()
	store.now = clock.Now

	for i := 0; i < 50; i++ {
		clock.Advance(100 * time.Millisecond)
		key, err := store.Get(context.Background(), testJwksIssuer, "made-up-kid")
		require.NoError(t, err)
		require.Nil(t, key)
	}
	mockedClient.AssertExpectations(t) // exactly one Do for fifty misses

	// Known keys are still served from the fetched set throughout.
	key, err := store.Get(context.Background(), testJwksIssuer, testKidA)
	require.NoError(t, err)
	require.NotNil(t, key)

	// After the cool-down a miss may fetch again.
	mockedClient.On("Do", testJwksURL).Return(jwksResponse(jwks), nil).Once()
	clock.Advance(DefaultJwksMinRefreshInterval)
	_, err = store.Get(context.Background(), testJwksIssuer, "another-made-up-kid")
	require.NoError(t, err)
	mockedClient.AssertExpectations(t)
}

// TestJwksTrustStore_RefreshIntervalPicksUpRemovedKeys pins revocation: a key the
// issuer withdrew from the JWKS used to stay trusted until some unrelated lookup
// missed. Once the set is older than the refresh interval, the next lookup — even a
// hit — re-fetches, and the withdrawn key stops verifying.
func TestJwksTrustStore_RefreshIntervalPicksUpRemovedKeys(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Do", testJwksURL).Return(jwksResponse(jwks), nil).Once()
	mockedClient.On("Do", testJwksURL).Return(jwksResponse(jwksOneKey), nil).Once()
	store := NewJwksKeyStore(testJwksIssuer, testJwksURL)
	store.client = mockedClient
	clock := newFakeClock()
	store.now = clock.Now

	key, err := store.Get(context.Background(), testJwksIssuer, testKidB)
	require.NoError(t, err)
	require.NotNil(t, key, "kid B is in the first key set")

	// Within the interval a hit is served from the cache: no fetch.
	clock.Advance(DefaultJwksRefreshInterval)
	key, err = store.Get(context.Background(), testJwksIssuer, testKidB)
	require.NoError(t, err)
	require.NotNil(t, key)

	// Past it, the hit triggers a re-fetch; the new set no longer carries kid B.
	clock.Advance(time.Second)
	key, err = store.Get(context.Background(), testJwksIssuer, testKidB)
	require.NoError(t, err)
	require.Nil(t, key, "kid B was withdrawn upstream and must no longer verify")
	key, err = store.Get(context.Background(), testJwksIssuer, testKidA)
	require.NoError(t, err)
	require.NotNil(t, key)
	mockedClient.AssertExpectations(t)
}

// TestJwksTrustStore_StaleSetFailsClosed: when the set is past the refresh interval and
// the refresh fails, the stale key is not handed out — a withdrawn key must not keep
// verifying just because the endpoint is down — and within the cool-down the caller
// gets ErrJwksStale rather than another round trip.
func TestJwksTrustStore_StaleSetFailsClosed(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Do", testJwksURL).Return(jwksResponse(jwks), nil).Once()
	mockedClient.On("Do", testJwksURL).Return((*http.Response)(nil), errors.New("endpoint down")).Once()
	store := NewJwksKeyStore(testJwksIssuer, testJwksURL)
	store.client = mockedClient
	clock := newFakeClock()
	store.now = clock.Now

	key, err := store.Get(context.Background(), testJwksIssuer, testKidA)
	require.NoError(t, err)
	require.NotNil(t, key)

	clock.Advance(DefaultJwksRefreshInterval + time.Second)
	key, err = store.Get(context.Background(), testJwksIssuer, testKidA)
	require.ErrorContains(t, err, "endpoint down")
	require.Nil(t, key)

	// Still stale, still cooling down: no fetch, no key.
	key, err = store.Get(context.Background(), testJwksIssuer, testKidA)
	require.ErrorIs(t, err, ErrJwksStale)
	require.Nil(t, key)
	mockedClient.AssertExpectations(t)
}

// blockingClient is an httpClient whose Do blocks until released, and reports when it
// has been entered.
type blockingClient struct {
	entered chan struct{}
	release chan struct{}
	body    string
}

func (c *blockingClient) Do(*http.Request) (*http.Response, error) {
	close(c.entered)
	<-c.release
	return jwksResponse(c.body), nil
}

// TestJwksTrustStore_CacheHitsAreNotBlockedByAFetch pins the lock-scope fix: the mutex
// used to be held across the HTTP round trip, so one slow fetch stalled every
// verification in the process. A lookup the cache can answer must return while a fetch
// for an unknown kid is still in flight.
func TestJwksTrustStore_CacheHitsAreNotBlockedByAFetch(t *testing.T) {
	// Warm the cache through a normal client first.
	warm := &httpClientMock{}
	warm.On("Do", testJwksURL).Return(jwksResponse(jwks), nil).Once()
	store := NewJwksKeyStore(testJwksIssuer, testJwksURL)
	store.client = warm
	clock := newFakeClock()
	store.now = clock.Now
	key, err := store.Get(context.Background(), testJwksIssuer, testKidA)
	require.NoError(t, err)
	require.NotNil(t, key)

	// Now make the next fetch hang, and trigger it with an unknown kid.
	slow := &blockingClient{entered: make(chan struct{}), release: make(chan struct{}), body: jwks}
	store.client = slow
	clock.Advance(DefaultJwksMinRefreshInterval)
	fetchDone := make(chan struct{})
	go func() {
		defer close(fetchDone)
		_, _ = store.Get(context.Background(), testJwksIssuer, "unknown-kid")
	}()
	select {
	case <-slow.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch was never started")
	}

	// While the fetch is blocked in Do, a cache hit must still be served.
	hit := make(chan VerificationKey, 1)
	go func() {
		k, _ := store.Get(context.Background(), testJwksIssuer, testKidA)
		hit <- k
	}()
	select {
	case k := <-hit:
		require.NotNil(t, k)
	case <-time.After(2 * time.Second):
		close(slow.release)
		t.Fatal("cache hit was blocked behind an in-flight fetch")
	}

	close(slow.release)
	<-fetchDone
}
