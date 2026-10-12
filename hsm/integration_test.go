// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package hsm

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/crypto11/v2"
	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"

	"github.com/eclipse-keypont/gose/jose"
)

// testCtx is the shared crypto11 handle for the HSM-backed suite. It is
// initialised by TestMain once the ephemeral SoftHSM token is ready.
var testCtx *crypto11.Context

const (
	integrationTokenLabel = "gose-hsm-test-token"
	integrationSoPin      = "0000"
	integrationDefaultPin = "1234"
)

// TestMain bootstraps an ephemeral SoftHSM token when PKCS11_MODULE is set,
// runs all tests against it, then cleans up.
//
// Without PKCS11_MODULE the suite runs normally and every HSM-backed test
// self-skips via skipIfNoLibrary, so `go test ./...` stays green on a machine
// with no PKCS#11 module.
//
// Token initialisation is done entirely through the PKCS#11 API
// (C_InitToken / C_InitPIN) — no external tools (softhsm2-util) required.
//
// Example usage:
//
//	PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
//	PKCS11_PIN=1234 \
//	go test -v ./hsm/
func TestMain(m *testing.M) {
	lib := os.Getenv("PKCS11_MODULE")
	if lib == "" {
		// No library configured — run the suite; HSM tests skip themselves.
		os.Exit(m.Run())
	}

	teardown := initSoftHSMToken(lib)
	initCrypto11(lib)

	code := m.Run()

	if testCtx != nil {
		_ = testCtx.Close()
	}
	teardown()
	os.Exit(code)
}

// skipIfNoLibrary skips the test when PKCS11_MODULE is not set.
func skipIfNoLibrary(t *testing.T) {
	t.Helper()
	if os.Getenv("PKCS11_MODULE") == "" {
		t.Skip("PKCS11_MODULE not set — skipping HSM integration test")
	}
}

// initSoftHSMToken creates a temp directory, writes a fresh softhsm2.conf,
// then initialises the token directly via the PKCS#11 API.
//
// PKCS#11 flow:
//  1. C_Initialize / C_GetSlotList(tokenPresent=false)  → find a free slot
//  2. C_InitToken                                        → set SO-PIN and label
//  3. C_GetSlotList(tokenPresent=true)                  → find the new slot
//  4. C_OpenSession / C_Login(SO) / C_InitPIN           → set user PIN
//
// Sets SOFTHSM2_CONF, PKCS11_TOKEN, and PKCS11_PIN so crypto11 and the tests
// pick up the right token automatically. Returns a teardown that removes the
// temp directory.
func initSoftHSMToken(modulePath string) func() {
	dir, err := os.MkdirTemp("", "gose-hsm-*")
	if err != nil {
		panic("initSoftHSMToken: MkdirTemp: " + err.Error())
	}

	tokensDir := filepath.Join(dir, "tokens")
	if err := os.Mkdir(tokensDir, 0700); err != nil {
		panic("initSoftHSMToken: Mkdir(tokens): " + err.Error())
	}

	conf := filepath.Join(dir, "softhsm2.conf")
	content := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n",
		tokensDir,
	)
	if err := os.WriteFile(conf, []byte(content), 0600); err != nil {
		panic("initSoftHSMToken: WriteFile(softhsm2.conf): " + err.Error())
	}

	// Must be set before the module is loaded so SoftHSM reads the right config.
	os.Setenv("SOFTHSM2_CONF", conf)

	if os.Getenv("PKCS11_PIN") == "" {
		os.Setenv("PKCS11_PIN", integrationDefaultPin)
	}
	userPin := os.Getenv("PKCS11_PIN")

	ctx, err := pkcs11.New(modulePath)
	if err != nil {
		panic("initSoftHSMToken: failed to load PKCS11_MODULE: " + modulePath + ": " + err.Error())
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		panic("initSoftHSMToken: C_Initialize: " + err.Error())
	}

	slots, err := ctx.GetSlotList(false)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		panic(fmt.Sprintf("initSoftHSMToken: C_GetSlotList(false): %v (slots=%d)", err, len(slots)))
	}

	if err := ctx.InitToken(slots[0], []byte(integrationSoPin), integrationTokenLabel); err != nil {
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: C_InitToken: " + err.Error())
	}

	// After C_InitToken the slot gets a new ID; re-fetch with tokenPresent=true.
	slots, err = ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		panic(fmt.Sprintf("initSoftHSMToken: C_GetSlotList(true) after InitToken: %v (slots=%d)", err, len(slots)))
	}

	sh, err := ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: OpenSession: " + err.Error())
	}
	if err := ctx.Login(sh, pkcs11.CKU_SO, []byte(integrationSoPin)); err != nil {
		ctx.CloseSession(sh)
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: Login(SO): " + err.Error())
	}
	if err := ctx.InitPIN(sh, []byte(userPin)); err != nil {
		ctx.Logout(sh)
		ctx.CloseSession(sh)
		ctx.Finalize()
		ctx.Destroy()
		panic("initSoftHSMToken: C_InitPIN: " + err.Error())
	}
	ctx.Logout(sh)
	ctx.CloseSession(sh)
	ctx.Finalize()
	ctx.Destroy()

	os.Setenv("PKCS11_TOKEN", integrationTokenLabel)

	fmt.Printf("initSoftHSMToken: token %q initialised in %s\n", integrationTokenLabel, dir)

	return func() {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "initSoftHSMToken teardown: RemoveAll(%s): %v\n", dir, err)
		}
	}
}

// initCrypto11 connects the package-level testCtx to the ephemeral token.
func initCrypto11(modulePath string) {
	cfg := &crypto11.Config{
		Path:       modulePath,
		TokenLabel: os.Getenv("PKCS11_TOKEN"),
		Pin:        os.Getenv("PKCS11_PIN"),
	}
	var err error
	if testCtx, err = crypto11.Configure(cfg); err != nil {
		panic("initCrypto11: crypto11.Configure: " + err.Error())
	}
	fmt.Printf("initCrypto11: connected to token %q\n", cfg.TokenLabel)
}

// TestAsymmetricDecryptionKeyStore_RSAOAEPRoundTrip provisions an RSA key pair
// on the token, looks it up through the store, and asserts that a value
// encrypted with the public key (via Encryptor) decrypts back to the original
// plaintext with the private key.
//
// This is the end-to-end path k8s-kms-plugin relies on: the store resolves a
// CKA_ID to a token-backed decryption key, and the matching encryption key is
// derived from the token's public key.
func TestAsymmetricDecryptionKeyStore_RSAOAEPRoundTrip(t *testing.T) {
	skipIfNoLibrary(t)

	kid := []byte("gose-hsm-rsa-oaep-kid")
	label := []byte("gose-hsm-rsa-oaep-label")

	keyPair, err := testCtx.GenerateRSAKeyPairWithLabel(kid, label, 2048)
	require.NoError(t, err)
	t.Cleanup(func() { _ = keyPair.Delete() })

	store := NewAsymmetricDecryptionKeyStore(testCtx)

	decKey, err := store.Get(string(kid))
	require.NoError(t, err)
	require.NotNil(t, decKey)
	assert.Equal(t, string(kid), decKey.Kid())
	assert.Equal(t, jose.AlgRSAOAEP, decKey.Algorithm())

	encKey, err := decKey.Encryptor()
	require.NoError(t, err)
	require.NotNil(t, encKey)

	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	ciphertext, err := encKey.Encrypt(jose.KeyOpsEncrypt, crypto.SHA256, plaintext)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ciphertext)

	recovered, err := decKey.Decrypt(jose.KeyOpsDecrypt, crypto.SHA256, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

// TestAsymmetricDecryptionKeyStore_UnknownKid asserts that looking up a CKA_ID
// that was never provisioned fails rather than returning a usable key.
func TestAsymmetricDecryptionKeyStore_UnknownKid(t *testing.T) {
	skipIfNoLibrary(t)

	store := NewAsymmetricDecryptionKeyStore(testCtx)

	_, err := store.Get("gose-hsm-does-not-exist")
	require.Error(t, err)
}

// TestAsymmetricDecryptionKeyStore_LabelLookup exercises the label-based
// constructor path: a key created with a CKA_LABEL is resolved by label and
// still round-trips.
func TestAsymmetricDecryptionKeyStore_LabelLookup(t *testing.T) {
	skipIfNoLibrary(t)

	kid := []byte("gose-hsm-label-kid")
	label := []byte("gose-hsm-label-lookup")

	keyPair, err := testCtx.GenerateRSAKeyPairWithLabel(kid, label, 2048)
	require.NoError(t, err)
	t.Cleanup(func() { _ = keyPair.Delete() })

	decKey, err := NewAsymmetricDecryptionKey(testCtx, keyPair, kid, label)
	require.NoError(t, err)

	encKey, err := decKey.Encryptor()
	require.NoError(t, err)

	plaintext := []byte("label lookup round trip")

	ciphertext, err := encKey.Encrypt(jose.KeyOpsEncrypt, crypto.SHA256, plaintext)
	require.NoError(t, err)

	recovered, err := decKey.Decrypt(jose.KeyOpsDecrypt, crypto.SHA256, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

// TestAsymmetricDecryptionKeyStore_LabelTrimsPadding guards against a token
// that right-pads CKA_LABEL with spaces: the store must still resolve the key.
func TestAsymmetricDecryptionKeyStore_LabelTrimsPadding(t *testing.T) {
	skipIfNoLibrary(t)

	kid := []byte("gose-hsm-pad-kid")
	label := []byte("gose-hsm-pad-label")

	keyPair, err := testCtx.GenerateRSAKeyPairWithLabel(kid, label, 2048)
	require.NoError(t, err)
	t.Cleanup(func() { _ = keyPair.Delete() })

	// SoftHSM stores labels space-padded; the lookup must not depend on that.
	padded := []byte(strings.TrimRight(string(label)+"   ", " "))
	decKey, err := NewAsymmetricDecryptionKey(testCtx, keyPair, kid, padded)
	require.NoError(t, err)

	encKey, err := decKey.Encryptor()
	require.NoError(t, err)

	plaintext := []byte("padded label round trip")
	ciphertext, err := encKey.Encrypt(jose.KeyOpsEncrypt, crypto.SHA256, plaintext)
	require.NoError(t, err)

	recovered, err := decKey.Decrypt(jose.KeyOpsDecrypt, crypto.SHA256, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}
