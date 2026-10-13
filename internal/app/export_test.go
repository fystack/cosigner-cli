package app

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	tsscrypto "github.com/bnb-chain/tss-lib/v3/crypto"
	eddsakeygen "github.com/bnb-chain/tss-lib/v3/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// sealTestRecord mirrors the runtime's LocalEncryptor.Encrypt.
func sealTestRecord(t *testing.T, kek []byte, scope, key string, plaintext []byte) []byte {
	t.Helper()
	scopeKey := make([]byte, 32)
	_, err := io.ReadFull(hkdf.New(sha256.New, kek, nil, []byte(scope)), scopeKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(scopeKey)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	out := append([]byte{1}, nonce...)
	return append(out, aead.Seal(nil, nonce, plaintext, append([]byte(scope+"\x00"), key...))...)
}

func seedExportHome(t *testing.T, a *App, password string, shares map[string][]byte) layout {
	t.Helper()
	l, _ := fixture(t, a)
	require.NoError(t, os.WriteFile(l.pairing(), []byte("cosigner_id: dev-1\nworkspace_id: ws-1\nparticipant_id: cos-236b2b44\n"), 0o600))
	envelope, err := encryptKEK([]byte(password), []byte(strings.Repeat("ab", 32)+"\n"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(l.encryptedKEK(), envelope, 0o600))

	dbPath := filepath.Join(l.state, "data", "cosigner.db")
	require.NoError(t, os.Remove(dbPath))
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.Exec("CREATE TABLE kv (key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT")
	require.NoError(t, err)
	kek := bytes.Repeat([]byte{0xab}, 32)
	put := func(scope, key string, value []byte) {
		_, err := db.Exec("INSERT INTO kv(key, value) VALUES(?, ?)", key, sealTestRecord(t, kek, scope, key, value))
		require.NoError(t, err)
	}
	for key, value := range shares {
		put(sharesScope, key, value)
	}
	put("cosigner:preparams", "preparams:ECDSA:active_slot", []byte("a"))
	return l
}

func exportTestApp(password string) (*App, *bytes.Buffer) {
	a := newTestApp(&fakeRunner{})
	out := &bytes.Buffer{}
	a.Out = out
	a.Random = rand.Reader
	a.Getenv = func(k string) string {
		if k == passwordEnv {
			return password
		}
		return ""
	}
	return a, out
}

func eddsaShareBlob(t *testing.T) []byte {
	t.Helper()
	pub := tsscrypto.ScalarBaseMult(tss.Edwards(), big.NewInt(12345))
	blob, err := json.Marshal(eddsakeygen.LocalPartySaveData{EDDSAPub: pub})
	require.NoError(t, err)
	return blob
}

// openTestMShare mirrors cosigner-recovery's openMShare.
func openTestMShare(t *testing.T, raw []byte, passphrase string) (mshareEnvelope, []mshareShare) {
	t.Helper()
	var env mshareEnvelope
	require.NoError(t, json.Unmarshal(raw, &env))
	salt, _ := base64.StdEncoding.DecodeString(env.Salt)
	nonce, _ := base64.StdEncoding.DecodeString(env.Nonce)
	ciphertext, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
	aad, err := json.Marshal(mshareHeader{Format: env.Format, KDF: env.KDF, Salt: env.Salt, Nonce: env.Nonce, Context: env.Context})
	require.NoError(t, err)
	key := argon2.IDKey([]byte(passphrase), salt, env.KDF.Time, env.KDF.MemoryKiB, env.KDF.Threads, 32)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	require.NoError(t, err)
	var payload struct {
		Shares []mshareShare `json:"shares"`
	}
	require.NoError(t, json.Unmarshal(plain, &payload))
	return env, payload.Shares
}

func TestExportWritesRecoverableMShare(t *testing.T) {
	blob := eddsaShareBlob(t)
	a, out := exportTestApp("test password")
	l := seedExportHome(t, a, "test password", map[string][]byte{
		"shares:EdDSA:wallet-1": blob,
		"shares:EdDSA:wallet-2": blob,
	})
	outDir := filepath.Join(t.TempDir(), "exports")
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "export", "--wallet", "wallet-1", "--out-dir", outDir})
	require.NoError(t, cmd.Execute())

	passphrase := regexp.MustCompile(`(?m)^    ([a-z]+(?:-[a-z]+){5})$`).FindStringSubmatch(out.String())
	require.Len(t, passphrase, 2, out.String())
	name := mshareFilename("wallet-1", "cos-236b2b44", time.Now().UTC())
	assert.True(t, strings.HasPrefix(name, "wallet-1-cos-23-"))
	raw, err := os.ReadFile(filepath.Join(outDir, name))
	require.NoError(t, err)
	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	env, shares := openTestMShare(t, raw, passphrase[1])
	assert.Equal(t, mshareFormat, env.Format)
	require.Len(t, shares, 1)
	assert.Equal(t, mshareContext{WorkspaceID: "ws-1", WalletID: "wallet-1", ParticipantID: "cos-236b2b44", DeviceID: "dev-1",
		Shares: []mshareContextEntry{{Protocol: "EdDSA", JointPublicKeyBase64: shares[0].JointPublicKeyBase64}}}, env.Context)
	assert.Equal(t, "wallet-1", shares[0].WalletID)
	assert.Equal(t, base64.StdEncoding.EncodeToString(blob), shares[0].ShareBlobBase64)
}

func TestExportListAndWrongPassword(t *testing.T) {
	a, out := exportTestApp("test password")
	l := seedExportHome(t, a, "test password", map[string][]byte{"shares:EdDSA:wallet-1": eddsaShareBlob(t)})
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "export", "--list"})
	require.NoError(t, cmd.Execute())
	assert.Equal(t, "wallet-1\tEdDSA\n", out.String())

	a, _ = exportTestApp("test password")
	l = seedExportHome(t, a, "other password", map[string][]byte{"shares:EdDSA:wallet-1": eddsaShareBlob(t)})
	cmd = a.Command()
	cmd.SetArgs([]string{"--home", l.home, "export", "--list"})
	assert.ErrorContains(t, cmd.Execute(), "check the password")
}

func TestExportRejectsUnknownWallet(t *testing.T) {
	a, _ := exportTestApp("test password")
	l := seedExportHome(t, a, "test password", map[string][]byte{"shares:EdDSA:wallet-1": eddsaShareBlob(t)})
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "export", "--wallet", "missing"})
	assert.ErrorContains(t, cmd.Execute(), "no shares found for wallet missing")
}

func TestExportRejectsUnattendedProfile(t *testing.T) {
	a, _ := exportTestApp("test password")
	l := seedExportHome(t, a, "test password", map[string][]byte{"shares:EdDSA:wallet-1": eddsaShareBlob(t)})
	s, err := loadSettings(l.home)
	require.NoError(t, err)
	s.Profile = "unattended"
	require.NoError(t, saveSettings(l.home, s))
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "export", "--list"})
	assert.ErrorContains(t, cmd.Execute(), "unattended")
}

func TestExportRefusesRunningContainer(t *testing.T) {
	a, _ := exportTestApp("test password")
	l := seedExportHome(t, a, "test password", map[string][]byte{"shares:EdDSA:wallet-1": eddsaShareBlob(t)})
	s, err := loadSettings(l.home)
	require.NoError(t, err)
	a.Runner = &fakeRunner{run: func(c runCall) ([]byte, error) {
		if c.args[0] == "ps" {
			return []byte("id"), nil
		}
		return containerJSON(t, l, s, true), nil
	}}
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "export", "--list"})
	assert.ErrorContains(t, cmd.Execute(), "cosigner-cli stop")
}

func TestExportFailsOnLockedStoreBeforePasswordPrompt(t *testing.T) {
	a, _ := exportTestApp("")
	l := seedExportHome(t, a, "test password", map[string][]byte{"shares:EdDSA:wallet-1": eddsaShareBlob(t)})
	unlock, err := lockFile(filepath.Join(l.state, "data", "cosigner.db.lock"))
	require.NoError(t, err)
	defer unlock()
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "export", "--list"})
	assert.ErrorContains(t, cmd.Execute(), "holds the store lock")
}

func TestGeneratePassphraseUsesBIP39Words(t *testing.T) {
	require.Len(t, wordlist, 2048)
	p, err := generatePassphrase(rand.Reader)
	require.NoError(t, err)
	assert.Len(t, strings.Split(p, "-"), msharePassphraseLen)
}

func TestNormalizePassphrase(t *testing.T) {
	require.Equal(t, "abandon-ability-able-about-above-absent", string(normalizePassphrase([]byte("  Abandon ability-ABLE  about\tabove absent "))))
	require.Nil(t, normalizePassphrase([]byte("abandon ability able about above")))
	require.Nil(t, normalizePassphrase([]byte("abandon ability able about above notaword")))
}

func TestOpenKEKAcceptsSpacedPassphraseAndExactPasswords(t *testing.T) {
	passphrase := "abandon-ability-able-about-above-absent"
	envelope, err := encryptKEK([]byte(passphrase), []byte("kek"))
	require.NoError(t, err)
	plain, used, err := openKEK([]byte("Abandon Ability Able About Above Absent"), envelope)
	require.NoError(t, err)
	require.Equal(t, "kek", string(plain))
	require.Equal(t, passphrase, string(used))

	chosen := "abandon ability able about above absent"
	envelope, err = encryptKEK([]byte(chosen), []byte("kek"))
	require.NoError(t, err)
	_, used, err = openKEK([]byte(chosen), envelope)
	require.NoError(t, err)
	require.Equal(t, chosen, string(used))

	_, _, err = openKEK([]byte("abandon ability able about above above"), envelope)
	require.ErrorIs(t, err, errWrongPassword)
}

func TestRandomPositionsAreDistinctSortedAndInRange(t *testing.T) {
	for range 200 {
		positions, err := randomPositions(rand.Reader, 6, 3)
		require.NoError(t, err)
		require.Len(t, positions, 3)
		require.True(t, positions[0] >= 0 && positions[0] < positions[1] && positions[1] < positions[2] && positions[2] < 6)
	}
}
