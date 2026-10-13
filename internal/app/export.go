package app

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	ecdsakeygen "github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	eddsakeygen "github.com/bnb-chain/tss-lib/v3/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

// The .mshare format must stay byte-compatible with cosigner-mobile
// (mobile/recovery_share.go) and cosigner-recovery (internal/recovery/mshare.go).
const (
	mshareFormat        = "fystack-wallet-share-v1"
	msharePassphraseLen = 6
	mshareSaltSize      = 16
	mshareNonceSize     = 12
	mshareKDFTime       = 3
	mshareKDFMemoryKiB  = 64 * 1024
	mshareKDFThreads    = 4
	mshareKeySize       = 32
	// Must match scopeShares and LocalEncryptor's record format in the cosigner runtime.
	sharesScope        = "cosigner:shares"
	shareRecordVersion = 1
	shareNonceSize     = 12
)

//go:embed assets/wordlist_en.txt
var wordlistRaw string

var wordlist = strings.Fields(wordlistRaw)

type mshareKDF struct {
	Name      string `json:"name"`
	MemoryKiB uint32 `json:"memory_kib"`
	Time      uint32 `json:"time"`
	Threads   uint8  `json:"threads"`
}

type mshareContextEntry struct {
	Protocol             string `json:"protocol"`
	JointPublicKeyBase64 string `json:"joint_public_key_base64"`
}

type mshareContext struct {
	WorkspaceID   string               `json:"workspace_id"`
	WalletID      string               `json:"wallet_id"`
	ParticipantID string               `json:"participant_id"`
	DeviceID      string               `json:"device_id"`
	Shares        []mshareContextEntry `json:"shares"`
}

// mshareHeader is the AAD; field order is part of the format.
type mshareHeader struct {
	Format  string        `json:"format"`
	KDF     mshareKDF     `json:"kdf"`
	Salt    string        `json:"salt"`
	Nonce   string        `json:"nonce"`
	Context mshareContext `json:"context"`
}

type mshareEnvelope struct {
	Format     string        `json:"format"`
	KDF        mshareKDF     `json:"kdf"`
	Salt       string        `json:"salt"`
	Nonce      string        `json:"nonce"`
	Context    mshareContext `json:"context"`
	Ciphertext string        `json:"ciphertext"`
}

type mshareShare struct {
	WalletID             string `json:"wallet_id"`
	Protocol             string `json:"protocol"`
	JointPublicKeyBase64 string `json:"joint_public_key_base64"`
	ShareBlobBase64      string `json:"share_blob_base64"`
}

type walletShares struct {
	walletID string
	blobs    map[string][]byte // protocol -> tss-lib LocalPartySaveData JSON
}

func (w walletShares) protocols() []string {
	out := make([]string, 0, len(w.blobs))
	for p := range w.blobs {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (a *App) exportCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export wallet key shares as passphrase-encrypted .mshare recovery files (service must be stopped)",
		Long: "Export this Cosigner's key shares, one .mshare file per wallet, for use with Fystack Recovery.\n" +
			"Each run generates a six-word passphrase that unlocks the files; it is printed once and never stored.",
		RunE: a.export,
	}
	cmd.Flags().StringSlice("wallet", nil, "Wallet ID to export (repeatable; default: all wallets)")
	cmd.Flags().String("out-dir", ".", "Directory to write .mshare files into")
	cmd.Flags().Bool("list", false, "List wallets with stored shares instead of exporting")
	return cmd
}

func (a *App) export(cmd *cobra.Command, _ []string) error {
	l, s, err := a.installation(cmd)
	if err != nil {
		return err
	}
	if s.Profile != "manual" {
		return errors.New("export requires the manual profile; the unattended storage key is held in KMS")
	}
	running, err := a.alreadyRunning(cmd.Context(), a.docker(cmd, s), l, s)
	if err != nil {
		return err
	}
	if running {
		return errors.New("the Cosigner is running; run `cosigner-cli stop` first")
	}
	var pairing struct {
		CosignerID    string `yaml:"cosigner_id"`
		WorkspaceID   string `yaml:"workspace_id"`
		ParticipantID string `yaml:"participant_id"`
	}
	raw, err := os.ReadFile(l.pairing())
	if err != nil {
		return fmt.Errorf("read pairing configuration: %w", err)
	}
	if err := yaml.Unmarshal(raw, &pairing); err != nil {
		return fmt.Errorf("parse pairing configuration: %w", err)
	}

	wallets, err := a.loadWalletShares(l)
	if err != nil {
		return err
	}
	defer func() {
		for _, w := range wallets {
			for _, blob := range w.blobs {
				clear(blob)
			}
		}
	}()
	list, _ := cmd.Flags().GetBool("list")
	if list {
		for _, w := range wallets {
			fmt.Fprintf(a.Out, "%s\t%s\n", w.walletID, strings.Join(w.protocols(), ","))
		}
		return nil
	}

	ids, _ := cmd.Flags().GetStringSlice("wallet")
	selected, err := selectWallets(wallets, ids)
	if err != nil {
		return err
	}
	outDir, _ := cmd.Flags().GetString("out-dir")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	passphrase, err := generatePassphrase(a.Random)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var written []string
	for _, w := range selected {
		ctx := mshareContext{WorkspaceID: pairing.WorkspaceID, WalletID: w.walletID, ParticipantID: pairing.ParticipantID, DeviceID: pairing.CosignerID}
		bundle, err := buildMShare(a.Random, passphrase, ctx, w)
		if err != nil {
			return fmt.Errorf("wallet %s: %w", w.walletID, err)
		}
		path := filepath.Join(outDir, mshareFilename(w.walletID, pairing.ParticipantID, now))
		if err := atomicWrite(path, bundle, 0o600); err != nil {
			return fmt.Errorf("wallet %s: %w", w.walletID, err)
		}
		written = append(written, path)
	}
	for _, path := range written {
		fmt.Fprintf(a.Out, "Wrote %s\n", path)
	}
	fmt.Fprintf(a.Out, "\nRecovery passphrase (unlocks every file above; shown only once):\n\n    %s\n\n", passphrase)
	fmt.Fprintln(a.Out, "Store the passphrase separately from the files. Anyone holding both, plus enough other shares, can rebuild the wallet keys.")
	return nil
}

func selectWallets(wallets []walletShares, ids []string) ([]walletShares, error) {
	if len(wallets) == 0 {
		return nil, errors.New("no wallet shares found in this Cosigner")
	}
	if len(ids) == 0 {
		return wallets, nil
	}
	byID := make(map[string]walletShares, len(wallets))
	for _, w := range wallets {
		byID[w.walletID] = w
	}
	out := make([]walletShares, 0, len(ids))
	for _, id := range ids {
		w, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("no shares found for wallet %s (use --list to see stored wallets)", id)
		}
		out = append(out, w)
	}
	return out, nil
}

// loadWalletShares holds the runtime's store lock while reading, so a Cosigner
// started concurrently (or missed by the container check) fails instead of racing.
func (a *App) loadWalletShares(l layout) ([]walletShares, error) {
	dbPath := filepath.Join(l.state, "data", "cosigner.db")
	if !fileExists(dbPath) {
		return nil, fmt.Errorf("Cosigner store not found at %s", dbPath)
	}
	unlock, err := lockFile(dbPath + ".lock")
	if err != nil {
		if errors.Is(err, errLocked) {
			return nil, errors.New("the Cosigner is running and holds the store lock; run `cosigner-cli stop` first")
		}
		return nil, fmt.Errorf("lock Cosigner store: %w", err)
	}
	defer unlock()
	// Take the lock before prompting so a running Cosigner fails fast.
	kek, err := a.storageKEK(l)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	aead, err := shareCipher(kek)
	if err != nil {
		return nil, err
	}
	rows, err := readShareRows(dbPath)
	if err != nil {
		return nil, err
	}

	byWallet := map[string]*walletShares{}
	for _, row := range rows {
		plain, err := openShareRecord(aead, row.key, row.value)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", row.key, err)
		}
		w := byWallet[row.walletID]
		if w == nil {
			w = &walletShares{walletID: row.walletID, blobs: map[string][]byte{}}
			byWallet[row.walletID] = w
		}
		w.blobs[row.protocol] = plain
	}
	out := make([]walletShares, 0, len(byWallet))
	for _, w := range byWallet {
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].walletID < out[j].walletID })
	return out, nil
}

type shareRow struct {
	key, protocol, walletID string
	value                   []byte
}

func readShareRows(dbPath string) ([]shareRow, error) {
	// mode=rw so a missing file is an error rather than a fresh empty database.
	dsn := (&url.URL{Scheme: "file", Path: dbPath}).String() + "?mode=rw&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open Cosigner store: %w", err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT key, value FROM kv WHERE key LIKE 'shares:%' ORDER BY key")
	if err != nil {
		return nil, fmt.Errorf("read Cosigner store: %w", err)
	}
	defer rows.Close()
	var out []shareRow
	for rows.Next() {
		var r shareRow
		if err := rows.Scan(&r.key, &r.value); err != nil {
			return nil, fmt.Errorf("read Cosigner store: %w", err)
		}
		parts := strings.Split(r.key, ":")
		if len(parts) != 3 || parts[0] != "shares" {
			continue
		}
		r.protocol, r.walletID = parts[1], parts[2]
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read Cosigner store: %w", err)
	}
	return out, nil
}

func shareCipher(kek []byte) (cipher.AEAD, error) {
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, kek, nil, []byte(sharesScope)), key); err != nil {
		return nil, fmt.Errorf("derive shares key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// openShareRecord decodes [version | nonce | ciphertext||tag] with AAD scope||0x00||rowKey.
func openShareRecord(aead cipher.AEAD, rowKey string, blob []byte) ([]byte, error) {
	if len(blob) < 1+shareNonceSize || blob[0] != shareRecordVersion {
		return nil, errors.New("unsupported share record")
	}
	aad := append([]byte(sharesScope+"\x00"), rowKey...)
	return aead.Open(nil, blob[1:1+shareNonceSize], blob[1+shareNonceSize:], aad)
}

func (a *App) storageKEK(l layout) ([]byte, error) {
	raw, err := os.ReadFile(l.encryptedKEK())
	if err != nil {
		return nil, fmt.Errorf("read encrypted storage KEK: %w", err)
	}
	password, err := a.readPassword(false)
	if err != nil {
		return nil, err
	}
	plaintext, used, err := openKEK(password, raw)
	if err != nil {
		return nil, err
	}
	clear(used)
	defer clear(plaintext)
	trimmed := bytes.TrimSpace(plaintext)
	kek := make([]byte, hex.DecodedLen(len(trimmed)))
	if _, err := hex.Decode(kek, trimmed); err != nil || len(kek) < 16 {
		clear(kek)
		return nil, errors.New("storage KEK is not a valid hex key")
	}
	return kek, nil
}

func buildMShare(random io.Reader, passphrase string, ctx mshareContext, w walletShares) ([]byte, error) {
	shares := make([]mshareShare, 0, len(w.blobs))
	for _, protocol := range w.protocols() {
		blob := w.blobs[protocol]
		pub, err := jointPublicKey(protocol, blob)
		if err != nil {
			return nil, err
		}
		pubB64 := base64.StdEncoding.EncodeToString(pub)
		shares = append(shares, mshareShare{WalletID: w.walletID, Protocol: protocol, JointPublicKeyBase64: pubB64, ShareBlobBase64: base64.StdEncoding.EncodeToString(blob)})
		ctx.Shares = append(ctx.Shares, mshareContextEntry{Protocol: protocol, JointPublicKeyBase64: pubB64})
	}
	payload, err := json.Marshal(struct {
		Shares []mshareShare `json:"shares"`
	}{shares})
	if err != nil {
		return nil, err
	}
	defer clear(payload)

	salt := make([]byte, mshareSaltSize)
	nonce := make([]byte, mshareNonceSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	header := mshareHeader{
		Format:  mshareFormat,
		KDF:     mshareKDF{Name: "argon2id", MemoryKiB: mshareKDFMemoryKiB, Time: mshareKDFTime, Threads: mshareKDFThreads},
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Context: ctx,
	}
	aad, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(passphrase), salt, header.KDF.Time, header.KDF.MemoryKiB, header.KDF.Threads, mshareKeySize)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return json.Marshal(mshareEnvelope{
		Format: header.Format, KDF: header.KDF, Salt: header.Salt, Nonce: header.Nonce, Context: header.Context,
		Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, payload, aad)),
	})
}

// jointPublicKey also validates that the stored blob is a usable tss-lib share.
func jointPublicKey(protocol string, blob []byte) ([]byte, error) {
	switch protocol {
	case "ECDSA":
		var data ecdsakeygen.LocalPartySaveData
		if err := json.Unmarshal(blob, &data); err != nil || data.ECDSAPub == nil {
			return nil, errors.New("invalid ECDSA share")
		}
		data.ECDSAPub.SetCurve(tss.S256())
		if !data.ECDSAPub.ValidateBasic() {
			return nil, errors.New("invalid ECDSA joint public key")
		}
		out := make([]byte, 65)
		out[0] = 4
		data.ECDSAPub.X().FillBytes(out[1:33])
		data.ECDSAPub.Y().FillBytes(out[33:])
		return out, nil
	case "EdDSA":
		var data eddsakeygen.LocalPartySaveData
		if err := json.Unmarshal(blob, &data); err != nil || data.EDDSAPub == nil {
			return nil, errors.New("invalid EdDSA share")
		}
		data.EDDSAPub.SetCurve(tss.Edwards())
		if !data.EDDSAPub.ValidateBasic() {
			return nil, errors.New("invalid EdDSA joint public key")
		}
		out := make([]byte, ed25519.PublicKeySize)
		y := data.EDDSAPub.Y().Bytes()
		for i := 0; i < len(y) && i < len(out); i++ {
			out[i] = y[len(y)-1-i]
		}
		if data.EDDSAPub.X().Bit(0) == 1 {
			out[len(out)-1] |= 0x80
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported share protocol %q", protocol)
	}
}

func generatePassphrase(random io.Reader) (string, error) {
	words := make([]string, msharePassphraseLen)
	for i := range words {
		j, err := randomIndex(random, len(wordlist))
		if err != nil {
			return "", fmt.Errorf("generate passphrase: %w", err)
		}
		words[i] = wordlist[j]
	}
	return strings.Join(words, "-"), nil
}

// randomIndex returns a uniform index below n, rejecting values that would bias
// the modulo.
func randomIndex(random io.Reader, n int) (int, error) {
	limit := (uint64(1) << 32) - ((uint64(1) << 32) % uint64(n))
	var buf [4]byte
	for {
		if _, err := io.ReadFull(random, buf[:]); err != nil {
			return 0, err
		}
		if v := uint64(binary.BigEndian.Uint32(buf[:])); v < limit {
			return int(v % uint64(n)), nil
		}
	}
}

var unsafeSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

func slug(value string) string {
	s := strings.Trim(unsafeSlugChars.ReplaceAllString(strings.ToLower(value), "-"), "-")
	if s == "" {
		return "wallet"
	}
	return s
}

// mshareFilename mirrors cosigner-mobile's recoveryShareFilename.
func mshareFilename(walletID, participantID string, now time.Time) string {
	participant := slug(participantID)
	if len(participant) > 6 {
		participant = participant[:6]
	}
	return fmt.Sprintf("%s-%s-%s.mshare", slug(walletID), participant, strings.ToLower(now.Format("02Jan2006")))
}
