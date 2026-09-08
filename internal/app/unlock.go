package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	unlockMagic       = "FYSTACK_COSIGNER_UNLOCK_V2\n"
	unlockTokenSize   = 32
	unlockHandshakeIO = 5 * time.Second
)

// V2 uses a fresh capability key per launch. The key never crosses the network:
// the client proves possession over a random challenge and receives an AEAD
// encrypted password. Docker administrators remain inside the trust boundary.
type unlockServer struct {
	listener    net.Listener
	token       string
	done        chan error
	finished    chan struct{}
	mu          sync.Mutex
	claimed     bool
	connections map[net.Conn]struct{}
}

func newUnlockServer(password []byte) (*unlockServer, error) {
	if len(password) == 0 || len(password) > 4096 {
		return nil, errors.New("password must contain 1 to 4096 bytes")
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("listen for storage unlock: %w", err)
	}
	raw := make([]byte, unlockTokenSize)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		listener.Close()
		return nil, err
	}
	s := &unlockServer{listener: listener, token: hex.EncodeToString(raw), done: make(chan error, 1), finished: make(chan struct{}), connections: make(map[net.Conn]struct{})}
	clear(raw)
	go s.serve(append([]byte(nil), password...))
	return s, nil
}

func (s *unlockServer) port() int { return s.listener.Addr().(*net.TCPAddr).Port }

func (s *unlockServer) serve(password []byte) {
	var handlers sync.WaitGroup
	defer close(s.finished)
	defer clear(password)
	defer handlers.Wait()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.claimed || len(s.connections) >= 16 {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.connections[conn] = struct{}{}
		s.mu.Unlock()
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() { conn.Close(); s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
			_ = conn.SetDeadline(time.Now().Add(unlockHandshakeIO))
			s.handle(conn, password)
		}()
	}
}

func (s *unlockServer) handle(conn net.Conn, password []byte) {
	magic := make([]byte, len(unlockMagic))
	if _, err := io.ReadFull(conn, magic); err != nil || string(magic) != unlockMagic {
		return
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return
	}
	if _, err := conn.Write(challenge); err != nil {
		return
	}
	key, err := hex.DecodeString(s.token)
	if err != nil {
		return
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(unlockMagic))
	mac.Write(challenge)
	proof := make([]byte, sha256.Size)
	if _, err := io.ReadFull(conn, proof); err != nil || !hmac.Equal(proof, mac.Sum(nil)) {
		return
	}
	s.mu.Lock()
	if s.claimed {
		s.mu.Unlock()
		return
	}
	s.claimed = true
	s.mu.Unlock()
	// Claim is terminal even if delivery fails: retry requires a fresh launch.
	defer s.listener.Close()
	defer clear(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		s.done <- err
		return
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		s.done <- err
		return
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		s.done <- err
		return
	}
	payload := aead.Seal(nonce, nonce, password, challenge)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	_, err = conn.Write(append(length[:], payload...))
	s.done <- err
}

func (s *unlockServer) wait(ctx context.Context) error {
	select {
	case err := <-s.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *unlockServer) close() {
	_ = s.listener.Close()
	s.mu.Lock()
	for conn := range s.connections {
		_ = conn.Close()
	}
	s.mu.Unlock()
	<-s.finished
	s.token = ""
}
