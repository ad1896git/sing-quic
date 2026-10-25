package hysteria2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/blake2b"
)

type obfsTestPacketConn struct {
	net.PacketConn
	packet []byte
}

func (c *obfsTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.packet = append([]byte(nil), p...)
	return len(p), nil
}

func (c *obfsTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return copy(p, c.packet), &net.UDPAddr{}, nil
}

func (c *obfsTestPacketConn) WriteVectorisedPacket(buffers []*buf.Buffer, _ M.Socksaddr) error {
	defer buf.ReleaseMulti(buffers)
	c.packet = nil
	for _, b := range buffers {
		c.packet = append(c.packet, b.Bytes()...)
	}
	return nil
}

func TestSalamanderVector(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sizes []int
	}{
		{"32Plus1", []int{32, 1}},
		{"Wrap", []int{17, 48, 31, 2}},
		{"EmptyBuffers", []int{0, 17, 0, 48, 0, 1, 0}},
		{"AllEmpty", []int{0, 0}},
		{"NoBuffers", nil},
		{"SingleBuffer", []int{97}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var payload []byte
			var buffers []*buf.Buffer
			for _, size := range tc.sizes {
				part := make([]byte, size)
				for i := range part {
					part[i] = byte(len(payload) + i)
				}
				payload = append(payload, part...)
				buffers = append(buffers, buf.As(part))
			}
			defer buf.ReleaseMulti(buffers)
			scalarRaw, vectorRaw := new(obfsTestPacketConn), new(obfsTestPacketConn)
			secret := []byte("salamander regression secret")
			scalar := NewSalamanderConn(scalarRaw, secret, true)
			vector := NewSalamanderConn(vectorRaw, secret, false).(*VectorisedSalamanderPacketConn)
			// Replay an identical salt through the actual scalar and vector writers.
			originalReader := rand.Reader
			defer func() { rand.Reader = originalReader }()
			salt := []byte("12345678")
			rand.Reader = bytes.NewReader(salt)
			if _, err := scalar.WriteTo(payload, &net.UDPAddr{}); err != nil {
				t.Fatal(err)
			}
			rand.Reader = bytes.NewReader(salt)
			if err := vector.WriteVectorisedPacket(buffers, M.Socksaddr{}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(scalarRaw.packet, vectorRaw.packet) {
				t.Fatalf("vector packet %x != scalar packet %x", vectorRaw.packet, scalarRaw.packet)
			}
		})
	}
}

func TestObfsSecretConcurrency(t *testing.T) {
	// Generated with both production files restored from f9887b8: ReadFrom
	// on salt || zero ciphertext gives the key stream; XOR with payload.
	fixedPackets := map[string]string{
		"Salamander": "010101010101010112f6f4f36a86e3b31379ecea200cf44da17c54efd7ab3e0c7240556d59a1421f12f6a4e26393ecf11072a9ba7f5fb041ac6d49bb9cbd374d7e42536055",
		"XPlus":      "01010101010101010101010101010101e12227d162cc80a487c7574d85349f93c0e837b76bb3096d86249f0a3e06393ce12277c06bd98fe684cc121dda67db9fcdf92ae320a5002c8a26990732",
	}
	for _, algorithm := range []string{"Salamander", "XPlus"} {
		for _, mode := range []string{"Read", "ScalarWrite", "VectorWrite", "VectorBuffers"} {
			t.Run(algorithm+"/"+mode, func(t *testing.T) {
				backing := bytes.Repeat([]byte{0xa5}, 128)
				copy(backing, "shared secret")
				secret := backing[:13]
				before := append([]byte(nil), backing...)
				payload := []byte("repeatable plaintext spanning more than one 32-byte key block")
				saltLen := 8
				if algorithm == "XPlus" {
					saltLen = 16
				}
				// This is the pre-fix derivation, with an owned secret so that the
				// reference itself cannot modify the shared backing array.
				encrypt := func(salt []byte) []byte {
					input := append(append([]byte(nil), secret...), salt...)
					var key [32]byte
					if algorithm == "Salamander" {
						key = blake2b.Sum256(input)
					} else {
						key = sha256.Sum256(input)
					}
					packet := append([]byte(nil), salt...)
					for i, b := range payload {
						packet = append(packet, b^key[i%len(key)])
					}
					return packet
				}
				if got := fmt.Sprintf("%x", encrypt(bytes.Repeat([]byte{1}, saltLen))); got != fixedPackets[algorithm] {
					t.Fatalf("reference packet = %s, want parent vector %s", got, fixedPackets[algorithm])
				}
				derive := func(seed byte) error {
					raw := new(obfsTestPacketConn)
					vectorised := mode == "VectorWrite" || mode == "VectorBuffers"
					var conn net.PacketConn
					if algorithm == "Salamander" {
						conn = NewSalamanderConn(raw, secret, !vectorised)
					} else {
						conn = hysteria.NewXPlusPacketConn(raw, secret, !vectorised)
					}
					if mode == "Read" {
						salt := bytes.Repeat([]byte{seed}, saltLen)
						raw.packet = encrypt(salt)
						for repeat := 0; repeat < 2; repeat++ {
							p := make([]byte, len(raw.packet))
							n, _, err := conn.ReadFrom(p)
							if err != nil {
								return err
							}
							if !bytes.Equal(p[:n], payload) {
								return fmt.Errorf("read = %x, want %x", p[:n], payload)
							}
						}
						return nil
					}
					for repeat := 0; repeat < 2; repeat++ {
						if mode == "VectorBuffers" {
							buffers := []*buf.Buffer{buf.As(append([]byte(nil), payload[:17]...)), buf.As(append([]byte(nil), payload[17:]...))}
							err := conn.(N.VectorisedPacketWriter).WriteVectorisedPacket(buffers, M.Socksaddr{})
							buf.ReleaseMulti(buffers)
							if err != nil {
								return err
							}
						} else {
							if _, err := conn.WriteTo(append([]byte(nil), payload...), &net.UDPAddr{}); err != nil {
								return err
							}
						}
						if !bytes.Equal(raw.packet, encrypt(raw.packet[:saltLen])) {
							return fmt.Errorf("derived packet differs from pre-fix derivation")
						}
					}
					return nil
				}
				// Check mutation deterministically before exercising concurrent callers.
				if err := derive(1); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(backing, before) {
					t.Fatal("derivation changed secret backing array, including bytes beyond its length")
				}
				const workers = 16
				errors := make(chan error, workers)
				var wg sync.WaitGroup
				for i := 0; i < workers; i++ {
					wg.Add(1)
					go func(seed byte) { defer wg.Done(); errors <- derive(seed) }(byte(i + 2))
				}
				wg.Wait()
				close(errors)
				for err := range errors {
					if err != nil {
						t.Error(err)
					}
				}
				if !bytes.Equal(backing, before) {
					t.Fatal("concurrent derivations changed secret backing array")
				}
			})
		}
	}
}
