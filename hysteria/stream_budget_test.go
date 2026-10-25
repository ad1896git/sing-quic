package hysteria

import (
	"testing"

	aTLS "github.com/sagernet/sing/common/tls"
)

type streamBudgetTLSConfig struct{ aTLS.ServerConfig }

func (streamBudgetTLSConfig) NextProtos() []string { return []string{"test"} }

func TestIncomingStreamBudgetConstructor(t *testing.T) {
	service, err := NewService[string](ServiceOptions{TLSConfig: streamBudgetTLSConfig{}, SendBPS: 1, ReceiveBPS: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := service.quicConfig.MaxIncomingStreams; got != defaultMaxIncomingStreams {
		t.Fatalf("MaxIncomingStreams = %d, want %d", got, defaultMaxIncomingStreams)
	}
}

func TestIncomingStreamBudgetOverride(t *testing.T) {
	for _, limit := range []int64{-1, 0, 1, 200} {
		service, err := NewService[string](ServiceOptions{
			TLSConfig: streamBudgetTLSConfig{}, SendBPS: 1, ReceiveBPS: 1,
			MaxIncomingStreams: limit,
		})
		if err != nil {
			t.Fatal(err)
		}
		want := limit
		if want <= 0 {
			want = defaultMaxIncomingStreams
		}
		if got := service.quicConfig.MaxIncomingStreams; got != want {
			t.Fatalf("override %d: MaxIncomingStreams = %d, want %d", limit, got, want)
		}
	}
}
