package hysteria2

import (
	"testing"

	aTLS "github.com/sagernet/sing/common/tls"
)

type streamBudgetTLSConfig struct{ aTLS.ServerConfig }

func (streamBudgetTLSConfig) NextProtos() []string { return []string{"test"} }

func TestIncomingStreamBudgetConstructor(t *testing.T) {
	service, err := NewService[string](ServiceOptions{TLSConfig: streamBudgetTLSConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := service.quicConfig.MaxIncomingStreams; got != 100 {
		t.Fatalf("MaxIncomingStreams = %d, want 100", got)
	}
}
