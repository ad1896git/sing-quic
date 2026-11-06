package udphop

import (
	"errors"
	"reflect"
	"testing"
)

func TestResolveUDPHopAddrPorts(t *testing.T) {
	for portStr, want := range map[string][]uint16{
		"443":       {443},
		"1":         {1},
		"65535":     {65535},
		"443,8443":  {443, 8443},
		"1000-1002": {1000, 1001, 1002},
		"1002-1000": {1000, 1001, 1002},
	} {
		addr, err := ResolveUDPHopAddr("127.0.0.1", portStr)
		if err != nil {
			t.Errorf("ResolveUDPHopAddr(%q) = %v", portStr, err)
			continue
		}
		if !reflect.DeepEqual(addr.Ports, want) {
			t.Errorf("ResolveUDPHopAddr(%q) ports = %v, want %v", portStr, addr.Ports, want)
		}
	}
}

func TestResolveUDPHopAddrInvalidPorts(t *testing.T) {
	for _, portStr := range []string{"", "0", "0-10", "10-0", "65536", "443,", "a", "1-2-3", "-1", " 443"} {
		_, err := ResolveUDPHopAddr("127.0.0.1", portStr)
		var portErr InvalidPortError
		if !errors.As(err, &portErr) {
			t.Errorf("ResolveUDPHopAddr(%q) = %v, want InvalidPortError", portStr, err)
		}
	}
}
