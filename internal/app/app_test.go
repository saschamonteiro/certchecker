package app

import (
	"testing"
)

func TestHostsFromCIDR(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		length      int
		first       string
		last        string
		shouldError string
	}{
		{
			name:   "subnet/32-singlehost",
			cidr:   "192.168.10.110/32",
			length: 1,
			first:  "192.168.10.110",
		}, {
			name:   "subnet/24",
			cidr:   "192.168.10.0/24",
			length: 254,
			first:  "192.168.10.1",
			last:   "192.168.10.254",
		},
		{
			name:   "subnet/16",
			cidr:   "192.168.0.0/16",
			length: 65534,
			first:  "192.168.0.1",
			last:   "192.168.255.254",
		},
		{
			name:        "no subnet",
			cidr:        "192.168.10.0",
			length:      0,
			shouldError: "invalid CIDR address: 192.168.10.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, err := hostsFromCIDR(tt.cidr)
			if err != nil {
				if tt.shouldError != "" {
					if err.Error() != tt.shouldError {
						t.Errorf("hostsFromCIDR() error = %v, want %v", err, tt.shouldError)
					}
				} else {
					t.Errorf("hostsFromCIDR() error = %v", err)
				}
			}
			if len(hosts) != tt.length {
				t.Errorf("hostsFromCIDR() = %v, want %v", len(hosts), tt.length)
			}
			if tt.length > 1 {
				if hosts[0] != tt.first {
					t.Errorf("hostsFromCIDR() = %v, want %v", hosts[0], tt.first)
				}
				if hosts[len(hosts)-1] != tt.last {
					t.Errorf("hostsFromCIDR() = %v, want %v", hosts[len(hosts)-1], tt.last)
				}
			}
			if tt.length == 1 {
				if hosts[0] != tt.first {
					t.Errorf("hostsFromCIDR() = %v, want %v", hosts[0], tt.first)
				}
			}
		})
	}
}
