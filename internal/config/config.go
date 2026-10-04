// Package config loads the VPN configuration.
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

type Peer struct {
	Name       string   `json:"name"`
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
}

type Config struct {
	PrivateKey string `json:"private_key"`
	ListenPort int    `json:"listen_port"`
	Address    string `json:"address"`
	Peers      []Peer `json:"peers"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// DecodeKey turns a base64 string into a 32-byte key.
func DecodeKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, fmt.Errorf("key must be 32 bytes, got %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}
