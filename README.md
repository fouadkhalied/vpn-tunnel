# VPN tunnel in Go (WireGuard-style skeleton)

Skeleton for the shipthatcode course "Build a VPN Tunnel". It compiles; every
`TODO` is yours to fill in. The course starts in Python and its exercises are
graded stdin/stdout programs, so this repo is the "real project" you grow alongside them.

## Layout, mapped to the course chapters

The course page only names the first and last lesson of each chapter, so the
mapping below is approximate. Adjust it as you go.

| Package | Course chapter |
|---|---|
| `internal/tun`, `internal/packet` | 1. VPN Fundamentals (TUN/TAP, encapsulation) |
| `internal/noise`, `internal/crypto` | 2. Cryptography & Handshake (Noise, X25519, ChaCha20-Poly1305, BLAKE2s) |
| `internal/router`, `internal/peer`, `internal/config` | 3. Tunneling & Routing (peers, cryptokey routing, endpoints/NAT) |
| `internal/device`, `cmd/vpn` | 4. Production (the main loops, performance) |

## Suggested order

1. `router`: make `go test ./internal/router` pass (this is the "Routing Decision" exercise).
2. `packet.ParseIPv4`, then add a test with a hand-built packet.
3. `tun.Open`, then print packets from `tunToUDP` to see real traffic.
4. Send packets unencrypted between two machines/namespaces. Get the tunnel working first.
5. `crypto.Session` (AEAD + replay window), with a static key.
6. `noise` handshake to derive keys, then rekeying and roaming.

## Run

```bash
go test ./...                     # router tests fail until you implement them
go build -o vpn ./cmd/vpn
cp config.example.json config.json
sudo ./vpn -config config.json    # needs root / CAP_NET_ADMIN
# in another terminal:
sudo ip addr add 10.0.0.1/24 dev wg0 && sudo ip link set wg0 up
```

Later chapters need: `go get golang.org/x/crypto`.
Test safely using two network namespaces, not your main network config.
