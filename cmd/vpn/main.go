package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"

	"vpntunnel/internal/config"
	"vpntunnel/internal/device"
	"vpntunnel/internal/peer"
	"vpntunnel/internal/router"
	"vpntunnel/internal/tun"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	ifName := flag.String("iface", "wg0", "TUN interface name")
	flag.Parse()

	if err := run(*cfgPath, *ifName); err != nil {
		log.Fatal(err)
	}
}

func run(cfgPath, ifName string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	routes := router.New()
	var peers []*peer.Peer
	for _, pc := range cfg.Peers {
		pub, err := config.DecodeKey(pc.PublicKey)
		if err != nil {
			return fmt.Errorf("peer %s: %w", pc.Name, err)
		}
		var allowed []netip.Prefix
		for _, cidr := range pc.AllowedIPs {
			pfx, err := netip.ParsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("peer %s: %w", pc.Name, err)
			}
			allowed = append(allowed, pfx)
			if err := routes.Add(pc.Name, cidr); err != nil {
				return fmt.Errorf("route %s: %w", cidr, err)
			}
		}
		var ep netip.AddrPort
		if pc.Endpoint != "" {
			if ep, err = netip.ParseAddrPort(pc.Endpoint); err != nil {
				return fmt.Errorf("peer %s endpoint: %w", pc.Name, err)
			}
		}
		peers = append(peers, peer.New(pc.Name, pub, allowed, ep))
	}

	tunDev, err := tun.Open(ifName)
	if err != nil {
		return fmt.Errorf("open tun: %w (needs root / CAP_NET_ADMIN)", err)
	}
	defer tunDev.Close()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: cfg.ListenPort})
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	log.Printf("vpn up on %s, udp :%d, %d peers", tunDev.Name(), cfg.ListenPort, len(peers))
	return device.New(tunDev, conn, routes, peers).Run(ctx)
}
