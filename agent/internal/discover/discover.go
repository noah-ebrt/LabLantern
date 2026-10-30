// Package discover sucht den vulnwatch-Master per mDNS (_vulnwatch._tcp) im lokalen Netz.
// Vertrauen entsteht dadurch nicht: Das klärt erst der Pairing-Code.
package discover

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

const service = "_vulnwatch._tcp.local."

var mdnsAddr = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// Masters liefert https-Adressen aller Antworten innerhalb von timeout. Gefragt wird auf jeder echten
// Netzwerkschnittstelle einzeln: Auf Docker- oder VPN-Hosts landet eine Multicast-Anfrage sonst leicht auf
// der falschen Schnittstelle.
func Masters(timeout time.Duration) ([]string, error) {
	q, err := query()
	if err != nil {
		return nil, err
	}
	ifaces := lanInterfaces()
	if len(ifaces) == 0 {
		ifaces = []*net.Interface{nil} // Standardroute
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	found := map[string]bool{}
	for _, ifi := range ifaces {
		wg.Add(1)
		go func(ifi *net.Interface) {
			defer wg.Done()
			for _, u := range ask(ifi, q, timeout) {
				mu.Lock()
				found[u] = true
				mu.Unlock()
			}
		}(ifi)
	}
	wg.Wait()
	out := make([]string, 0, len(found))
	for u := range found {
		out = append(out, u)
	}
	sort.Strings(out)
	return out, nil
}

// lanInterfaces: aktive Schnittstellen mit IPv4 und Multicast, ohne Loopback, Docker, Bridges und VPN.
func lanInterfaces() []*net.Interface {
	all, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []*net.Interface
	for i := range all {
		ifi := &all[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		skip := false
		for _, p := range []string{"docker", "br-", "veth", "virbr", "tailscale", "wg", "tun", "zt", "cni", "flannel"} {
			if strings.HasPrefix(ifi.Name, p) {
				skip = true
			}
		}
		if addrs, _ := ifi.Addrs(); !skip && hasIPv4(addrs) {
			out = append(out, ifi)
		}
	}
	return out
}

func hasIPv4(addrs []net.Addr) bool {
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			return true
		}
	}
	return false
}

// ask sendet die Anfrage über eine Schnittstelle; Antworten an einen Port ≠ 5353 kommen als Unicast zurück
// (RFC 6762, „legacy unicast“).
func ask(ifi *net.Interface, q []byte, timeout time.Duration) []string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil
	}
	defer conn.Close()
	if ifi != nil {
		pc := ipv4.NewPacketConn(conn)
		if err := pc.SetMulticastInterface(ifi); err != nil {
			return nil
		}
	}
	if _, err := conn.WriteToUDP(q, mdnsAddr); err != nil {
		return nil
	}
	var out []string
	buf := make([]byte, 9000)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		out = append(out, Parse(buf[:n], from.IP)...)
	}
}

func query() ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(service), Type: dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

type srv struct {
	target string
	port   uint16
}

// Parse liest SRV- und A-Einträge einer Antwort; ohne A-Eintrag gilt die Absenderadresse.
func Parse(msg []byte, from net.IP) []string {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil
	}
	_ = p.SkipAllQuestions()
	var srvs []srv
	addrs := map[string]string{}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		collect(&p, h, &srvs, addrs, p.SkipAnswer)
	}
	_ = p.SkipAllAuthorities()
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		collect(&p, h, &srvs, addrs, p.SkipAdditional)
	}
	var out []string
	for _, s := range srvs {
		ip := addrs[s.target]
		if ip == "" && from != nil {
			ip = from.String()
		}
		if ip != "" && s.port != 0 {
			out = append(out, "https://"+net.JoinHostPort(ip, fmt.Sprint(s.port)))
		}
	}
	return out
}

func collect(p *dnsmessage.Parser, h dnsmessage.ResourceHeader, srvs *[]srv, addrs map[string]string, skip func() error) {
	switch h.Type {
	case dnsmessage.TypeSRV:
		if r, err := p.SRVResource(); err == nil && strings.HasSuffix(h.Name.String(), "."+service) {
			*srvs = append(*srvs, srv{r.Target.String(), r.Port})
		}
	case dnsmessage.TypeA:
		if r, err := p.AResource(); err == nil {
			addrs[h.Name.String()] = netip.AddrFrom4(r.A).String()
		}
	default:
		_ = skip()
	}
}
