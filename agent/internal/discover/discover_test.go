package discover

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseUsesSRVPortAndARecord(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.StartAnswers()
	b.PTRResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(service), Class: dnsmessage.ClassINET},
		dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("vulnwatch." + service)})
	b.StartAdditionals()
	b.SRVResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("vulnwatch." + service), Class: dnsmessage.ClassINET},
		dnsmessage.SRVResource{Port: 8443, Target: dnsmessage.MustNewName("vulnwatch-master.local.")})
	b.AResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("vulnwatch-master.local."), Class: dnsmessage.ClassINET},
		dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	got := Parse(msg, net.IPv4(10, 0, 0, 1))
	if len(got) != 1 || got[0] != "https://192.0.2.10:8443" {
		t.Fatalf("%v", got)
	}
	if Parse([]byte("garbage"), nil) != nil {
		t.Fatal("garbage parsed")
	}
}
