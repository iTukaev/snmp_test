package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/slayercat/GoSNMPServer"
)

func main() {
	go func() { _ = http.ListenAndServe(":8080", nil) }()
	now := time.Now()

	master := GoSNMPServer.MasterAgent{
		Logger: GoSNMPServer.NewDiscardLogger(),
		SecurityConfig: GoSNMPServer.SecurityConfig{
			AuthoritativeEngineBoots: 1,
			Users: []gosnmp.UsmSecurityParameters{
				{
					UserName:                 "admin",
					AuthenticationProtocol:   gosnmp.MD5,
					PrivacyProtocol:          gosnmp.NoPriv,
					AuthenticationPassphrase: "infinetadmin",
				},
			},
		},
		SubAgents: []*GoSNMPServer.SubAgent{
			{
				CommunityIDs: []string{"public"},
				OIDs: []*GoSNMPServer.PDUValueControlItem{
					{
						OID:  ".1.3.6.1.4.1.2021.11.60",
						Type: gosnmp.TimeTicks,
						OnGet: func() (value interface{}, err error) {
							return GoSNMPServer.Asn1TimeTicksWrap(123456788), nil
						},
						Document: "Uptime",
					},
				},
			},
		},
	}

	iter := newIter()
	for i := 0; i < 100000; i++ {
		addr := iter.next()
		srv := GoSNMPServer.NewSNMPServer(master)
		err := srv.ListenUDP("udp", addr)
		if err != nil {
			log.Fatalln("NewUDPListener", addr, err)
		}

		go func() { _ = srv.ServeForever() }()
	}

	fmt.Println(iter.next())
	fmt.Println(time.Since(now))
	<-context.Background().Done()
}

type ipIterator struct {
	ip netip.Addr
}

func newIter() ipIterator {
	return ipIterator{ip: netip.MustParseAddr("127.0.0.1")}
}

func (i *ipIterator) next() string {
	addr := i.ip.String()
	i.ip = i.ip.Next()
	if i.ip.As4()[3] == 0 {
		i.ip = i.ip.Next()
	}

	return addr + ":1161"
}
