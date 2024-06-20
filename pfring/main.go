package main

import (
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
	"github.com/slayercat/GoSNMPServer"
)

var counter atomic.Uint64
var ipCache = cache{
	c: map[string]struct{}{},
}

func main() {
	go func() { _ = http.ListenAndServe(":8080", nil) }()

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()

		for {
			select {
			case <-t.C:
				current := counter.Swap(0)
				fmt.Println("next count:", current)
			}
		}
	}()

	if err := master.ReadyForWork(); err != nil {
		panic(err)
	}

	if ring, err := pfring.NewRing("lo", 65000, pfring.FlagPromisc); err != nil {
		panic(err)
	} else if err := ring.SetBPFFilter("udp and dst port 161"); err != nil { // optional
		panic(err)
	} else if err := ring.Enable(); err != nil { // Must do this!, or you get no packets!
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
		for packet := range packetSource.Packets() {
			handlePacket(packet) // Do something with a packet here.
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	ip4 := packet.NetworkLayer().(*layers.IPv4)

	// Упрощённая версия проверки дублирования пакетов UDP. Конкретно у меня все пакеты UDP дублируются при текущих
	// заданных параметрах. net.ListenUDP автоматически разрешает эту проблему на уровне ОС. pfring же принимает все
	// пакеты как есть и поэтому дублируются вся обработка snmp.
	if ipCache.pop(ip4.SrcIP.String()) {
		return
	}
	ipCache.put(ip4.SrcIP.String())

	udp := packet.TransportLayer().(*layers.UDP)
	payload := packet.ApplicationLayer().Payload()

	result, err := master.ResponseForBuffer(payload)
	if err != nil {
		fmt.Println("ResponseForBuffer Error:", err)
		return
	}

	if len(result) != 0 {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip4.DstIP, Port: int(udp.DstPort)})
		if err != nil {
			fmt.Println("ListenUDP", err)
			return
		}
		defer func() { _ = conn.Close() }()

		rr := udpReplyer{
			target: &net.UDPAddr{IP: ip4.SrcIP, Port: int(udp.SrcPort)},
			conn:   conn,
		}
		if err = rr.ReplyPDU(result); err != nil {
			fmt.Println("Reply PDU meet err:", err)
		}
	}
}

type cache struct {
	c  map[string]struct{}
	mu sync.Mutex
}

func (c *cache) put(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.c[ip] = struct{}{}
}

func (c *cache) pop(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.c[ip]; ok {
		delete(c.c, ip)
		return true
	}

	return false
}

type udpReplyer struct {
	target *net.UDPAddr
	conn   *net.UDPConn
}

func (r *udpReplyer) ReplyPDU(i []byte) error {
	conn := r.conn
	_, err := conn.WriteToUDP(i, r.target)
	if err != nil {
		return errors.Wrap(err, "WriteToUDP")
	}
	return nil
}

func (r *udpReplyer) Shutdown() {}

var master = GoSNMPServer.MasterAgent{
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
						counter.Add(1)
						return GoSNMPServer.Asn1TimeTicksWrap(123456788), nil
					},
					Document: "Uptime",
				},
			},
		},
	},
}
