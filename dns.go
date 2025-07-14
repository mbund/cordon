package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sync"

	"github.com/miekg/dns"
)

type DNSManager struct {
	messages []*dns.Msg
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func NewDNSManager() *DNSManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &DNSManager{
		messages: make([]*dns.Msg, 0, 256),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (dm *DNSManager) StartListeners() error {
	var err error

	defer func() {
		if err != nil {
			dm.cancel()
			dm.wg.Wait()
		}
	}()

	connIPv4UDP, err := net.ListenPacket("ip4:udp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("failed to create raw UDP IPv4 socket: %w", err)
	}
	dm.wg.Add(1)
	go func() {
		defer func() {
			connIPv4UDP.Close()
			dm.wg.Done()
		}()
		dm.handleUDPPackets(connIPv4UDP)
	}()

	connIPv6UDP, err := net.ListenPacket("ip6:udp", "::")
	if err != nil {
		return fmt.Errorf("failed to create raw UDP IPv6 socket: %w", err)
	}
	dm.wg.Add(1)
	go func() {
		defer func() {
			connIPv6UDP.Close()
			dm.wg.Done()
		}()
		dm.handleUDPPackets(connIPv6UDP)
	}()

	connIPv4TCP, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("failed to create raw TCP IPv4 socket: %w", err)
	}
	dm.wg.Add(1)
	go func() {
		defer func() {
			connIPv4TCP.Close()
			dm.wg.Done()
		}()
		dm.handleTCPPackets(connIPv4TCP)
	}()

	connIPv6TCP, err := net.ListenPacket("ip6:tcp", "::")
	if err != nil {
		return fmt.Errorf("failed to create raw TCP IPv6 socket: %w", err)
	}
	dm.wg.Add(1)
	go func() {
		defer func() {
			connIPv6TCP.Close()
			dm.wg.Done()
		}()
		dm.handleTCPPackets(connIPv6TCP)
	}()

	slog.Info("DNS Manager listening...")

	return nil
}

func (dm *DNSManager) Close() {
	dm.cancel()
	dm.wg.Wait()
	slog.Info("Closed DNS Manager")
}

func (dm *DNSManager) handleUDPPackets(conn net.PacketConn) {
	buffer := make([]byte, 4096)
	errChan := make(chan error, 1)
	dataChan := make(chan []byte)

	for {
		go func() {
			n, _, err := conn.ReadFrom(buffer)
			if err != nil {
				errChan <- err
				return
			}
			data := make([]byte, n)
			copy(data, buffer[:n])
			dataChan <- data
		}()

		select {
		case <-dm.ctx.Done():
			return
		case err := <-errChan:
			if err != nil {
				return
			}
		case data := <-dataChan:
			if len(data) < 8 {
				continue
			}

			// Parse UDP header
			srcPort := binary.BigEndian.Uint16(data[0:2])
			dstPort := binary.BigEndian.Uint16(data[2:4])

			if srcPort != 53 && dstPort != 53 {
				continue
			}

			// Skip UDP header (8 bytes) to get DNS data
			dnsData := data[8:]
			if len(dnsData) < 12 {
				continue
			}

			msg := new(dns.Msg)
			if err := msg.Unpack(dnsData); err != nil {
				continue
			}

			if msg.Response {
				dm.messages = append(dm.messages, msg)
			}
		}
	}
}

func (dm *DNSManager) handleTCPPackets(conn net.PacketConn) {
	buffer := make([]byte, 4096)
	errChan := make(chan error, 1)
	dataChan := make(chan []byte)

	for {
		go func() {
			n, _, err := conn.ReadFrom(buffer)
			if err != nil {
				errChan <- err
				return
			}
			data := make([]byte, n)
			copy(data, buffer[:n])
			dataChan <- data
		}()

		select {
		case <-dm.ctx.Done():
			return
		case err := <-errChan:
			if err != nil {
				return
			}
		case data := <-dataChan:
			if len(data) < 20 {
				continue
			}

			// Parse TCP header
			srcPort := binary.BigEndian.Uint16(data[0:2])
			dstPort := binary.BigEndian.Uint16(data[2:4])

			if srcPort != 53 && dstPort != 53 {
				continue
			}

			// Calculate TCP header length
			tcpHeaderLen := int((data[12] >> 4) * 4)
			if tcpHeaderLen < 20 || len(data) < tcpHeaderLen {
				continue
			}

			// Get TCP payload
			tcpPayload := data[tcpHeaderLen:]
			if len(tcpPayload) < 14 { // 2 bytes length + 12 bytes DNS header minimum
				continue
			}

			// TCP DNS messages are prefixed with 2-byte length
			msgLen := binary.BigEndian.Uint16(tcpPayload[0:2])
			if len(tcpPayload) < int(msgLen)+2 {
				continue
			}

			msg := new(dns.Msg)
			if err := msg.Unpack(tcpPayload[2 : 2+msgLen]); err != nil {
				continue
			}

			if msg.Response {
				dm.messages = append(dm.messages, msg)
			}
		}
	}
}

type systemdResolvedCache []struct {
	Protocol string `json:"protocol"`
	Family   int    `json:"family,omitempty"`
	Ifindex  int    `json:"ifindex,omitempty"`
	Ifname   string `json:"ifname,omitempty"`
	Cache    []struct {
		Key struct {
			Class int    `json:"class"`
			Type  uint16 `json:"type"`
			Name  string `json:"name"`
		} `json:"key"`
		RRs []struct {
			RR struct {
				Key struct {
					Class int    `json:"class"`
					Type  uint16 `json:"type"`
					Name  string `json:"name"`
				} `json:"key"`
				Address []byte `json:"address"`
			} `json:"rr"`
			Raw string `json:"raw"`
		} `json:"rrs"`
		Until int64 `json:"until"`
	} `json:"cache"`
}

func (dm *DNSManager) parseSystemdResolvedCache() []*dns.Msg {
	resolvectl, err := exec.LookPath("resolvectl")
	if err != nil {
		return nil
	}

	output, err := exec.Command(resolvectl, "show-cache", "--json=short").Output()
	if err != nil {
		return nil
	}

	var cache systemdResolvedCache
	if err := json.Unmarshal(output, &cache); err != nil {
		return nil
	}

	var messages []*dns.Msg

	for _, entry := range cache {
		if entry.Protocol != "dns" {
			continue
		}

		for _, record := range entry.Cache {
			msg := new(dns.Msg)
			msg.Response = true
			msg.Answer = make([]dns.RR, 0, len(record.RRs))

			question := dns.Question{
				Name:   dns.Fqdn(record.Key.Name),
				Qtype:  record.Key.Type,
				Qclass: uint16(record.Key.Class),
			}
			msg.Question = []dns.Question{question}

			for _, rr := range record.RRs {
				var answer dns.RR

				switch rr.RR.Key.Type {
				case dns.TypeA:
					if len(rr.RR.Address) != 4 {
						continue
					}
					r := new(dns.A)
					r.Hdr = dns.RR_Header{
						Name:   dns.Fqdn(rr.RR.Key.Name),
						Rrtype: dns.TypeA,
						Class:  uint16(rr.RR.Key.Class),
						Ttl:    3600, // Default TTL
					}
					r.A = net.IP(rr.RR.Address)
					answer = r

				case dns.TypeAAAA:
					if len(rr.RR.Address) != 16 {
						continue
					}
					r := new(dns.AAAA)
					r.Hdr = dns.RR_Header{
						Name:   dns.Fqdn(rr.RR.Key.Name),
						Rrtype: dns.TypeAAAA,
						Class:  uint16(rr.RR.Key.Class),
						Ttl:    3600, // Default TTL
					}
					r.AAAA = net.IP(rr.RR.Address)
					answer = r
				}

				if answer != nil {
					msg.Answer = append(msg.Answer, answer)
				}
			}

			if len(msg.Answer) > 0 {
				messages = append(messages, msg)
			}
		}
	}

	return messages
}

func (dm *DNSManager) checkRecordsForIP(records []dns.RR, ip net.IP, domains map[string]struct{}) {
	for _, rr := range records {
		switch record := rr.(type) {
		case *dns.A:
			if record.A.Equal(ip) {
				domains[record.Hdr.Name] = struct{}{}
			}
		case *dns.AAAA:
			if record.AAAA.Equal(ip) {
				domains[record.Hdr.Name] = struct{}{}
			}
		}
	}
}

func (dm *DNSManager) ReverseLookup(ip net.IP) []string {
	domains := make(map[string]struct{})

	cache := dm.parseSystemdResolvedCache()
	for _, msg := range cache {
		dm.checkRecordsForIP(msg.Answer, ip, domains)
	}

	for _, msg := range dm.messages {
		dm.checkRecordsForIP(msg.Answer, ip, domains)
	}

	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}

	return result
}
