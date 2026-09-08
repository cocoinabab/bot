//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	windivertLayerNetwork = 0
	maxPacketSize         = 0xFFFF
	windivertAddressSize  = 80
)

var raknetMagicV4 = []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78}

type endpoint struct {
	IP   string
	Port uint16
}

func (e endpoint) String() string { return net.JoinHostPort(e.IP, strconv.Itoa(int(e.Port))) }

type sessionMapping struct {
	Client   endpoint
	Target   endpoint
	IfIdx    uint32
	SubIfIdx uint32
	Last     time.Time
}

type redirector struct {
	dll       *syscall.LazyDLL
	open      *syscall.LazyProc
	recv      *syscall.LazyProc
	send      *syscall.LazyProc
	closeFn   *syscall.LazyProc
	checksums *syscall.LazyProc
	h         syscall.Handle
	port      uint16
	al        *appLogger

	mu     sync.RWMutex
	active *sessionMapping
	closed chan struct{}
	once   sync.Once
}

func newRedirector(proxyPort uint16, al *appLogger) (*redirector, error) {
	dll := syscall.NewLazyDLL("WinDivert.dll")
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("cannot load WinDivert.dll: %w", err)
	}
	r := &redirector{
		dll:       dll,
		open:      dll.NewProc("WinDivertOpen"),
		recv:      dll.NewProc("WinDivertRecv"),
		send:      dll.NewProc("WinDivertSend"),
		closeFn:   dll.NewProc("WinDivertClose"),
		checksums: dll.NewProc("WinDivertHelperCalcChecksums"),
		port:      proxyPort,
		al:        al,
		closed:    make(chan struct{}),
	}
	// Restrict active diversion to the normal Bedrock ports plus replies from our local proxy.
	// Non-client packets matching this filter (including the proxy's own upstream RakNet traffic) are reinjected unchanged.
	filter := fmt.Sprintf("outbound and udp and (udp.DstPort == 19132 or udp.DstPort == 19133 or udp.SrcPort == %d)", proxyPort)
	fp, _ := syscall.BytePtrFromString(filter)
	h, _, e1 := r.open.Call(uintptr(unsafe.Pointer(fp)), uintptr(windivertLayerNetwork), uintptr(0), uintptr(0))
	if h == 0 || h == ^uintptr(0) {
		if e1 != syscall.Errno(0) {
			return nil, e1
		}
		return nil, errors.New("WinDivertOpen failed; run as Administrator")
	}
	r.h = syscall.Handle(h)
	return r, nil
}

func (r *redirector) Close() {
	r.once.Do(func() {
		close(r.closed)
		if r.h != 0 {
			r.closeFn.Call(uintptr(r.h))
		}
	})
}

func (r *redirector) TargetForClient(addr string) (endpoint, bool) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return endpoint{}, false
	}
	p64, _ := strconv.ParseUint(portStr, 10, 16)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return endpoint{}, false
	}
	if r.active.Client.IP == host && r.active.Client.Port == uint16(p64) {
		return r.active.Target, true
	}
	return endpoint{}, false
}

func (r *redirector) Run() {
	buf := make([]byte, maxPacketSize)
	for {
		select {
		case <-r.closed:
			return
		default:
		}
		var recvLen uint32
		var addr [windivertAddressSize]byte
		ok, _, e1 := r.recv.Call(
			uintptr(r.h),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
		if ok == 0 {
			select {
			case <-r.closed:
				return
			default:
			}
			if e1 != syscall.Errno(0) {
				r.al.printf("[DIVERT-RECV-ERR] %v", e1)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		pkt := buf[:int(recvLen)]
		u, valid := parseIPv4UDP(pkt)
		if !valid {
			r.reinject(pkt, &addr, false)
			continue
		}

		// Local proxy -> Minecraft client. Make it appear as if it came from the original remote server.
		if u.Src.Port == r.port {
			r.mu.RLock()
			m := cloneMapping(r.active)
			r.mu.RUnlock()
			if m != nil && u.Dst == m.Client {
				if rewriteIPv4UDP(pkt, m.Target.IP, u.Dst.IP, m.Target.Port, u.Dst.Port) {
					setAddrOutbound(&addr, false)
					setAddrInterface(&addr, m.IfIdx, m.SubIfIdx)
					r.reinject(pkt, &addr, true)
					continue
				}
			}
			r.reinject(pkt, &addr, false)
			continue
		}

		// Detect only the first active vanilla-client OpenConnectionRequest1. While a session is active,
		// any other RakNet source is the proxy's own upstream connection and must pass unchanged.
		r.mu.Lock()
		if r.active != nil && time.Since(r.active.Last) > 45*time.Second {
			r.active = nil
		}
		m := r.active
		if m == nil && isOpenConnectionRequest1(u.Payload) {
			m = &sessionMapping{
				Client:   u.Src,
				Target:   u.Dst,
				IfIdx:    binary.LittleEndian.Uint32(addr[16:20]),
				SubIfIdx: binary.LittleEndian.Uint32(addr[20:24]),
				Last:     time.Now(),
			}
			r.active = m
			r.al.printf("[NAT] detected Minecraft session client=%s target=%s", m.Client.String(), m.Target.String())
		}
		if m != nil && u.Src == m.Client && u.Dst == m.Target {
			m.Last = time.Now()
			localIP := m.Client.IP
			r.mu.Unlock()
			// Redirect to a UDP listener on this machine while preserving the client's source endpoint.
			if rewriteIPv4UDP(pkt, m.Client.IP, localIP, m.Client.Port, r.port) {
				setAddrOutbound(&addr, true)
				r.reinject(pkt, &addr, true)
				continue
			}
			r.reinject(pkt, &addr, false)
			continue
		}
		r.mu.Unlock()

		// Proxy upstream traffic and unrelated matching UDP must continue normally.
		r.reinject(pkt, &addr, false)
	}
}

func cloneMapping(m *sessionMapping) *sessionMapping {
	if m == nil {
		return nil
	}
	c := *m
	return &c
}

func (r *redirector) reinject(pkt []byte, addr *[windivertAddressSize]byte, modified bool) {
	if len(pkt) == 0 {
		return
	}
	if modified {
		// Clear checksum-valid bits before recalculation, then let WinDivert update them.
		clearAddrChecksumBits(addr)
		r.checksums.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(&addr[0])), uintptr(0))
	}
	var sent uint32
	ok, _, e1 := r.send.Call(
		uintptr(r.h),
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&sent)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
	if ok == 0 && e1 != syscall.Errno(0) {
		r.al.printf("[DIVERT-SEND-ERR] %v", e1)
	}
}

func setAddrOutbound(addr *[windivertAddressSize]byte, outbound bool) {
	flags := binary.LittleEndian.Uint64(addr[8:16])
	const bit = uint64(1) << 17
	if outbound {
		flags |= bit
	} else {
		flags &^= bit
	}
	binary.LittleEndian.PutUint64(addr[8:16], flags)
}

func clearAddrChecksumBits(addr *[windivertAddressSize]byte) {
	flags := binary.LittleEndian.Uint64(addr[8:16])
	flags &^= (uint64(1) << 21) | (uint64(1) << 22) | (uint64(1) << 23)
	binary.LittleEndian.PutUint64(addr[8:16], flags)
}

func setAddrInterface(addr *[windivertAddressSize]byte, ifIdx, subIfIdx uint32) {
	binary.LittleEndian.PutUint32(addr[16:20], ifIdx)
	binary.LittleEndian.PutUint32(addr[20:24], subIfIdx)
}

type parsedUDP struct {
	Src, Dst endpoint
	Payload  []byte
	IHL      int
}

func parseIPv4UDP(pkt []byte) (parsedUDP, bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return parsedUDP{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return parsedUDP{}, false
	}
	src := net.IP(pkt[12:16]).String()
	dst := net.IP(pkt[16:20]).String()
	sp := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	dp := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	udpLen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
	end := len(pkt)
	if udpLen >= 8 && ihl+udpLen <= len(pkt) {
		end = ihl + udpLen
	}
	return parsedUDP{Src: endpoint{src, sp}, Dst: endpoint{dst, dp}, Payload: pkt[ihl+8 : end], IHL: ihl}, true
}

func rewriteIPv4UDP(pkt []byte, srcIP, dstIP string, srcPort, dstPort uint16) bool {
	u, ok := parseIPv4UDP(pkt)
	if !ok {
		return false
	}
	sip := net.ParseIP(srcIP).To4()
	dip := net.ParseIP(dstIP).To4()
	if sip == nil || dip == nil {
		return false
	}
	copy(pkt[12:16], sip)
	copy(pkt[16:20], dip)
	binary.BigEndian.PutUint16(pkt[u.IHL:u.IHL+2], srcPort)
	binary.BigEndian.PutUint16(pkt[u.IHL+2:u.IHL+4], dstPort)
	return true
}

func isOpenConnectionRequest1(payload []byte) bool {
	return len(payload) >= 1+len(raknetMagicV4) && payload[0] == 0x05 && bytes.Contains(payload, raknetMagicV4)
}
