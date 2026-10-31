package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// fakeTor imitates the parts of Tor that ghostshare uses, so daemon and CLI
// tests run the real tor.go code without Tor or a network:
//
//   - a control port: PROTOCOLINFO, AUTHENTICATE, GETINFO, GETCONF,
//     SETEVENTS, ADD_ONION, DEL_ONION, SIGNAL, QUIT
//   - a SOCKS5 proxy that connects "<id>.onion:80" to the local address
//     given in that onion's ADD_ONION Port= argument
//
// Like real Tor, an onion disappears on DEL_ONION or when the control
// connection that created it closes.
type fakeTor struct {
	ctl, socks net.Listener
	authHdr    string // AUTH line of the PROTOCOLINFO reply
	returnKey  bool   // send a PrivateKey even when asked to discard it

	mu     sync.Mutex
	cmds   []string
	onions map[string]string // service ID -> local target address
}

func newFakeTor(t *testing.T, authHdr string) *fakeTor {
	t.Helper()
	ctl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socks, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ft := &fakeTor{ctl: ctl, socks: socks, authHdr: authHdr, onions: map[string]string{}}
	t.Cleanup(func() { ctl.Close(); socks.Close() })
	go acceptLoop(ctl, ft.serveControl)
	go acceptLoop(socks, func(c net.Conn) {
		serveSocks(c, func(host string, port int) (string, bool) {
			id, ok := strings.CutSuffix(host, ".onion")
			if !ok || port != onionPort {
				return "", false
			}
			ft.mu.Lock()
			defer ft.mu.Unlock()
			target, ok := ft.onions[id]
			return target, ok
		})
	})
	return ft
}

func acceptLoop(l net.Listener, handle func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go handle(c)
	}
}

func (ft *fakeTor) controlAddr() string { return ft.ctl.Addr().String() }
func (ft *fakeTor) socksAddr() string   { return ft.socks.Addr().String() }

func (ft *fakeTor) env() torEnv {
	return torEnv{controlAddr: ft.controlAddr(), lookPath: missingTor}
}

func (ft *fakeTor) commands() []string {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return append([]string(nil), ft.cmds...)
}

func (ft *fakeTor) onionCount() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return len(ft.onions)
}

func (ft *fakeTor) serveControl(c net.Conn) {
	var owned, unpublished []string
	defer func() {
		c.Close()
		ft.mu.Lock()
		for _, id := range owned {
			delete(ft.onions, id)
		}
		ft.mu.Unlock()
	}()
	r := bufio.NewReader(c)
	reply := func(s string) { io.WriteString(c, s) }
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		ft.mu.Lock()
		ft.cmds = append(ft.cmds, line)
		ft.mu.Unlock()
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "PROTOCOLINFO":
			reply("250-PROTOCOLINFO 1\r\n250-" + ft.authHdr + "\r\n250-VERSION Tor=\"0.4.8.10\"\r\n250 OK\r\n")
		case "AUTHENTICATE":
			reply("250 OK\r\n")
		case "GETINFO":
			switch strings.Join(f[1:], " ") {
			case "version":
				reply("250-version=0.4.8.10 (git-0123456789abcdef)\r\n250 OK\r\n")
			case "net/listeners/socks":
				reply("250-net/listeners/socks=\"" + ft.socksAddr() + "\"\r\n250 OK\r\n")
			default:
				reply("552 Unrecognized key\r\n")
			}
		case "GETCONF":
			reply("250 DisableNetwork=0\r\n")
		case "SETEVENTS":
			reply("250 OK\r\n")
			if strings.Contains(line, "HS_DESC") {
				for _, id := range unpublished {
					reply("650 HS_DESC UPLOAD " + id + " UNKNOWN $AAAA\r\n")
					reply("650 HS_DESC UPLOADED " + id + " UNKNOWN $AAAA\r\n")
				}
				unpublished = nil
			}
		case "ADD_ONION":
			target := ""
			discard := false
			for _, a := range f[2:] {
				if v, ok := strings.CutPrefix(a, "Port="); ok {
					_, target, _ = strings.Cut(v, ",")
				}
				if v, ok := strings.CutPrefix(a, "Flags="); ok && strings.Contains(v, "DiscardPK") {
					discard = true
				}
			}
			id := newOnionID()
			ft.mu.Lock()
			ft.onions[id] = target
			ft.mu.Unlock()
			owned = append(owned, id)
			unpublished = append(unpublished, id)
			resp := "250-ServiceID=" + id + "\r\n"
			if !discard || ft.returnKey {
				key := make([]byte, 64)
				rand.Read(key)
				resp += "250-PrivateKey=ED25519-V3:" + base64.StdEncoding.EncodeToString(key) + "\r\n"
			}
			reply(resp + "250 OK\r\n")
		case "DEL_ONION":
			if len(f) > 1 {
				ft.mu.Lock()
				delete(ft.onions, f[1])
				ft.mu.Unlock()
			}
			reply("250 OK\r\n")
		case "SIGNAL":
			reply("250 OK\r\n")
		case "QUIT":
			reply("250 closing connection\r\n")
			return
		default:
			reply("510 Unrecognized command\r\n")
		}
	}
}

// newOnionID returns a random 56-character v3 service ID.
func newOnionID() string {
	b := make([]byte, 35)
	rand.Read(b)
	return strings.ToLower(base32.StdEncoding.EncodeToString(b))
}

// serveSocks handles one SOCKS5 CONNECT. The client must send a domain name
// (as curl --socks5-hostname does); resolve maps it to a local address.
func serveSocks(c net.Conn, resolve func(host string, port int) (string, bool)) {
	defer c.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	io.ReadFull(c, make([]byte, hdr[1]))
	c.Write([]byte{5, 0}) // no auth
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[3] != 3 {
		return
	}
	n := make([]byte, 1)
	io.ReadFull(c, n)
	name := make([]byte, n[0])
	io.ReadFull(c, name)
	pb := make([]byte, 2)
	io.ReadFull(c, pb)
	target, ok := resolve(string(name), int(binary.BigEndian.Uint16(pb)))
	if !ok {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // host unreachable
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(up, c)
	io.Copy(c, up)
}

// onionGet fetches a URL through a SOCKS proxy, like Tor Browser would.
// ok is false when the onion could not be reached at all.
func onionGet(t *testing.T, socks, link string) (code int, body string, ok bool) {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext:       d.(proxy.ContextDialer).DialContext,
		DisableKeepAlives: true,
	}}
	resp, err := c.Get(link)
	if err != nil {
		return 0, "", false
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b), true
}

// linkParts splits http://<onion>/<token>/<name>.
func linkParts(t *testing.T, link string) (onion, token string) {
	t.Helper()
	rest, ok := strings.CutPrefix(link, "http://")
	parts := strings.Split(rest, "/")
	if !ok || len(parts) != 3 || !strings.HasSuffix(parts[0], ".onion") || len(parts[0]) != 56+len(".onion") {
		t.Fatalf("%q is not an http://<v3>.onion/<token>/<file> link", link)
	}
	return parts[0], parts[1]
}
