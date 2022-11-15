// Copyright 2015 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	addrrx   = flag.String("rx", "", "http service address")
	addrtx   = flag.String("tx", "", "http service address")
	certaddr = flag.String("cg", "", "http service address")
	c        = flag.Bool("c", false, "client mode")
	s        = flag.Bool("s", false, "server mode")

	lastpong    = time.Now()
	lastwsrecv  = time.Now()
	lastwssend  = time.Now()
	lastudprecv = time.Now()
	lastudpsend = time.Now()
)

func resolve(addrtx *string) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
				Control: control,
			}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}
	host, port, _ := net.SplitHostPort(*addrtx)
	addrs, err := r.LookupHost(context.TODO(), host)
	if err != nil || len(addrs) == 0 {
		log.Error().Msgf("cannot get ip for txaddr %s %s", err, addrs)
		os.Exit(1)
	}
	*addrtx = net.JoinHostPort(addrs[0], port)
	log.Debug().Str("ipport", *addrtx).Msgf("the address has been resolved")
}
func control(_, _ string, cc syscall.RawConn) error {
	return cc.Control(func(fd uintptr) {
		fmt.Println(syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 52240))
	})

}

func main() {
	flag.Parse()
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	log.Level(zerolog.TraceLevel)
	if *c {
		if *addrrx == "" {
			*addrrx = "[::]:1050"
		}
		if *addrtx == "" {
			*addrtx = "hn.karmanyaah.malhotra.cc:15321"
		}

		client()
	} else if *s {
		if *addrrx == "" {
			*addrrx = "[::]:15321"
		}
		if *addrtx == "" {
			*addrtx = "localho.st:1051" //"hn.malhotra.cc:1050"
		}
		if *certaddr == "" {
			*certaddr = *addrrx
		}

		resolve(addrtx)
		server()
	} else {
		log.Print("PICK -c or -s")
		os.Exit(1)
	}
}

func wsclient() (toserv chan []byte, tome chan []byte, err error) {
	toserv = make(chan []byte)
	tome = make(chan []byte)

	u := url.URL{Scheme: "wss", Host: *addrtx, Path: "/echo"}

	d := websocket.DefaultDialer
	d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, ServerName: *certaddr}
	d.NetDial = func(network, addr string) (net.Conn, error) {
		resolve(&addr)
		return (&net.Dialer{Control: control}).Dial(network, addr)
	}

	go func() {
		for {
			restarting := false
			log.Info().Msgf("connecting to %s", u.String())
			c, _, err := d.Dial(u.String(), nil)
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			log.Info().Msgf("connected to %s", u.String())

			lastpong = time.Now().Add(3 * time.Second) // give some time to establish bc y not
			c.SetPongHandler(func(appData string) error {
				lastpong = time.Now()
				return nil
			})

			go func() {
				ticker := time.NewTicker(1 * time.Second)
				for {
					var err error
					select {
					case f, openchan := <-toserv:
						if !openchan {
							err = errors.New("toserv chan closed")
						}

						lastwssend = time.Now()
						err = c.WriteMessage(websocket.BinaryMessage, f)

					case <-ticker.C:
						err = c.WriteMessage(websocket.PingMessage, []byte{})
						log.Print(lastpong.Local().Format("15:04:05"), lastwsrecv.Local().Format("15:04:05"), lastwssend.Local().Format("15:04:05"), lastudprecv.Local().Format("15:04:05"), lastudpsend.Local().Format("15:04:05"))
						if lastpong.Before(time.Now().Add(-4 * time.Second)) {
							err = errors.New("No ping reply for 4 seconds")
						}
					default:
						if restarting {
							return
						} else {
							time.Sleep(5 * time.Millisecond)
						} // TODO better more efficient checking, faster
					}
					if err != nil {
						log.Print("write:", err, "restarting")
						restarting = true
						return
					}
				}
			}()

			go func() {
				for {
					if restarting {
						return
					}

					_, msg, err := c.ReadMessage()
					if err != nil {
						log.Print("WS RECEIVE ERR CLIENT", err)
						restarting = true
						continue
					}
					lastwsrecv = time.Now()
					tome <- msg
				}
			}()

			for !restarting {
				time.Sleep(time.Second)
			}
			log.Print("restarting started")
			c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			c.Close()
			log.Print("restarting closed")

			select {
			case _, open := <-toserv:
				if !open {
					close(tome)
					log.Print("restarting shutting down")
					return
				}
			case <-time.After(time.Second):
				continue
			}
		}

	}()

	return
}

type udpMsg struct {
	source  netip.AddrPort
	content []byte
}

func NewUDPMessage(b []byte) *udpMsg {
	bef, after, found := bytes.Cut(b, []byte(" "))
	if !found {
		log.Print("err sep not found")
		return nil
	}

	ap, err := netip.ParseAddrPort(string(bef))
	if err != nil {
		log.Print("Unable to parse addrport", err)
		return nil
	}
	return &udpMsg{source: ap, content: after}
}

func (u udpMsg) Serialize() []byte {
	return append([]byte(u.source.String()+" "), u.content...)
}

func listener() (fromclient chan udpMsg, toclient chan udpMsg, err error) {
	fromclient = make(chan udpMsg)
	toclient = make(chan udpMsg)
	closeme := make(chan struct{})

	uconn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(*addrrx)))
	if err != nil {
		log.Fatal().Err(err).Msg("cant listen")
	}

	go func() {
		stuff := [1e4]byte{}
		for {
			select {
			case <-closeme:
				close(fromclient)
				uconn.Close()
				return
			default:
				n, addr, err := uconn.ReadFromUDPAddrPort(stuff[:])
				log.Print(n, addr, err)
				lastudprecv = time.Now()
				if n != 0 {
					log.Print("sending udp to chan")
					fromclient <- udpMsg{addr, stuff[:n]}
					log.Print("sent udp to chan")
				}
				if err != nil {
					log.Print("UDP GOROUTINE CLIENT", err)
					break
				}
			}
		}

	}()

	go func() {
		for {
			select {
			case <-closeme:
				return
			case content, open := <-toclient:
				log.Print("gottoclient pt2")
				if !open {
					close(closeme)
				}
				_, err := uconn.WriteToUDPAddrPort(content.content, content.source)
				lastudpsend = time.Now()
				if err != nil {
					log.Print("udp write:", err)
					return
				}
			}
		}
	}()

	return
}

func client() {
	//log.Logger = log.Level(zerolog.InfoLevel)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	toserv, tome, err := wsclient()
	if err != nil {
		log.Fatal().Err(err).Msg("wsclient")
	}

	fromclient, toclient, err := listener()

	for {
		select {
		case p := <-fromclient:
			log.Trace().Msg("gotfromclient")
			toserv <- p.Serialize()
			log.Trace().Msg("donefromclient")
		case p := <-tome:
			log.Trace().Msg("gottome")
			toclient <- *NewUDPMessage(p)
			log.Trace().Msg("donetome")
		case <-interrupt:
			log.Error().Msg("interrupt")

			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			close(toserv)
			close(toclient)
			//select {
			////case _, c:=<-fromclient ; _,d:=<-tome; !(c || d):
			//case <-time.After(time.Second):
			//}
			return
		}
	}
}

var upgrader = websocket.Upgrader{} // use default options

func echo(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)
		}
	}()
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Info().Msgf("upgrade: %s", err)
		return
	}

	//uc := bytes.NewBufferString("A")
	uc, err := net.DialUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[::]:0")), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(*addrtx)))
	if err != nil {
		log.Error().Msgf("CANNOT DIAL UDP %s", err)
	}
	closed := false
	var bef []byte

	go func() { // only after first write
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Recovered in f", r)
				debug.PrintStack()
			}
		}()
		readstuff := [10000]byte{}
		for {
			if closed {
				break
			}
			log.Trace().Int("readstuffslicelen", len(readstuff[100+1:])).Msgf("wait to read udp msg")

			n, err := uc.Read(readstuff[100+1:]) // todo ReadFrom and match addr???
			copy(readstuff[100-len(bef):100], bef)
			readstuff[100] = []byte(" ")[0]
			log.Trace().Msg(string(readstuff[0:200]))

			log.Trace().Msgf("read msg from udp %d %s", n, err)
			if err != nil {
				log.Error().Msgf("UDP LISTEN SERVER %s", err)
				break
			}
			err = c.WriteMessage(websocket.BinaryMessage, readstuff[100-len(bef):100+1+n])
			if err != nil {
				log.Print("write:", err)
				break
			}
		}

	}()

	for {
		_, message, err := c.ReadMessage()
		log.Trace().Msg("read msg from ws")
		if err != nil {
			log.Print("read:", err)
			break
		}
		var after []byte
		var found bool
		bef, after, found = bytes.Cut(message, []byte(" "))
		if !found {
			log.Print("err sep not found")
			continue
		}
		n, err := uc.Write(after)
		log.Trace().Err(err).Int("len", n).Msgf("write msg to udpconn err %s", err)

		//log.Printf("recv: %s %s", bef, after)

	}

	log.Print("CLOSING WS CONN")
	closed = true
	uc.Close()

}

func server() {
	cert, err := GenX509KeyPair()
	if err != nil {
		log.Fatal().Err(err).Msg("cant gen cert")
	}
	tlsconfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	server := http.Server{Addr: *addrrx, TLSConfig: tlsconfig}
	http.HandleFunc("/echo", echo)
	log.Info().Msg("starting server")
	log.Fatal().Err(server.ListenAndServeTLS("", ""))
}

// https://gist.github.com/shivakar/cd52b5594d4912fbeb46
// GenX509KeyPair generates the TLS keypair for the server
func GenX509KeyPair() (tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:         *certaddr,
			Country:            []string{"USA"},
			Organization:       []string{"example.com"},
			OrganizationalUnit: []string{"quickserve"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 9), // Valid for one day
		SubjectKeyId:          []byte{113, 117, 105, 99, 107, 115, 101, 114, 118, 101},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return outCert, nil
}
