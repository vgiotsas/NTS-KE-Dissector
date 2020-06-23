package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/gob"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/secure-io/siv-go"
	"ntske"
)

type PlainCookie struct {
	Algo uint16
	S2C  []byte
	C2S  []byte
}

func pack(v interface{}) (buf *bytes.Buffer, err error) {
	buf = new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(v)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func (c PlainCookie) Encrypt(key []byte, keyid int) (EncryptedCookie, error) {
	var ecookie EncryptedCookie

	ecookie.ID = uint16(keyid)
	bits := make([]byte, 16)
	_, err := rand.Read(bits)
	if err != nil {
		return ecookie, err
	}
	ecookie.Nonce = bits

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		return ecookie, err
	}

	buf, err := c.Pack()
	if err != nil {
		return ecookie, err
	}

	ecookie.Ciphertext = aessiv.Seal(nil, ecookie.Nonce, buf.Bytes(), nil)

	return ecookie, nil
}

func (c PlainCookie) Pack() (buf *bytes.Buffer, err error) {
	return pack(c)
}

type EncryptedCookie struct {
	ID         uint16
	Nonce      []byte
	Ciphertext []byte
}

func (c EncryptedCookie) Pack() (buf *bytes.Buffer, err error) {
	return pack(c)
}

type Config struct {
	Listen       string
	Certfile     string
	Privatefile  string
	CookieKeyID  int
	CookieSecret string
}

func loadConfig(configfile string) (*Config, error) {
	contents, err := ioutil.ReadFile(configfile)
	if err != nil {
		return nil, err
	}

	conf := new(Config)

	if _, err := toml.Decode(string(contents), &conf); err != nil {
		return nil, err
	}

	return conf, nil
}

func main() {
	var debug bool
	var configfile string

	flag.StringVar(&configfile, "config", "./ntskeserver.toml", "Path to configuration file")
	flag.BoolVar(&debug, "debug", false, "Be more verbose")
	flag.Parse()

	conf, err := loadConfig(configfile)
	if err != nil {
		fmt.Printf("Can't load configuration file. Exiting... %v\n", err)
		os.Exit(1)
	}

	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls12=1")

	certs, err := tls.LoadX509KeyPair(conf.Certfile, conf.Privatefile)
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{
		ServerName:   "localhost",
		NextProtos:   []string{"ntske/1"},
		Certificates: []tls.Certificate{certs},
		CipherSuites: []uint16{
        		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
    },
    MinVersion:               tls.VersionTLS12,
    PreferServerCipherSuites: true,
	}

	listener, err := tls.Listen("tcp", conf.Listen, config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")

	for {
		ke, err := ntske.NewListener(listener)
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}

		go handleClient(ke, conf.CookieKeyID, conf.CookieSecret, debug)
	}
}

func handleClient(ke *ntske.KeyExchange, cookiekeyid int, cookiesecret string, debug bool) {
	err := ke.Read()
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}

	err = ke.ExportKeys()
	if err != nil {
		fmt.Printf("Couldn't export session keys")
		return
	}

	var msg ntske.ExchangeMsg

	// We're speaking NTPv4 next
	var nextproto ntske.NextProto
	nextproto.NextProto = ntske.NTPv4
	msg.AddRecord(nextproto)

	// Using AES SIV for NTS
	var algo ntske.Algorithm
	algo.Algo = []uint16{ntske.AES_SIV_CMAC_256}
	msg.AddRecord(algo)

	// You're supposed to ask this server for time
	var server ntske.Server
	server.Addr = []byte("ntp1.glypnod.com")
	msg.AddRecord(server)

	// On this port
	var port ntske.Port
	port.Port = 123
	msg.AddRecord(port)

	// Here's a cookie.
	var plaincookie PlainCookie

	plaincookie.Algo = ntske.AES_SIV_CMAC_256
	plaincookie.C2S = ke.Meta.C2sKey
	plaincookie.S2C = ke.Meta.S2cKey

	ecookie, err := plaincookie.Encrypt([]byte(cookiesecret), cookiekeyid)
	if err != nil {
		fmt.Printf("Couldn't encrypt cookie: %v\n", err)
		os.Exit(1)
	}

	buf, err := ecookie.Pack()
	if err != nil {
		os.Exit(1)
	}

	var cookie ntske.Cookie
	cookie.Cookie = buf.Bytes()

	msg.AddRecord(cookie)

	// End of Message
	var end ntske.End
	msg.AddRecord(end)

	if debug {
		msg.String()
	}

	buf, err = msg.Pack()
	if err != nil {
		return
	}

	_, err = ke.Conn.Write(buf.Bytes())
	if err != nil {
		fmt.Printf("Write error: %v\n", err)
	}

	log.Println("server: conn: closed")
}
