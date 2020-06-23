package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/alecthomas/kingpin"
	"gitlab.com/hacklunch/ntp"
	// "gitlab.com/hacklunch/ntske"
        "ntske"
)

type Config struct {
	Server   string
	CACert   string
	Interval int
}

func printmeta(meta ntske.Data) {
	fmt.Printf("NTSKE exchange yielded:\n"+
		"  c2s: %x\n"+
		"  s2c: %x\n"+
		"  server: %v\n"+
		"  port: %v\n"+
		"  algo: %v\n",
		string(meta.C2sKey),
		string(meta.S2cKey),
		meta.Server,
		meta.Port,
		meta.Algo,
	)

	fmt.Printf("  %v cookies:\n", len(meta.Cookie))
	for i, cookie := range meta.Cookie {
		fmt.Printf("  #%v: %x\n", i+1, cookie)
	}
}

func loadConfig(configfile string, conf *Config) (*Config, error) {
	contents, err := ioutil.ReadFile(configfile)
	if err != nil {
		return nil, err
	}

	if _, err := toml.Decode(string(contents), &conf); err != nil {
		return nil, err
	}

	return conf, nil
}

func tlsSetup(cacert string, insecure bool) (*tls.Config, error) {
	// Enable experimental TLS 1.3
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=0")

	c := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
                        tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
    			},
    		PreferServerCipherSuites: true,
	}
	if cacert != "" {
		certPool := x509.NewCertPool()
		certs, err := ioutil.ReadFile(cacert)
		if err != nil {
			return nil, fmt.Errorf("read from cacert file %s failed: %v", cacert, err)
		}
		if ok := certPool.AppendCertsFromPEM(certs); !ok {
			return nil, fmt.Errorf("append PEM certs from %s failed: %v", cacert, err)
		}
		c.RootCAs = certPool
	}

	if insecure {
		c.InsecureSkipVerify = true
	}

	return c, nil
}

func keyExchange(server string, c *tls.Config, debug bool) (*ntske.KeyExchange, error) {
	ke, err := ntske.Connect(server, c, debug)
	if err != nil {
		return nil, fmt.Errorf("connection failure to %v: %v", server, err)
	}

	err = ke.Exchange()
	if err != nil {
		return nil, fmt.Errorf("NTS-KE exchange error: %v", err)
	}

	if len(ke.Meta.Cookie) == 0 {
		return nil, fmt.Errorf("received no cookies")
	}

	if ke.Meta.Algo != ntske.AES_SIV_CMAC_256 {
		return nil, fmt.Errorf("unknown algorithm in NTS-KE")
	}

	err = ke.ExportKeys()
	if err != nil {
		return nil, fmt.Errorf("export key failure: %v", err)
	}

	return ke, nil
}

// Needs root or capability to set time. Should probably run in its own process.
func setTime(t time.Time) error {
	tv := syscall.NsecToTimeval(t.UnixNano())
	err := syscall.Settimeofday(&tv)
	if err != nil {
		return err
	}

	return nil
}

const defaultInterval = 1000 // 16m40s
const lowestInterval = 15

func main() {
	var (
		configFlag, serverFlag, caCertFlag string
		intervalFlag                       int
		insecureFlag, dryFlag              bool
		verboseFlag, debugFlag             bool
	)

	help := `Query and set authenticated system time using NTS/NTP.

When running, ntsclient will by default attempt to set the system time.
This requires root or capability.

The options can also be set using environment variables. For example,
"--config" can be set by the environment variable NTSCLIENT_CONFIG. Or
just a server, by setting the variable NTSCLIENT_SERVER. For boolean
flags, use the values "true" or "false".

Options given on the command-line take precedence both over those in
a configuration file, and over environment variables.`

	app := kingpin.New("ntsclient", help).DefaultEnvars()
	app.HelpFlag.Short('h')
	app.Version(versionNumber)
	app.Flag("config", "Path to a configuration file (TOML format)").
		Short('c').StringVar(&configFlag)
	app.Flag("server", "Ask this server about time").
		Short('s').PlaceHolder("HOST:PORT").StringVar(&serverFlag)
	app.Flag("interval", fmt.Sprintf("Interval in seconds between queries, default: %d", defaultInterval)).
		Short('i').PlaceHolder("SECONDS").IntVar(&intervalFlag)
	app.Flag("cacert", "Verify server using CA certificate(s) in file (PEM)").PlaceHolder("FILE").StringVar(&caCertFlag)
	app.Flag("insecure", "Don't verify server certificate").BoolVar(&insecureFlag)
	app.Flag("dry-run", "Don't actually set system time").
		Short('n').BoolVar(&dryFlag)
	app.Flag("verbose", "Turn on verbose output").
		Short('v').BoolVar(&verboseFlag)
	app.Flag("debug", "Turn on debug output").BoolVar(&debugFlag)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	conf := &Config{Interval: defaultInterval}

	// Don't use the default log flags so we don't have any
	// timestamps.
	log.SetFlags(0)

	if configFlag != "" {
		var err error
		conf, err = loadConfig(configFlag, conf)
		if err != nil {
			log.Fatalf("couldn't load configuration file: %v", err)
		}
	}

	// let flags override config file
	if serverFlag != "" {
		conf.Server = serverFlag
	}
	if caCertFlag != "" {
		conf.CACert = caCertFlag
	}
	if intervalFlag > 0 {
		conf.Interval = intervalFlag
	}

	if !debugFlag && time.Duration(conf.Interval)*time.Second < lowestInterval*time.Second {
		log.Fatalf("Refusing polling interval less than %d in non-debug mode", lowestInterval)
	}

	if conf.Server == "" {
		log.Fatalf("No server configured, try --help")
	}

	if debugFlag {
		log.Printf("Conf: %#v\n", conf)
	}

	tlsconfig, err := tlsSetup(conf.CACert, insecureFlag)
	if err != nil {
		log.Fatalf("Couldn't set up TLS: %v", err)
	}

	for {
		ke, err := keyExchange(conf.Server, tlsconfig, debugFlag)
		if err != nil {
			log.Printf("key exchange failed: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if debugFlag {
			printmeta(ke.Meta)
		}

		var opt ntp.QueryOptions
		opt.Port = int(ke.Meta.Port)
		opt.NTS = true
		opt.C2s = ke.Meta.C2sKey
		opt.S2c = ke.Meta.S2cKey
		opt.Cookie = ke.Meta.Cookie[0]
		opt.Debug = debugFlag

		nrcookies := len(ke.Meta.Cookie)

		for n := 0; n < nrcookies; n++ {
			resp, err := ntp.QueryWithOptions(ke.Meta.Server, opt)
			if err != nil {
				log.Printf("NTP query failed: %v", err)
				goto sleep
			}

			if debugFlag {
				log.Printf("response: %#v\n", resp)
			}

			err = resp.Validate()
			if err != nil {
				log.Printf("NTP response validation error: %v", err)
				goto sleep
			}

			if dryFlag || verboseFlag || debugFlag {
				log.Printf("Network time on %v:%v %v. Local clock off by %v.\n",
					ke.Meta.Server, ke.Meta.Port, resp.Time, resp.ClockOffset)
			}
			if !dryFlag {
				err := setTime(time.Now().Add(resp.ClockOffset))
				if err != nil {
					log.Printf("Couldn't set system time: %v", err)
				}
			} else if verboseFlag || debugFlag {
				log.Printf("Dry-run, not setting system time")
			}

		sleep:
			time.Sleep(time.Duration(conf.Interval) * time.Second)
		}
	}
}
