
# NTS-KE Wireshark Dissector

The `ntpke-dissector.lua` is a Wireshark dissector written in Lua to parse NTS-KE (Network Time Security Key Establishment) messages that conform to the [IETF Draft Version 28](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-28#section-4). 

## Testing the dissector

To test the dissector you can use the sample pcapng files inside the `pcap` directory. Since the NTS-KE messages are exchanged over TLS, the messages need to be decrypted. The `pcap` files have the secret keys embedded to enable viewing the NTS-KE paylod.

The `pcap/go-embedded.pcang` file has been made available by Marco davids at [https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16222](https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16222)

The `pcap/ntske.pcapng` file has been created using [gonts](https://gitlab.com/hacklunch/gonts), an NTS-KE implementation by Daniel Lublin.

Apart from the official Wireshark [documentation on TLS](https://wiki.wireshark.org/TLS#Transport_Layer_Security_.28TLS.29), the following two presentations helped me to learn how to embed TLS keys in a Wireshark pcapng file:

- Peter Wu, [SSL/TLS Decryption uncovering secrets](https://lekensteyn.nl/files/wireshark-ssl-tls-decryption-secrets-sharkfest18eu.pdf),  SharkFest ’18 Europe.
- Sake Blok, [I Spy, with My Little Eye, Something Inside TLS! ... overcoming TLS decrypting challenges](https://suricon.net/wp-content/uploads/2019/11/SURICON2019_I-Spy-with-My-Little-Eye-Something-Inside-TLS.pdf) SURICON 2019 Amsterdam.

### Details on generating decrypted NTS-KE traces

#### Basic configuration of NTS-KE client and server

First, I installed the [ntsclient](https://gitlab.com/hacklunch/ntsclient) and [ntskeserver](https://gitlab.com/hacklunch/ntskeserver). Both are installed in the same machine, so the NTS-KE queries and responses are both from the localhost. For the server I generated a new private key and certificate with the following command:
 
 ```bash
  openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
 ```

Then I updated the [ntskeserver.toml](https://github.com/vgiotsas/NTS-KE-Dissector/blob/master/testing/ntskeserver/ntskeserver.toml) and  [ntsclient.toml](https://github.com/vgiotsas/NTS-KE-Dissector/blob/master/testing/ntsclient/ntsclient.toml) configuration files of the server and the client to point to the correct keys and server addresses. 

#### Changes to client and server TLS configuration to enable Wireshark to decrypt the traffic

For Wireshark to decrypt TLS traffic we need to provide either the RSA private key, or the key log file with the per-session secrets. to capture the pre-session secrets for applications that use *openssl* we can set the SSLKEYLOGFILE environment variable to the path of the file in which the keys will be logged. However, the *tls* library of *go* does not use openssl, so this technique is not applicable.

The first workaround I followed was to use the private RSA key of the server to decrypt the TLS traffic. Nonetheless, this approach has to major limitations:

* The cipher suite selected by the server is not using (EC)DHE.
* It does _not_ work with TLS 1.3.

Therefore, I needed to override the default TLS configuration used by the NTS-KE server in [main.go#L121](https://github.com/vgiotsas/NTS-KE-Dissector/blob/master/testing/ntskeserver/main.go#L121) and client in [client.go#L63](https://github.com/vgiotsas/NTS-KE-Dissector/blob/master/testing/ntsclient/client.go#L63). For example, I've set the client configuration as follows:

```
c := &tls.Config{
    MinVersion: tls.VersionTLS12,
    MaxVersion: tls.VersionTLS12,
    CipherSuites: []uint16{
        tls.TLS_RSA_WITH_AES_128_CBC_SHA256
    },
    PreferServerCipherSuites: true,
}
```
I also updated the server script to set the address of the NTP server that the NTS-KE server will contact ([main.go#L176](https://github.com/vgiotsas/NTS-KE-Dissector/blob/master/testing/ntskeserver/main.go#L176)). 

The last change to the NTS-KE server and client is to change the import of the `ntske` library from `"gitlab.com/hacklunch/ntske"` to a local module so I can change the format of the NTS-KE messages to generate malformed messages and test some error checking features of the dissector.
 
Then I re-built both server and client, and I start the server which listens at `127.0.0.1:4403`.

To verify that indeed the desired TLS version and cipher are used:
`openssl s_client -connect 127.0.0.1:4430`

Finally, I issued an NTS client request as follows:

`./ntsclient --config ntsclient.toml --debug --insecure`

Note the use of the `--insecure` which is required since the keys are self-signed.

#### Generating a Wireshark pcapng file with embedded decryption secrets 

As explained in the [documentation](https://wiki.wireshark.org/TLS#Embedding_decryption_secrets_in_a_pcapng_file), to generate a  pcapng file with the decryption secrets embedded, only (pre-) master secrets can be used.

So after capturing the traffic, I first imported the pem private key:
`Edit --> Preferences... --> RSA Keys --> Add new keyfile...`

Then I exported the TLS Session Keys in a text file:
`File --> Export TLS Session Keys`

This file has the (pre-) master secrets in the required NSS format. 

Finally,  embeded the decryption secrets in a pcapng file using editcap:

`editcap --inject-secrets tls,session-keys.keys inputnle-dsb.pcapng ntske-sample-dsb2.pcapng`

## Development Notes

This was the first time I wrote a dissector for Wireshark, so as an introduction to the topic I followed Graham Bloice's [presentation](https://www.youtube.com/watch?v=Fp_7g5as1VY) at Sharkfest'18. This presentation summarizes the different methods to develop a dissector and suggests that a Lua iimplementation offers a good tradeoff
between offering advanced features and quick development. So I decided to develop the dissector with Lua.

Since I've never worked before with Lua, I started with a relatively simple [tutorial](https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html) on implementing a Lua dissector for the MongoDB wire protocol to get familiar with the language syntax and the Wireshark API.

I then spent some time studying the official [Lua examples](https://wiki.wireshark.org/Lua/Examples#A_dissector_tutorial_script) and especially the [DNS dissectory](https://wiki.wireshark.org/Lua/Examples?action=AttachFile&do=get&target=dissector.lua).
I also found very useful Wireshark’s Lua API Reference Manual, especially section [11.6: Functions For New Protocols And Dissectors](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html). 

Unfortunately, after I finished developing the dissector [I realized](https://ask.wireshark.org/question/17368/can-i-submit-a-lua-dissector-to-code-review/) only C/C++ dissectors can be submitted for code review and be accepted to the codebase. So in retrospect, while it's fast to develop in Lua, developing a C/C++ dissector would be more meaningful in terms of contributing back to the project.

### TODOs

* Improve error handling: Some potential errors in the protocol messages are currently unchecked. For instance, client must not send "New Cookie for NTPv4" messages.
* Port the Lua dissector to C++
* Produce more test cases

## Author

Vasileios Giotsas giotsas@gmail.com


