#!/usr/bin/env python3
"""  
Traverse memory dump, looking for prime factors.  
Author: Einar Otto Stangvik / @einaros / https://hacking.ventures
Environment: Python 3
"""  
import sys, subprocess

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
    
def main(cert_path, data_path):
  mod = get_modulus(cert_path)
  mod = int(mod, 16)
  key_size = int(mod.bit_length() / 16)
  print('Key size: %d'%key_size)
  with open(data_path, 'rb') as f:
    data = f.read()
  print('Data length: %d'%len(data))
  length = len(data) - key_size
  for i in range(length):
    if i % 100000 == 0:
      sys.stdout.write(chr(27) + '[%dG'%(1) + chr(27) + '[0K')
      sys.stdout.write('Progress: %d%%'%(100.0*i/length))
      sys.stdout.flush()
    if data[i] % 2 == 0:
      continue
    p = long(data, i, key_size)
    if p != 0 and p != 1 and p != mod and mod % p == 0:
      sys.stdout.write(chr(27) + '[%dG'%(1) + chr(27) + '[0K')
      print('%s Offset 0x%x: p = %s'%(data_path, i, p))
  sys.stdout.write(chr(27) + '[%dG'%(1) + chr(27) + '[0K')
    
if __name__ == '__main__':
  sys.exit(main(*sys.argv[1:]))
