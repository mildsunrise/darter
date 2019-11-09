# READING PRIMITIVES

from struct import unpack, pack


def readcstr(f):
    buf = bytes()
    while True:
        b = f.read(1)
        if b == None: raise Exception('Unexpected EOF')
        if b[0] == 0:
            return bytes(buf)
        buf += b

def readuint(f, bits=64, signed=False):
    if bits == 8: return unpack('b' if signed else 'B', f.read(1))[0]
    x = 0; s = 0
    while True:
        b = f.read(1)[0]
        if b & 0x80: break
        x |= (b & 0x7F) << s
        s += 7
    x |= (b - (0xc0 if signed else 0x80)) << s
    assert s < bits
    #assert x.bit_length() <= bits # stronger assertion (not actually made in dart)
    if x.bit_length() > bits:
        print('--> Int {} longer than {} bits'.format(x, bits))
    return x

def readint(f, bits=64):
    return readuint(f, bits, signed=True)

readcid = lambda f: readint(f, 32)
read1 = lambda f: { 0: False, 1: True}[f.read(1)[0]]
readtokenposition = lambda f: readint(f, 32)

# FIXME: verify these functions work correctly, then change 70 to 64
readfloat  = lambda f: unpack('<f', pack('<I', readuint(f, 32) & ((1<<32)-1)))[0]
readdouble = lambda f: unpack('<d', pack('<Q', readuint(f, 70) & ((1<<64)-1)))[0]

# Other

def read_uleb128(f):
    x = 0; s = 0
    while True:
        b = f.read(1)[0]
        x |= (b & 0x7F) << s
        if not (b & 0x80): break
        s += 7
    return x
