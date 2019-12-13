import re
import capstone as cs
from capstone.arm64 import *

supports = lambda _, arch: arch == 'arm64'
make_engine = lambda _: cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)

find_register = lambda op, reg: re.search(r'(\W|^)' + reg + r'(\W|$)', op[3], flags=re.ASCII)
int_opt = lambda x: 0 if x is None else int(x, 0)

def match_nref(ops, i):
    if find_register(ops[i], 'x27'):
        res = match_loadobj(ops, i)
        if res is None:
            # print('Couldn\'t extract 0x{:x}: {} {}'.format(ops[i][0], ops[i][2], ops[i][3])) # FIXME: proper logging
            return
        i, offset, reg = res
        div, mod = divmod(offset, 8)
        assert mod == 0
        return i, 'load', div - 2, reg
    if ops[i][2] == 'bl':
        return i+1, 'call', int(ops[i][3][1:], 0)

def match_loadobj(ops, i):
    m = None
    def match(name, pattern, func=lambda: True, mov=1):
        nonlocal m, i
        if not (0 <= i < len(ops) and ops[i][2] == name): return
        r = re.fullmatch(pattern, ops[i][3], flags=re.ASCII)
        if r is None: return
        m = r.groups()
        if not func(): return
        i += mov
        return True

    if match('add', r'(\w+), x27, \1'):
        src = m[0]
        if not match('ldr', r'(\w+), \[(\w+)\]', lambda: m[1] == src): return
        target = m[0]
        orig_i, i = i, i-3
        if match('orr', r'(\w+), xzr, #(\w+)', lambda: m[0] == src, -1):
            return orig_i, int(m[1], 0), target
        offset = 0
        if match('movk', r'(\w+), #(\w+), lsl #16', lambda: m[0] == src, -1):
            offset = int(m[1], 0) << 16
        if not match('movz', r'(\w+), #(\w+)', lambda: m[0] == src, -1): return
        offset |= int(m[1], 0)
        return orig_i, offset, target

    src, offset = 'x27', 0
    while match('add', r'(\w+), (\w+), #(\w+)(, lsl #(\d+))?', lambda: m[1] == src):
        offset += int(m[2], 0) << int_opt(m[4])
        src = m[0]
    if match('ldr', r'(\w+), \[(\w+)(, #(\w+))?\]', lambda: m[1] == src):
        offset += int_opt(m[3])
        return i, offset, m[0]
    if match('ldp', r'x5, x30, \[(\w+)(, #(\w+))?\]', lambda: m[0] == src):
        offset += int_opt(m[2])
        if not match('blr', 'x30'): return
        return i, offset, 'call'
