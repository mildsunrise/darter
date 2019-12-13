import re
import capstone as cs
from capstone.arm import *

supports = lambda _, arch: arch == 'arm'
make_engine = lambda _: cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)

find_register = lambda op, reg: re.search(r'(\W|^)' + reg + r'(\W|$)', op[3], flags=re.ASCII)
int_opt = lambda x: 0 if x is None else int(x, 0)

def match_nref(ops, i):
    if find_register(ops[i], 'r5'):
        res = match_loadobj(ops, i)
        if res is None:
            # print('Couldn\'t extract 0x{:x}: {} {}'.format(ops[i][0], ops[i][2], ops[i][3])) # FIXME: use proper logging
            return
        i, offset, reg = res
        div, mod = divmod(offset + 1, 4)
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

    src, offset = 'r5', 0
    while match('add', r'(\w+), (\w+), #(\w+)(, lsl #(\d+))?', lambda: m[1] == src):
        offset += int(m[2], 0) << int_opt(m[4])
        src = m[0]
    if match('ldr', r'(\w+), \[(\w+)(, #(\w+))?\]', lambda: m[1] == src):
        offset += int_opt(m[3])
        return i, offset, m[0]
