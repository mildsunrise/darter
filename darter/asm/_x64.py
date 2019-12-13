import capstone as cs
from capstone.arm64 import *

supports = lambda _, arch: arch == 'x64'
make_engine = lambda _: cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)

# TODO
