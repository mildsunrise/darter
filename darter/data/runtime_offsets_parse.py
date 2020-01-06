#!/usr/bin/env python3
# This script parses the offset at runtime/vm/compiler/runtime_offsets_extracted.h
# file and produces runtime_offsets.json

from collections import OrderedDict
from sys import stdin, stdout
import json
import re

mappings = {
  'defined(target_arch_arm)': 'arm',
  'defined(target_arch_x64)': 'x64',
  'defined(target_arch_ia32)': 'ia32',
  'defined(target_arch_arm64)': 'arm64',
  'defined(target_arch_dbc) && defined(target_arch_is_64_bit)': 'dbc-64',
  'defined(target_arch_dbc) && defined(target_arch_is_32_bit)': 'dbc-32',
}

content = stdin.read()
archs = OrderedDict()
values = None
while True:
    if m := re.match(r'\s*\#if ([^\n]+)\n', content):
        content = content[m.end():]
        cond = m.group(1).lower()
        assert cond not in archs
        assert values is None
        archs[mappings[cond]] = values = OrderedDict()
    elif m := re.match(r'\s*\#endif  // ([^\n]+)\n', content):
        content = content[m.end():]
        assert values != None
        values = None
    elif m := re.match(r'\s*static constexpr dart::compiler::target::word\s+(?P<name>\w+)\s*=\s*(?P<value>-?\d+)\s*;', content):
        content = content[m.end():]
        values[m.group('name')] = int(m.group('value'), 0)
    elif m := re.match(r'\s*static constexpr dart::compiler::target::word\s+(?P<name>\w+)\[\]\s*=\s*\{\s*(?P<value>(-?\d+\s*\,\s*)+-?\d+)\s*\}\s*;', content):
        content = content[m.end():]
        values[m.group('name')] = [ int(x, 0) for x in m.group('value').split(',') ]
    else:
        break

if content.strip():
    raise Exception('Couldn\'t parse: {}'.format(repr(content)))

json.dump(archs, stdout, indent=4)
print()
