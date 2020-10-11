#!/usr/bin/python3
# Generates a .dart main file that imports every possible
# file from all packages in `.packages`, obeying some blacklists.

import re
import os

# place your own
BLACKLISTS = {
  'sky_engine',
  ('intl', 'intl_browser.dart'),
  ('intl', 'date_symbol_data_http_request.dart'),
  ('matcher', 'mirror_matchers.dart'), ('quiver', 'mirrors.dart'),
}
SKIP_DIRS = { 'src' }

with open('.packages') as f:
  ls = f.read().splitlines()

ls = [ re.fullmatch(r'(.*?)(\#.*)?', x).group(1).strip() for x in ls ]
ls = [ x for x in ls if x ]
for x in ls:
  package, target = re.fullmatch(r'(\w+):(?:file://)?(.+)', x).groups()
  if target == 'lib/': continue # skip our own module
  if package in BLACKLISTS: continue

  for folder, dirs, files in os.walk(target):
    for d in SKIP_DIRS:
      if d in dirs:
        dirs.remove(d)
    for f in files:
      if not f.endswith('.dart'): continue
      f = os.path.relpath(os.path.join(folder, f), target)
      if (package, f) in BLACKLISTS: continue
      print(f"import 'package:{package}/{f}';")

print('void main() {}')
