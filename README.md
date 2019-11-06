# darter: Dart snapshot parser

`darter` is a Python module that can fully parse the data inside a Dart snapshot
(i.e. the `libapp.so` file in a release Flutter app). Examples of what you can
do with the parsed info:

 - Extract string table of an application
 - Print function / class / file list
 - Print reference tree
 - Detect where a certain string/object is used from
 - Extract call graph

See the [playground notebook](Playground.ipynb) for more details.  
However, be aware of limitations below before using it.


## Technical details

Given an *data section* and an *instructions section* (and optionally a *base*):

 - Parse the clusters allocation section, building the reference table.
 - Parse the clusters fill section.
 - Parse the root object.
 - Link the references between objects.
 - Parse the native structures (`OneByteString`, `CodeSourceMap`, `Instructions`, etc.).
 - The resulting VM objects (and cluster descriptions) are returned to your code.

The information is returned as parsed as much as possible, so that it is easy to
manipulate. Back-references are tracked too, so that it's easy to know where a certain
object is referenced from.

`darter` can parse both 'VM' snapshots and 'isolate' ones (the ones we care about).

The notebook also includes an experimental **native reference extractor**, which
disassembles compiled code and detects references to VM objects. This is crucial
for AOT snapshots, because we get no high-level bytecode.


## Limitations

- Even though the code handles the other kinds of snapshots, it has only been tested
  with **AppAOT** snapshots compiled for **ARM** on **release mode** and probably still
  needs some modifications in order to work with i.e. AppJIT snapshots.

- The code is also missing a few tweaks before it can work on snapshots compiled for
  64-bit architectures (calls to `unpack`).

- This parser was written based on dart-sdk at `1ef83b86ae`.
  The snapshot format is internal to the VM. It dumps some of the objects as they appear
  in memory; you need to know how the VM (arch, compile flags) was compiled in order
  to parse it. It can change frequently between versions, as there's not a standard spec
  (AFAIK) for the format.

- The code quality is far from perfect.

Any help or donations are welcome.


## How to use

### Initialize settings

First, you need to initialize the settings. Copy `darter/settings.sample.py`
as `darter/settings.py` sample and edit the settings to match your architecture
and flags. Those need to be correct for parsing to succeed.

### Dependencies

`darter` has no dependencies, but the notebook uses [Radare2](https://www.radare.org)
to inspect the binary and extract the appropriate data for parsing, as well as for
disassembly analysis.

 - [Install Radare2](https://www.radare.org/n/radare2.html)
 - Install the `r2pipe` module: `pip3 install r2pipe`

### Open notebook

`darter` in itself is just a module, it has no stand-alone program or CLI.  
One way to use it is through the included **Playground.ipynb** notebook.
[Install Jupyter](https://jupyter.org/install) and open the notebook to start
playing.


## See also

If you are new to Dart / Flutter reverse-engineering, it's a good idea to read
this introduction first: https://mrale.ph/dartvm/

The relevant code on snapshot serialization is at [`runtime/vm/clustered_snapshot.cc`](https://github.com/dart-lang/sdk/blob/1ef83b86ae637ffe7359173804cbc6d3fa25e6db/runtime/vm/clustered_snapshot.cc)
and [`runtime/vm/raw_object.h`](https://github.com/dart-lang/sdk/blob/1ef83b86ae637ffe7359173804cbc6d3fa25e6db/runtime/vm/raw_object.h).

There's also additional info in the `info` directory.
