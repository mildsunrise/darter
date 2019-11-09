# darter: Dart snapshot parser

`darter` is a Python module that can fully parse the data inside a Dart snapshot
(i.e. the `libapp.so` file in a release Flutter app).

Features:

 - Parses 100% of the snapshot data, including memory structures.
 - Supports many architectures and the three snapshot types (old, AppJIT and AppAOT).
 - Tested on AppAOT ARM Product snapshots, and AppJIT x64 Release snapshots.
 - Usually zero-config: autodetects flags & settings from the snapshot.
 - Extracts the blobs from `app.so` or `.snapshot` files automatically.
 - Stores back-references, so you can travel the graph easily.
 - Debugging output & strict mode controls.
 - Comes with some examples of native instruction inspection.
 - Auxiliary parsing for code source maps and other structures.

Examples of what you can do with the parsed info:

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

- The parser is still at an early stage and will not work in every case.
  It has only been tested on AppAOT ARM Product snapshots, and AppJIT x64 Release
  snapshots. It still doesn't support all architectures that Dart runs on (without
  some modifications, at least).

- This parser was written based on dart-sdk at `1ef83b86ae`.

  The snapshot format is internal to the VM. It dumps some of the objects as they appear
  in memory; you need to know how the VM (arch, compile flags) was compiled in order
  to parse it. It can change frequently between versions, as there's not a standard spec
  (AFAIK) for the format.

- Keep in mind that this is for parsing binary (i.e. architecture-dependent) snapshots.
  `.dill` files and some `.snapshot` files contain [Kernel AST](https://github.com/dart-lang/sdk/tree/master/pkg/kernel), which
  is completely different and currently not supported by `darter`.
  [[Learn more]](https://github.com/dart-lang/sdk/wiki/Snapshots#kernel-snapshots)

Any help or donations are welcome.


## How to use

`darter` in itself is just a module, it has no stand-alone program or CLI.  
One way to use it is through the included **Playground.ipynb** notebook.

First, [install Radare2](https://www.radare.org/n/radare2.html) (it is only
required for the `file` module (parsing ELF snapshots) and the native ref finder).

Then install `r2pipe`: `pip3 install r2pipe`

Finally [install Jupyter](https://jupyter.org/install) and open the notebook to start
playing.


## See also

If you are new to Dart / Flutter reverse-engineering, it's a good idea to read
this introduction first: https://mrale.ph/dartvm/

The relevant code on snapshot serialization is at [`runtime/vm/clustered_snapshot.cc`](https://github.com/dart-lang/sdk/blob/1ef83b86ae637ffe7359173804cbc6d3fa25e6db/runtime/vm/clustered_snapshot.cc)
and [`runtime/vm/raw_object.h`](https://github.com/dart-lang/sdk/blob/1ef83b86ae637ffe7359173804cbc6d3fa25e6db/runtime/vm/raw_object.h).

There's also additional info in the `info` directory.
