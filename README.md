⚠️ **Warning:** This project is outdated. The format of Dart snapshots changes CONSTANTLY, and any Dart RE tools like this one NEED constant maintenance or they stop working with newer versions of Dart / Flutter. Contributions are welcome, but I currently do not have the time to invest in monitoring changes to the VM and keeping this updated.

So, if your snapshot was produced by a reasonably modern version, it probably won't parse [correctly]. Still, if you want to try, you'll probably need at least [the fix in #3](https://github.com/mildsunrise/darter/issues/8#issuecomment-929099367).

---

# darter: Dart snapshot parser

`darter` is a Python module that can fully parse the data inside a Dart snapshot
(i.e. the `libapp.so` file in a release Flutter app).

Features:

 - Parses 100% of the snapshot data, including memory structures.
 - Supports many architectures and the three snapshot types (old, AppJIT and AppAOT).
 - Usually zero-config: autodetects flags & settings from the snapshot.
 - Extracts the blobs from `app.so` or `.snapshot` files automatically.
 - Stores back-references, so you can navigate the graph easily.
 - Debugging output & strict mode controls.
 - Disassembles and analyzes the compiled code to find references to VM objects.

Examples of what you can do with the parsed info:

 - Extract string table of the application
 - Find usages of a certain object
 - Export metadata for Radare2
 - Deobfuscate a snapshot by matching it with a reference one
 - Generate call graph, library dependency graph, etc.

**Note:**
Keep in mind that this is for parsing binary (i.e. architecture-dependent) snapshots.
`.dill` files and some `.snapshot` files contain [Kernel AST](https://github.com/dart-lang/sdk/tree/master/pkg/kernel), which
is a completely different format and currently not supported by `darter`.
[[Learn more]](https://github.com/dart-lang/sdk/wiki/Snapshots#kernel-snapshots)


## How to use

Most of the code is zero-dependency, except for:

 - `parse_elf_snapshot(...)` requires [pyelftools](https://github.com/eliben/pyelftools)

 - the `darter.asm` module (for analyzing the assembled code) requires
   [Capstone](https://www.capstone-engine.org/documentation.html)
   (and its python binding)

`darter` in itself is just a module, it has no stand-alone program or CLI.  
The recommended way to use it is by including it in a notebook and
playing with the parsed data.

[Install Jupyter](https://jupyter.org/install) and open the `1-introduction`
notebook for a basic walkthrough of the parsed data; then head to `2-playground`
which contains more interesting examples of use.

It's *highly recommended* that you first play with a known snapshot (i.e.
that you have built yourself or have the code), before analyzing the
snapshot you are after.


## Status

The parser is still at an early stage and will not work in every case.

 - It has been heavily tested on AppAOT Product snapshots on ARM and ARM64.
 - It has been lightly tested on AppJIT Release snapshots on x64.
 - The disassembly analysis is architecture-dependent, and currently supports ARM and ARM64.
 - The rest of the code is mostly architecture-independent, but it may not work on other architectures without some modifications.

This parser was written based on dart-sdk at `1ef83b86ae`.
The snapshot format is internal to the VM. It dumps some of the objects as they appear
in memory; you need to know how the VM (arch, compile flags) was compiled in order
to parse it. It [can change frequently between versions](./info/versions.md), as
there's not a standard spec (AFAIK) for the format.

Any help or donations are welcome.


## Technical details

Given an *data section* and an *instructions section* (and optionally a *base*):

 - Parse the clusters allocation section, building the reference table.
 - Parse the clusters fill section.
 - Parse the root object.
 - Link the references between objects.
 - Parse the native structures (`OneByteString`, `CodeSourceMap`, `Instructions`, etc.).
 - The resulting VM objects (and cluster descriptions) are returned.

The information is returned as parsed as much as possible, so that it is easy to
manipulate. Back-references are tracked too, so that it's easy to know where a certain
object is referenced from.

`darter` can parse both 'VM' snapshots and 'isolate' ones (the ones we care about).

The `darter.asm` module disassembles the compiled code and analyzes it.
This is crucial for AOT snapshots, because we get no high-level bytecode.


## See also

If you are new to Dart / Flutter reverse-engineering, it's a good idea to read
this introduction first: https://mrale.ph/dartvm/

The relevant code on snapshot serialization is at [`runtime/vm/clustered_snapshot.cc`](https://github.com/dart-lang/sdk/blob/1ef83b86ae637ffe7359173804cbc6d3fa25e6db/runtime/vm/clustered_snapshot.cc)
and [`runtime/vm/raw_object.h`](https://github.com/dart-lang/sdk/blob/1ef83b86ae637ffe7359173804cbc6d3fa25e6db/runtime/vm/raw_object.h).

There's also additional info in the `info` directory.
