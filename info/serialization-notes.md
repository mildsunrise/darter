### Internals & deserialization

runtime/vm/class_id.h specifies a list of class IDs -> preprocess and extract the enum

Header {
  int32 magicValue = 0xdcdcf5f5
  int64 length  -> length of snapshot data in bytes, not including magic value
  int64 kind
}

IncludesCode: FullJIT, FullAOT
IncludesBytecode: Full, FullJIT
the code (if any) starts after the snapshot data (rounded up to kMaxObjectAlignment)

after header comes: SnapshotHeader {
  version string (32 bytes)
  features string (nul terminated)
}

CIDs are int32
tags is a uint8

except Header, the rest of the ints/uints longer than 8 bits are encoded using SLEB128,
but inverted (high bit set to 1 to terminate int)

objects are clustered by class -> type information written once per class

2 major sections:
 - how to allocate objects
 - how to initialize them

allocation section is read for each cluster
then initialization is read  
then finally a 'roots' section which initializes the ObjectStore


### Instructions layout

#### Registers

r5 holds the Data() of the global_object_pool minus one byte.  
so, to load object 9188 of the pool into r4, we do:  
`Data() + 4 * 9188` -> `Data() + 0x8f90` -> `r5 + 0x8f8f` -> instructions:

~~~
024985e2       add r4, r5, 0x8000
8f4f94e5       ldr r4, [r4, 0xf8f]
~~~

#### Entry point

A RawInstructions object has 4 entry points (depending on checked/unchecked, polymorphic/monomorphic).

 - The entry point is `data_pos + (appropriate constant from below)`  
   For ARM + AOT: 0 for monomorphic, 20 for polymorphic
 - If it's unchecked, the `unchecked_entrypoint_pc_offset` field should be added too


~~~
#if defined(TARGET_ARCH_IA32)
  static const intptr_t kMonomorphicEntryOffsetJIT = 6;
  static const intptr_t kPolymorphicEntryOffsetJIT = 34;
  static const intptr_t kMonomorphicEntryOffsetAOT = 0;
  static const intptr_t kPolymorphicEntryOffsetAOT = 0;
#elif defined(TARGET_ARCH_X64)
  static const intptr_t kMonomorphicEntryOffsetJIT = 8;
  static const intptr_t kPolymorphicEntryOffsetJIT = 40;
  static const intptr_t kMonomorphicEntryOffsetAOT = 8;
  static const intptr_t kPolymorphicEntryOffsetAOT = 32;
#elif defined(TARGET_ARCH_ARM)
  static const intptr_t kMonomorphicEntryOffsetJIT = 0;
  static const intptr_t kPolymorphicEntryOffsetJIT = 40;
  static const intptr_t kMonomorphicEntryOffsetAOT = 0;
  static const intptr_t kPolymorphicEntryOffsetAOT = 20;
#elif defined(TARGET_ARCH_ARM64)
  static const intptr_t kMonomorphicEntryOffsetJIT = 8;
  static const intptr_t kPolymorphicEntryOffsetJIT = 48;
  static const intptr_t kMonomorphicEntryOffsetAOT = 8;
  static const intptr_t kPolymorphicEntryOffsetAOT = 28;
#elif defined(TARGET_ARCH_DBC)
  static const intptr_t kMonomorphicEntryOffsetJIT = 0;
  static const intptr_t kPolymorphicEntryOffsetJIT = 0;
  static const intptr_t kMonomorphicEntryOffsetAOT = 0;
  static const intptr_t kPolymorphicEntryOffsetAOT = 0;
#else
~~~
