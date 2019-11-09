# CONSTANTS

import json
import os.path


EXPECTED_VERSION = 'c8562f0ee0ebc38ba217c7955956d1cb'

MAGIC_VALUE = 0xdcdcf5f5

kSectionMarker = 0xABAB

kMaxPreferredCodeAlignment = 32

with open(os.path.join(os.path.dirname(__file__), 'data', 'classIds.json')) as f:
    kClassId = json.load(f)
kkClassId = { k: v for (v, k) in enumerate(kClassId) }
kNumPredefinedCids = kkClassId['kNumPredefinedCids']
kInstanceCid = kkClassId['kInstanceCid']
kTypedDataInt8ArrayCid = kkClassId['kTypedDataInt8ArrayCid']
kByteDataViewCid = kkClassId['kByteDataViewCid']

kTypedDataCidRemainderInternal = 0
kTypedDataCidRemainderView = 1
kTypedDataCidRemainderExternal = 2

kDataSerializationAlignment = 8

kEntryType = [ 'kTaggedObject', 'kImmediate', 'kNativeFunction', 'kNativeFunctionWrapper', 'kNativeEntryData' ]
kkEntryType = { k: v for (v, k) in enumerate(kEntryType) }
decodeObjectEntryTypeBits = lambda x: { "patchable": not (x >> 7), "entry_type": x & 0x7F }

__isBase = lambda x, r: \
    (kTypedDataInt8ArrayCid <= x < kByteDataViewCid) and (x - kTypedDataInt8ArrayCid) % 3 == r
isTypedData = lambda x: __isBase(x, kTypedDataCidRemainderInternal)
isTypedDataView = lambda x: __isBase(x, kTypedDataCidRemainderView) or x == kByteDataViewCid
isExternalTypedData = lambda x: __isBase(x, kTypedDataCidRemainderExternal)

kKind = [
    ('kFull', "Full snapshot of core libraries or an application"),
    ('kFullJIT', "Full + JIT code"),
    ('kFullAOT', "Full + AOT code"),
    ('kMessage', "A partial snapshot used only for isolate messaging"),
    ('kNone', "gen_snapshot"),
    ('kInvalid', None),
]
kkKind = { k[0]: v for (v, k) in enumerate(kKind) }

kPcDescriptorKindBits = [
    ('deopt', 'Deoptimization continuation point.'),
    ('icCall', 'IC call.'),
    ('unoptStaticCall', 'Call to a known target via stub.'),
    ('runtimeCall', 'Runtime call.'),
    ('osrEntry', 'OSR entry point in unopt. code.'),
    ('rewind', 'Call rewind target address.'),
    ('other', None),
]
kkPcDescriptorKindBits = { k[0]: v for (v, k) in enumerate(kPcDescriptorKindBits) }

with open(os.path.join(os.path.dirname(__file__), 'data', 'stub_code_list.json')) as f:
    kStubCodeList = json.load(f)

# runtime/vm/dart_entry.h
kCachedDescriptorCount = 32
# runtime/vm/object.h
kCachedICDataArrayCount = 4


### AppJIT blob wrapping

kAppJITMagic = 0xf6f6dcdc
kAppSnapshotPageSize = 4 * 1024

### AppAOT blob wrapping

kAppAOTSymbols = [
    '_kDartVmSnapshotData',
    '_kDartVmSnapshotInstructions',
    '_kDartIsolateSnapshotData',
    '_kDartIsolateSnapshotInstructions'
]
