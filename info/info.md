### Dart info

- General introduction about VM internals, snapshots, etc.
  https://mrale.ph/dartvm/ (last updated 2019-01)

  File that handles serialization / deserialization of snapshots:
  [`clustered_snapshot.cc`](https://github.com/dart-lang/sdk/blob/master/runtime/vm/clustered_snapshot.cc)

  File that defines Dart's public API:
  [`dart_api.h`](https://github.com/dart-lang/sdk/blob/master/runtime/include/dart_api.h)  
  Implementation:
  [`dart_api_impl.cc`](https://github.com/dart-lang/sdk/blob/master/runtime/vm/dart_api_impl.cc)

  an entry point to the AOT compilation loop in the VM:
  https://github.com/dart-lang/sdk/blob/cb6127570889bed147cbe6292cb2c0ba35271d58/runtime/vm/compiler/aot/precompiler.cc#L190

  Interesting methods:
  - Dart_CreateAppAOTSnapshotAsBlobs
    -> returns 4 binary blobs -> **this is what flutter used at some point, the 4 blobs were packaged at assets dir in APK**
  - Dart_CreateAppAOTSnapshotAsAssembly
    - outputs assembly file that defines 4 symbols (the blobs) and can be linked however we want
  - Dart_CreateVMAOTSnapshotAsAssembly
    - Like Dart_CreateAppAOTSnapshotAsAssembly, but only includes
      kDartVmSnapshotData and kDartVmSnapshotInstructions.
  - Dart_CreateAppAOTSnapshotAsElf -> (newer one, see below)
    - Like Dart_CreateAppAOTSnapshotAsAssembly, but outputs a .so instead of assembly file
      - This is what is used now, and in tsunami, produced ELF gets placed in lib/.../libapp.so

- Dart SDK can now compile AOT as ELF binaries directly  
  [[vm] Direct generation of ELF shared libraries.](https://dart-review.googlesource.com/c/sdk/+/81323)  
  Merged on 2019-05-28
  Introduces Dart_CreateAppAOTSnapshotAsElf and kAppAOTElf type

AOT [snapshot types](https://dart.googlesource.com/sdk/+/af93ebcf4cb55ae5f0f39a183ad2d42ca13ae51f/runtime/bin/gen_snapshot.cc#79):

    kCore,
    kCoreJIT,
    kApp,
    kAppJIT,
    kAppAOTBlobs,
    kAppAOTAssembly,
    kAppAOTElf,
    kVMAOTAssembly,


### Flutter

Flutter engine operation in AOT mode (beware of outdated content):
https://github.com/flutter/flutter/wiki/Flutter-engine-operation-in-AOT-Mode

#32743: Support AOT .so (--build-shared-library) compilation for Android arm64
https://github.com/flutter/flutter/issues/32743

https://github.com/flutter/flutter/pull/32787


Running `flutter build aot` on last Flutter, demo app, executes:

# Build kernel file
flutter/bin/cache/dart-sdk/bin/dart --sdk-root ... --strong --target=flutter
   --aot --tfa -Ddart.vm.product=true
   --packages .packages
   --output-dill build/aot/app.dill
   --depfile build/aot/kernel_compile.d
   package:myapp/main.dart

# Compile kernel file into AOT snapshot, as ELF (strip, deterministic, casual_async_stack)
flutter/bin/cache/artifacts/engine/android-arm-release/linux-x64/gen_snapshot
  --causal_async_stacks
  --deterministic
  --snapshot_kind=app-aot-elf
  --elf=build/aot/app.so
  --strip
  --no-sim-use-hardfp
  --no-use-integer-division
  build/aot/app.dill

Code NOT OBFUSCATED by default, but can be made so with --obfuscate (https://github.com/flutter/flutter/wiki/Obfuscating-Dart-Code)

https://github.com/flutter/engine/pull/8979

Part of Flutter where AOT snapshot is loaded:
https://github.com/flutter/engine/blob/master/shell/platform/android/io/flutter/view/FlutterNativeView.java#L105

https://stackoverflow.com/questions/54388974/how-does-dart-flutter-get-compiled-to-android


### Dart building

https://github.com/dart-lang/sdk/wiki/Building

https://github.com/dart-lang/sdk/wiki/Building-Dart-SDK-for-ARM-processors

./tools/build.py -m release -a arm --os=android create_sdk





