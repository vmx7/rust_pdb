rust_pdb  -  self-contained il2cpp to windows pdb
-------------------------------------------------

generates a windows pdb from a unity il2cpp game with no external tools. reads
GameAssembly.dll and global-metadata.dat (both ship with the game), dumps the
il2cpp metadata natively (types, methods, signatures, il2cpp.h) and writes the
pdb from scratch: msf container plus tpi / dbi / gsi / psi streams. no compiler,
no linker, no il2cppdumper. x64 pe only (metadata v39, e.g. rust).

build (visual studio 2022, x64 release):
    msbuild rust_pdb.sln -p:Configuration=Release -p:Platform=x64

run:
    x64\Release\rust_pdb.exe
    x64\Release\rust_pdb.exe <GameAssembly.dll> <global-metadata.dat> [out.pdb]

with no arguments it auto-detects a steam rust install (GameAssembly.dll plus
RustClient_Data\il2cpp_data\Metadata\global-metadata.dat) and writes the pdb
next to the dll. byte-identical to the reference native writer on the same
inputs (same sha256).

pipeline (all in-process):
    metadata      global-metadata.dat parser (v39)
    il2cpp_binary pe parse, registration discovery, method pointers, rgctx
    executor      type and method names, c-type signatures
    struct_gen    il2cpp.h (fields, vtable, rgctx, static, arrays, enums)
    pdb writer    il2cpp.h -> tpi records, procs and data symbols, msf + streams

refs:
    llvm pdb file format docs, microsoft-pdb reference repo
    perfare/il2cppdumper (metadata layout and struct generation reference)
