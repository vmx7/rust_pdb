rust_pdb  -  il2cppdumper output to windows pdb
-----------------------------------------------

turns il2cppdumper output into a windows pdb that ida and windbg auto-load.
reads GameAssembly.dll (pe guid, age, sections), il2cpp.h (struct and enum
types) and script.json (method names, signatures, addresses), then writes the
pdb from scratch: msf container plus tpi / dbi / gsi / psi streams. no compiler,
no linker. x64 pe only (metadata v39, e.g. rust).

build (visual studio 2022, x64 release):
    build.cmd

run:
    x64\Release\rust_pdb.exe <GameAssembly.dll> <il2cpp.h> <script.json> [out.pdb]

out.pdb defaults to <GameAssembly>.pdb next to the dll. byte-identical to the
reference native writer on the same inputs (same sha256).

refs:
    llvm pdb file format docs, microsoft-pdb reference repo
    perfare/il2cppdumper (il2cpp.h and script.json producer)
