#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "io.hpp"
#include "pdb/il2cpp.hpp"
#include "pdb/pe.hpp"
#include "pdb/proc.hpp"
#include "pdb/script_json.hpp"
#include "pdb/streams.hpp"

namespace fs = std::filesystem;

namespace
{
    constexpr uint64_t max_proc_size = 0x200000;

    [[nodiscard]] int generate(const std::string & dll, const std::string & header_path,
        const std::string & script_path, const std::string & out_pdb)
    {
        const il2pdb::pe_info pe = il2pdb::pe_parse(dll);
        std::fprintf(stderr, "pe: %zu sections, rsds=%s, age=%u\n", pe.sections.size(),
            pe.has_rsds ? "yes" : "no", pe.age);

        il2pdb::il2cpp_types types = il2pdb::parse_and_build(il2pdb::read_text(header_path));
        std::fprintf(stderr, "types: %zu records\n", types.records.size());

        const il2pdb::script scr = il2pdb::parse_script_json(il2pdb::read_text(script_path));
        std::fprintf(stderr, "script: %zu methods, %zu addresses\n",
            scr.methods.size(), scr.addresses.size());

        std::vector<uint64_t> addrs = scr.addresses;
        std::sort(addrs.begin(), addrs.end());
        addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());

        const auto code_size = [&addrs](uint64_t rva, uint32_t sec_end) -> uint32_t
        {
            const uint64_t cap = static_cast<uint64_t>(sec_end) - rva;
            const std::size_t j = static_cast<std::size_t>(
                std::upper_bound(addrs.begin(), addrs.end(), rva) - addrs.begin());
            uint64_t s = (j < addrs.size()) ? (addrs[j] - rva) : cap;
            if (s == 0)
            {
                s = 1;
            }
            if (s > cap)
            {
                s = cap;
            }
            if (s > max_proc_size)
            {
                s = max_proc_size;
            }
            return static_cast<uint32_t>(s);
        };

        std::vector<il2pdb::proc> procs{};
        procs.reserve(scr.methods.size());
        for (const il2pdb::script_method & m : scr.methods)
        {
            const uint32_t rva = static_cast<uint32_t>(m.address);
            const std::optional<il2pdb::seg_off_result> so = pe.seg_off(rva);
            if (!so.has_value())
            {
                continue;
            }
            const uint32_t size = code_size(m.address, so->sec_end);
            const uint32_t type_index = m.has_sig ? types.sig_to_proc(m.sig) : 0;
            procs.push_back(il2pdb::proc{m.name, so->seg, so->off, size, type_index});
        }
        std::fprintf(stderr, "procs: %zu\n", procs.size());

        il2pdb::build_input input{pe.guid, pe.age, std::move(procs), std::move(types.records),
            pe.section_headers, {}};
        const std::vector<uint8_t> pdb = il2pdb::build_pdb(input);
        il2pdb::write_bytes(out_pdb, std::span<const uint8_t>(pdb.data(), pdb.size()));
        std::fprintf(stderr, "wrote %s (%zu mb)\n", out_pdb.c_str(), pdb.size() / 1000000);
        return 0;
    }
}

int main(int argc, char** argv)
{
    if (argc < 4 || argc > 5)
    {
        std::fprintf(stderr,
            "usage: rust_pdb <GameAssembly.dll> <il2cpp.h> <script.json> [out.pdb]\n");
        return 2;
    }

    const std::string dll = argv[1];
    const std::string header_path = argv[2];
    const std::string script_path = argv[3];
    const std::string out_pdb = argc == 5
        ? std::string(argv[4])
        : fs::path(dll).replace_extension(".pdb").string();

    try
    {
        return generate(dll, header_path, script_path, out_pdb);
    }
    catch (const std::exception & e)
    {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
