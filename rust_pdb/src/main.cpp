#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "dumper/executor.hpp"
#include "dumper/il2cpp_binary.hpp"
#include "dumper/metadata.hpp"
#include "dumper/struct_generator.hpp"
#include "io.hpp"
#include "pdb/il2cpp.hpp"
#include "pdb/pe.hpp"
#include "pdb/proc.hpp"
#include "pdb/streams.hpp"

namespace fs = std::filesystem;

namespace
{
    constexpr uint64_t max_proc_size = 0x200000;
    constexpr const char* tag = "[rust_pdb]";

    struct inputs
    {
        std::string dll;
        std::string metadata;
        std::string out_pdb;
    };

    [[nodiscard]] std::optional<fs::path> find_metadata(const fs::path & rust_dir)
    {
        std::error_code ec{};
        for (const auto & entry : fs::directory_iterator(rust_dir, ec))
        {
            if (!entry.is_directory(ec))
            {
                continue;
            }
            const std::string name = entry.path().filename().string();
            if (name.size() >= 5 && name.compare(name.size() - 5, 5, "_Data") == 0)
            {
                const fs::path meta = entry.path() / "il2cpp_data" / "Metadata"
                    / "global-metadata.dat";
                if (fs::exists(meta, ec))
                {
                    return meta;
                }
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<fs::path> steam_libraries()
    {
        std::vector<fs::path> roots{};
        std::error_code ec{};
        for (const char* base : {"C:\\Program Files (x86)\\Steam", "C:\\Program Files\\Steam"})
        {
            if (!fs::exists(base, ec))
            {
                continue;
            }
            roots.emplace_back(base);
            const fs::path vdf = fs::path(base) / "steamapps" / "libraryfolders.vdf";
            if (!fs::exists(vdf, ec))
            {
                continue;
            }
            const std::string text = il2pdb::read_text(vdf.string());
            const std::string key = "\"path\"";
            std::size_t pos = 0;
            while ((pos = text.find(key, pos)) != std::string::npos)
            {
                const std::size_t q1 = text.find('"', pos + key.size());
                const std::size_t q2 = q1 == std::string::npos
                    ? std::string::npos
                    : text.find('"', q1 + 1);
                if (q2 == std::string::npos)
                {
                    break;
                }
                const std::string raw = text.substr(q1 + 1, q2 - q1 - 1);
                std::string path{};
                for (std::size_t i = 0; i < raw.size(); ++i)
                {
                    if (raw[i] == '\\' && i + 1 < raw.size() && raw[i + 1] == '\\')
                    {
                        path.push_back('\\');
                        ++i;
                    }
                    else
                    {
                        path.push_back(raw[i]);
                    }
                }
                if (fs::exists(path, ec))
                {
                    roots.emplace_back(path);
                }
                pos = q2 + 1;
            }
        }
        return roots;
    }

    [[nodiscard]] std::optional<inputs> auto_detect()
    {
        std::error_code ec{};
        for (const fs::path & lib : steam_libraries())
        {
            const fs::path rust = lib / "steamapps" / "common" / "Rust";
            const fs::path dll = rust / "GameAssembly.dll";
            if (!fs::exists(dll, ec))
            {
                continue;
            }
            if (const std::optional<fs::path> meta = find_metadata(rust))
            {
                return inputs{dll.string(), meta->string(), (rust / "GameAssembly.pdb").string()};
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] int generate(const inputs & in)
    {
        const auto started = std::chrono::steady_clock::now();
        std::fprintf(stderr, "%s target %s\n", tag, in.dll.c_str());

        const il2pdb::pe_info pe = il2pdb::pe_parse(in.dll);
        std::fprintf(stderr, "%s pe image: %zu sections, age %u%s\n", tag, pe.sections.size(),
            pe.age, pe.has_rsds ? "" : " (no rsds)");

        std::fprintf(stderr, "%s dumping rust via il2cpp ...\n", tag);
        il2pdb::dump::metadata md(il2pdb::read_bytes(in.metadata));
        il2pdb::dump::il2cpp_binary bin(il2pdb::read_bytes(in.dll),
            static_cast<int>(md.type_defs.size()), static_cast<int>(md.image_defs.size()));
        bin.init();
        il2pdb::dump::executor ex(md, bin);
        ex.build_struct_names();
        const il2pdb::dump::dump_result res = il2pdb::dump::run_dump(md, bin, ex);
        std::fprintf(stderr, "%s   %zu methods, %zu addresses, %zu mb il2cpp.h\n", tag,
            res.methods.size(), res.addresses.size(), res.il2cpp_h.size() / 1000000);

        std::fprintf(stderr, "%s building type info ...\n", tag);
        il2pdb::il2cpp_types types = il2pdb::parse_and_build(res.il2cpp_h);
        std::fprintf(stderr, "%s   %zu type records\n", tag, types.records.size());

        const std::vector<uint64_t> & addrs = res.addresses;
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
        procs.reserve(res.methods.size());
        for (const il2pdb::dump::script_method_entry & m : res.methods)
        {
            const uint32_t rva = static_cast<uint32_t>(m.address);
            const std::optional<il2pdb::seg_off_result> so = pe.seg_off(rva);
            if (!so.has_value())
            {
                continue;
            }
            const uint32_t size = code_size(m.address, so->sec_end);
            const uint32_t type_index = m.signature.empty() ? 0 : types.sig_to_proc(m.signature);
            procs.push_back(il2pdb::proc{m.name, so->seg, so->off, size, type_index});
        }

        std::vector<il2pdb::data_sym> data_syms{};
        data_syms.reserve(res.data_symbols.size());
        for (const il2pdb::dump::data_symbol & d : res.data_symbols)
        {
            const std::optional<il2pdb::seg_off_result> so = pe.seg_off(static_cast<uint32_t>(d.rva));
            if (!so.has_value())
            {
                continue;
            }
            uint32_t ti = 0;
            if (!d.type_base.empty())
            {
                const uint32_t base_ti = types.resolve_typeref(d.type_base, d.pointer_depth);
                ti = d.array_count > 0 ? types.make_array(base_ti, d.array_count * 8) : base_ti;
            }
            data_syms.push_back(il2pdb::data_sym{d.name, so->seg, so->off, ti});
        }
        std::fprintf(stderr, "%s   %zu functions, %zu data symbols\n", tag,
            procs.size(), data_syms.size());

        std::fprintf(stderr, "%s writing pdb ...\n", tag);
        il2pdb::build_input input{pe.guid, pe.age, std::move(procs), std::move(types.records),
            pe.section_headers, std::move(data_syms)};
        const std::vector<uint8_t> pdb = il2pdb::build_pdb(input);
        il2pdb::write_bytes(in.out_pdb, std::span<const uint8_t>(pdb.data(), pdb.size()));

        const double secs = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - started).count();
        std::fprintf(stderr, "%s done: %s (%zu mb) in %.1fs\n", tag, in.out_pdb.c_str(),
            pdb.size() / 1000000, secs);
        return 0;
    }
}

int main(int argc, char** argv)
{
    std::vector<std::string> positional{};
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h")
        {
            std::fprintf(stderr, "usage: rust_pdb [<GameAssembly.dll> <global-metadata.dat> "
                "[out.pdb]]\n  (no arguments: auto-detect steam rust)\n");
            return 0;
        }
        positional.push_back(arg);
    }

    inputs in{};
    if (positional.empty())
    {
        const std::optional<inputs> detected = auto_detect();
        if (!detected.has_value())
        {
            std::fprintf(stderr, "%s could not auto-detect rust; pass <GameAssembly.dll> "
                "<global-metadata.dat> [out.pdb]\n", tag);
            return 2;
        }
        in = *detected;
        std::fprintf(stderr, "%s auto-detected steam rust\n", tag);
    }
    else if (positional.size() == 2 || positional.size() == 3)
    {
        in.dll = positional[0];
        in.metadata = positional[1];
        in.out_pdb = positional.size() == 3
            ? positional[2]
            : fs::path(in.dll).replace_extension(".pdb").string();
    }
    else
    {
        std::fprintf(stderr, "usage: rust_pdb [<GameAssembly.dll> <global-metadata.dat> "
            "[out.pdb]]\n");
        return 2;
    }

    try
    {
        return generate(in);
    }
    catch (const std::exception & e)
    {
        std::fprintf(stderr, "%s error: %s\n", tag, e.what());
        return 1;
    }
}
