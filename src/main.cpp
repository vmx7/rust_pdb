#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#pragma warning(push, 0)
#include <windows.h>
#pragma warning(pop)

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

    struct inputs
    {
        std::string dll;
        std::string header;
        std::string script;
        std::string out_pdb;
    };

    [[nodiscard]] std::string env_path(const char* name)
    {
        std::array<char, MAX_PATH> buf{};
        const DWORD n = GetEnvironmentVariableA(name, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0 || n >= static_cast<DWORD>(buf.size()))
        {
            return {};
        }
        return std::string(buf.data(), n);
    }

    [[nodiscard]] std::string exe_dir()
    {
        std::array<char, MAX_PATH> buf{};
        const DWORD n = GetModuleFileNameA(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0 || n >= static_cast<DWORD>(buf.size()))
        {
            return {};
        }
        return fs::path(std::string(buf.data(), n)).parent_path().string();
    }

    [[nodiscard]] std::vector<fs::path> steam_roots()
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

    [[nodiscard]] std::string find_rust_dll()
    {
        std::error_code ec{};
        for (const fs::path & root : steam_roots())
        {
            const fs::path dll = root / "steamapps" / "common" / "Rust" / "GameAssembly.dll";
            if (fs::exists(dll, ec))
            {
                return dll.string();
            }
        }
        return {};
    }

    [[nodiscard]] std::string find_dump_dir(const std::vector<fs::path> & seeds)
    {
        std::error_code ec{};
        std::vector<fs::path> dirs = seeds;
        const std::string profile = env_path("USERPROFILE");
        if (!profile.empty())
        {
            for (const auto & entry : fs::directory_iterator(fs::path(profile) / "Documents", ec))
            {
                if (entry.is_directory(ec))
                {
                    dirs.push_back(entry.path());
                }
            }
        }
        for (const fs::path & d : dirs)
        {
            if (d.empty())
            {
                continue;
            }
            if (fs::exists(d / "il2cpp.h", ec) && fs::exists(d / "script.json", ec))
            {
                return d.string();
            }
        }
        return {};
    }

    [[nodiscard]] std::optional<inputs> auto_detect()
    {
        std::error_code ec{};
        const fs::path cwd = fs::current_path(ec);
        const fs::path exe = exe_dir();

        std::string dll{};
        for (const fs::path & d : {cwd, exe})
        {
            if (d.empty())
            {
                continue;
            }
            const fs::path cand = d / "GameAssembly.dll";
            if (fs::exists(cand, ec))
            {
                dll = cand.string();
                break;
            }
        }
        if (dll.empty())
        {
            dll = find_rust_dll();
        }
        if (dll.empty())
        {
            return std::nullopt;
        }

        const fs::path dll_dir = fs::path(dll).parent_path();
        const std::string dump = find_dump_dir({cwd, dll_dir, exe});
        if (dump.empty())
        {
            return std::nullopt;
        }

        inputs in{};
        in.dll = dll;
        in.header = (fs::path(dump) / "il2cpp.h").string();
        in.script = (fs::path(dump) / "script.json").string();
        in.out_pdb = (dll_dir / "GameAssembly.pdb").string();
        return in;
    }

    [[nodiscard]] int generate(const inputs & in)
    {
        const il2pdb::pe_info pe = il2pdb::pe_parse(in.dll);
        std::fprintf(stderr, "pe: %zu sections, rsds=%s, age=%u\n", pe.sections.size(),
            pe.has_rsds ? "yes" : "no", pe.age);

        il2pdb::il2cpp_types types = il2pdb::parse_and_build(il2pdb::read_text(in.header));
        std::fprintf(stderr, "types: %zu records\n", types.records.size());

        const il2pdb::script scr = il2pdb::parse_script_json(il2pdb::read_text(in.script));
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
        il2pdb::write_bytes(in.out_pdb, std::span<const uint8_t>(pdb.data(), pdb.size()));
        std::fprintf(stderr, "wrote %s (%zu mb)\n", in.out_pdb.c_str(), pdb.size() / 1000000);
        return 0;
    }
}

int main(int argc, char** argv)
{
    inputs in{};

    if (argc == 1)
    {
        const std::optional<inputs> detected = auto_detect();
        if (!detected.has_value())
        {
            std::fprintf(stderr, "auto-detect failed: need GameAssembly.dll (steam rust) plus "
                "il2cpp.h and script.json (il2cppdumper output)\n");
            return 2;
        }
        in = *detected;
        std::fprintf(stderr, "auto-detected:\n  dll:    %s\n  header: %s\n  script: %s\n"
            "  out:    %s\n", in.dll.c_str(), in.header.c_str(), in.script.c_str(),
            in.out_pdb.c_str());
    }
    else if (argc == 2)
    {
        const fs::path dir = argv[1];
        in.dll = (dir / "GameAssembly.dll").string();
        in.header = (dir / "il2cpp.h").string();
        in.script = (dir / "script.json").string();
        in.out_pdb = (dir / "GameAssembly.pdb").string();
    }
    else if (argc == 4 || argc == 5)
    {
        in.dll = argv[1];
        in.header = argv[2];
        in.script = argv[3];
        in.out_pdb = argc == 5
            ? std::string(argv[4])
            : fs::path(in.dll).replace_extension(".pdb").string();
    }
    else
    {
        std::fprintf(stderr,
            "usage:\n"
            "  rust_pdb                                              auto-detect rust + dump\n"
            "  rust_pdb <dir>                                        dir has dll, il2cpp.h, script.json\n"
            "  rust_pdb <GameAssembly.dll> <il2cpp.h> <script.json> [out.pdb]\n");
        return 2;
    }

    try
    {
        return generate(in);
    }
    catch (const std::exception & e)
    {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
