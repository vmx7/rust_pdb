#include "pe.hpp"

#include "io.hpp"

#include <stdexcept>

namespace il2pdb
{
    namespace
    {
        uint16_t u16le(const std::vector<uint8_t> & b, std::size_t o)
        {
            return static_cast<uint16_t>(b[o] | (static_cast<uint16_t>(b[o + 1]) << 8));
        }

        uint32_t u32le(const std::vector<uint8_t> & b, std::size_t o)
        {
            return static_cast<uint32_t>(b[o])
                | (static_cast<uint32_t>(b[o + 1]) << 8)
                | (static_cast<uint32_t>(b[o + 2]) << 16)
                | (static_cast<uint32_t>(b[o + 3]) << 24);
        }
    }

    pe_info pe_parse(std::string_view path)
    {
        const std::vector<uint8_t> b = read_bytes(path);
        const std::size_t e = u32le(b, 0x3C);
        if (!(b[e] == 'P' && b[e + 1] == 'E' && b[e + 2] == 0 && b[e + 3] == 0))
        {
            throw std::runtime_error("bad PE sig");
        }
        const std::size_t nsec = u16le(b, e + 6);
        const std::size_t optsize = u16le(b, e + 20);
        const std::size_t opt = e + 24;
        const bool pe32plus = u16le(b, opt) == 0x20B;
        const std::size_t dd_off = opt + (pe32plus ? 112 : 96);
        const uint32_t debug_rva = u32le(b, dd_off + 6 * 8);
        const uint32_t debug_size = u32le(b, dd_off + 6 * 8 + 4);

        const std::size_t sec_off = opt + optsize;

        pe_info info{};
        for (std::size_t i = 0; i < nsec; ++i)
        {
            const std::size_t s = sec_off + i * 40;
            const uint32_t vsize = u32le(b, s + 8);
            const uint32_t vaddr = u32le(b, s + 12);
            info.sections.push_back(pe_section{vaddr, vsize, static_cast<uint16_t>(i + 1)});
        }

        const auto rva_to_off = [&](uint32_t rva) -> std::optional<std::size_t>
        {
            for (std::size_t i = 0; i < nsec; ++i)
            {
                const std::size_t so = sec_off + i * 40;
                const uint32_t vsize = u32le(b, so + 8);
                const uint32_t vaddr = u32le(b, so + 12);
                const uint32_t rawptr = u32le(b, so + 20);
                if (rva >= vaddr && rva < vaddr + vsize)
                {
                    return static_cast<std::size_t>(rawptr + (rva - vaddr));
                }
            }
            return std::nullopt;
        };

        if (debug_rva != 0)
        {
            if (const std::optional<std::size_t> off = rva_to_off(debug_rva))
            {
                const std::size_t n = debug_size / 28;
                for (std::size_t i = 0; i < n; ++i)
                {
                    const std::size_t ent = *off + i * 28;
                    const uint32_t dtype = u32le(b, ent + 12);
                    const std::size_t dsize = u32le(b, ent + 16);
                    const std::size_t drptr = u32le(b, ent + 24);
                    if (dtype == 2 && dsize >= 24)
                    {
                        if (b[drptr] == 'R' && b[drptr + 1] == 'S'
                            && b[drptr + 2] == 'D' && b[drptr + 3] == 'S')
                        {
                            for (std::size_t g = 0; g < 16; ++g)
                            {
                                info.guid[g] = b[drptr + 4 + g];
                            }
                            info.age = u32le(b, drptr + 20);
                            info.has_rsds = true;
                        }
                    }
                }
            }
        }

        info.section_headers.assign(
            b.begin() + static_cast<std::ptrdiff_t>(sec_off),
            b.begin() + static_cast<std::ptrdiff_t>(sec_off + nsec * 40));
        return info;
    }

    std::optional<seg_off_result> pe_info::seg_off(uint32_t rva) const
    {
        for (const pe_section & s : sections)
        {
            if (rva >= s.vaddr && rva < s.vaddr + s.vsize)
            {
                return seg_off_result{s.seg, rva - s.vaddr, s.vaddr + s.vsize};
            }
        }
        return std::nullopt;
    }
}
