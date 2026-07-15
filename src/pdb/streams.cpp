#include "streams.hpp"

#include "gsi.hpp"
#include "msf.hpp"
#include "writer.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace il2pdb
{
    namespace
    {
        constexpr std::size_t stream_old_dir = 0;
        constexpr std::size_t stream_pdb = 1;
        constexpr std::size_t stream_tpi = 2;
        constexpr std::size_t stream_dbi = 3;
        constexpr std::size_t stream_ipi = 4;
        constexpr std::size_t stream_names = 5;
        constexpr std::size_t stream_module = 6;
        constexpr std::size_t stream_tpi_hash = 7;
        constexpr std::size_t stream_globals = 8;
        constexpr std::size_t stream_publics = 9;
        constexpr std::size_t stream_symrecord = 10;
        constexpr std::size_t stream_sechdr = 11;

        constexpr uint16_t s_end = 0x0006;
        constexpr uint16_t s_gproc32 = 0x1110;

        struct module_stream
        {
            std::vector<uint8_t> bytes;
            uint32_t sym_byte_size;
            std::vector<uint32_t> proc_offsets;
        };

        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> build_named_map(
            std::string_view name, uint32_t value)
        {
            std::vector<uint8_t> strbuf{};
            const uint32_t name_off = static_cast<uint32_t>(strbuf.size());
            for (const char ch : name)
            {
                strbuf.push_back(static_cast<uint8_t>(ch));
            }
            strbuf.push_back(0);

            const std::size_t size = 1;
            const std::size_t capacity = size * 2 > 1 ? size * 2 : 1;
            std::vector<std::optional<std::pair<uint32_t, uint32_t>>> buckets(capacity);
            {
                const std::span<const uint8_t> nb(
                    reinterpret_cast<const uint8_t*>(name.data()), name.size());
                std::size_t idx = hash_string_v1(nb) % capacity;
                while (buckets[idx].has_value())
                {
                    idx = (idx + 1) % capacity;
                }
                buckets[idx] = std::make_pair(name_off, value);
            }

            byte_writer t{};
            t.u32(static_cast<uint32_t>(size));
            t.u32(static_cast<uint32_t>(capacity));
            const std::size_t words = (capacity + 31) / 32;
            t.u32(static_cast<uint32_t>(words));
            for (std::size_t wi = 0; wi < words; ++wi)
            {
                uint32_t word = 0;
                for (std::size_t bit = 0; bit < 32; ++bit)
                {
                    const std::size_t b = wi * 32 + bit;
                    if (b < capacity && buckets[b].has_value())
                    {
                        word |= (1u << bit);
                    }
                }
                t.u32(word);
            }
            t.u32(0);
            for (const auto & b : buckets)
            {
                if (b.has_value())
                {
                    t.u32(b->first);
                    t.u32(b->second);
                }
            }
            return {strbuf, t.data()};
        }

        std::vector<uint8_t> build_pdb_info(const std::array<uint8_t, 16> & guid, uint32_t age)
        {
            byte_writer w{};
            w.u32(20000404);
            w.u32(0);
            w.u32(age);
            w.bytes(guid);

            const auto [strbuf, table] = build_named_map("/names",
                static_cast<uint32_t>(stream_names));
            w.u32(static_cast<uint32_t>(strbuf.size()));
            w.bytes(strbuf);
            w.bytes(table);

            w.u32(20140508);
            return w.data();
        }

        std::vector<uint8_t> empty_type_stream()
        {
            byte_writer w{};
            w.u32(20040203);
            w.u32(56);
            w.u32(0x1000);
            w.u32(0x1000);
            w.u32(0);
            w.u16(0xFFFF);
            w.u16(0xFFFF);
            w.u32(4);
            w.u32(0x3FFFF);
            w.u32(0);
            w.u32(0);
            w.u32(0);
            w.u32(0);
            w.u32(0);
            w.u32(0);
            return w.data();
        }

        std::vector<uint8_t> build_names_stream()
        {
            byte_writer w{};
            w.u32(0xEFFEEFFE);
            w.u32(1);
            w.u32(1);
            w.u8(0);
            w.u32(1);
            w.u32(0);
            w.u32(0);
            return w.data();
        }

        module_stream build_module_stream(const std::vector<proc> & procs)
        {
            byte_writer syms{};
            syms.u32(4);

            std::vector<uint32_t> proc_offsets{};
            proc_offsets.reserve(procs.size());
            for (const proc & p : procs)
            {
                proc_offsets.push_back(static_cast<uint32_t>(syms.size()));

                byte_writer b{};
                b.u32(0);
                b.u32(0);
                b.u32(0);
                b.u32(p.size);
                b.u32(0);
                b.u32(0);
                b.u32(p.type_index);
                b.u32(p.off);
                b.u16(p.seg);
                b.u8(0);
                b.cstr(p.name);
                pad_sym(b.data());
                std::vector<uint8_t> rec = frame(s_gproc32, b.data());

                const std::size_t proc_start = syms.size();
                const std::size_t end_offset = proc_start + rec.size();
                const std::size_t ptr_end_field = 2 + 2 + 4;
                const uint32_t eo = static_cast<uint32_t>(end_offset);
                rec[ptr_end_field] = static_cast<uint8_t>(eo & 0xFF);
                rec[ptr_end_field + 1] = static_cast<uint8_t>((eo >> 8) & 0xFF);
                rec[ptr_end_field + 2] = static_cast<uint8_t>((eo >> 16) & 0xFF);
                rec[ptr_end_field + 3] = static_cast<uint8_t>((eo >> 24) & 0xFF);
                syms.bytes(rec);

                const std::vector<uint8_t> endrec = frame(s_end, std::span<const uint8_t>{});
                syms.bytes(endrec);
            }

            const uint32_t sym_byte_size = static_cast<uint32_t>(syms.size());
            byte_writer w{};
            w.bytes(syms.data());
            w.u32(0);
            return module_stream{w.data(), sym_byte_size, std::move(proc_offsets)};
        }

        std::vector<uint8_t> dbi_modinfo(uint16_t module_sym_stream, uint32_t sym_byte_size)
        {
            byte_writer w{};
            w.u32(0);
            for (int i = 0; i < 28; ++i)
            {
                w.u8(0);
            }
            w.u16(0);
            w.u16(module_sym_stream);
            w.u32(sym_byte_size);
            w.u32(0);
            w.u32(0);
            w.u16(0);
            w.u16(0);
            w.u32(0);
            w.u32(0);
            w.u32(0);
            w.cstr("il2cpp");
            w.cstr("il2cpp");
            while (w.size() % 4 != 0)
            {
                w.u8(0);
            }
            return w.data();
        }

        std::vector<uint8_t> dbi_source_info()
        {
            byte_writer w{};
            w.u16(1);
            w.u16(0);
            w.u16(0);
            w.u16(0);
            while (w.size() % 4 != 0)
            {
                w.u8(0);
            }
            return w.data();
        }

        std::vector<uint8_t> dbi_optional_dbg_header(uint16_t sechdr_stream)
        {
            byte_writer w{};
            for (int i = 0; i < 11; ++i)
            {
                if (i == 5)
                {
                    w.u16(sechdr_stream);
                }
                else
                {
                    w.u16(0xFFFF);
                }
            }
            return w.data();
        }

        std::vector<uint8_t> build_dbi(uint16_t module_sym_stream, uint32_t sym_byte_size,
            uint16_t global_stream, uint16_t public_stream, uint16_t symrecord_stream,
            uint16_t sechdr_stream)
        {
            const std::vector<uint8_t> modinfo = dbi_modinfo(module_sym_stream, sym_byte_size);
            const std::vector<uint8_t> seccontrib{};
            const std::vector<uint8_t> secmap{};
            const std::vector<uint8_t> srcinfo = dbi_source_info();
            const std::vector<uint8_t> typeserver{};
            const std::vector<uint8_t> ec = build_names_stream();
            const std::vector<uint8_t> dbg_header = dbi_optional_dbg_header(sechdr_stream);

            byte_writer w{};
            w.i32(-1);
            w.u32(19990903);
            w.u32(1);
            w.u16(global_stream);
            w.u16(36363);
            w.u16(public_stream);
            w.u16(0);
            w.u16(symrecord_stream);
            w.u16(0);
            w.i32(static_cast<int32_t>(modinfo.size()));
            w.i32(static_cast<int32_t>(seccontrib.size()));
            w.i32(static_cast<int32_t>(secmap.size()));
            w.i32(static_cast<int32_t>(srcinfo.size()));
            w.i32(static_cast<int32_t>(typeserver.size()));
            w.u32(0);
            w.i32(static_cast<int32_t>(dbg_header.size()));
            w.i32(static_cast<int32_t>(ec.size()));
            w.u16(0);
            w.u16(0x8664);
            w.u32(0);

            w.bytes(modinfo);
            w.bytes(seccontrib);
            w.bytes(secmap);
            w.bytes(srcinfo);
            w.bytes(typeserver);
            w.bytes(ec);
            w.bytes(dbg_header);
            return w.data();
        }
    }

    std::vector<uint8_t> build_pdb(const build_input & input)
    {
        const module_stream module = build_module_stream(input.procs);
        const uint32_t sym_byte_size = module.sym_byte_size;

        std::vector<std::vector<uint8_t>> streams(12);
        const tpi_streams tpi = build_tpi(input.types, static_cast<uint16_t>(stream_tpi_hash));
        const gsi_streams gsi = gsi_build(input.procs, module.proc_offsets, input.data_syms);

        streams[stream_old_dir] = std::vector<uint8_t>{};
        streams[stream_pdb] = build_pdb_info(input.guid, input.age);
        streams[stream_tpi] = tpi.tpi;
        streams[stream_ipi] = empty_type_stream();
        streams[stream_names] = build_names_stream();
        streams[stream_module] = module.bytes;
        streams[stream_dbi] = build_dbi(
            static_cast<uint16_t>(stream_module), sym_byte_size,
            static_cast<uint16_t>(stream_globals), static_cast<uint16_t>(stream_publics),
            static_cast<uint16_t>(stream_symrecord), static_cast<uint16_t>(stream_sechdr));
        streams[stream_tpi_hash] = tpi.hash;
        streams[stream_globals] = gsi.globals;
        streams[stream_publics] = gsi.publics;
        streams[stream_symrecord] = gsi.symrecord;
        streams[stream_sechdr] = input.section_headers;

        return msf_build(streams);
    }
}
