#include "gsi.hpp"

#include "writer.hpp"

#include <algorithm>
#include <cstddef>
#include <span>

namespace il2pdb
{
    namespace
    {
        constexpr uint16_t s_pub32_kind = 0x110E;
        constexpr uint16_t s_procref_kind = 0x1125;
        constexpr uint16_t s_gdata32_kind = 0x110D;
        constexpr uint32_t iphr_hash = 4096;

        struct entry
        {
            uint32_t off;
            uint32_t name_hash;
            std::vector<uint8_t> name;
        };

        std::span<const uint8_t> as_bytes(const std::string & s)
        {
            return std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(s.data()), s.size());
        }

        std::vector<uint8_t> s_pub32(const proc & p)
        {
            byte_writer b{};
            b.u32(0x2);
            b.u32(p.off);
            b.u16(p.seg);
            b.cstr(p.name);
            pad_sym(b.data());
            return frame(s_pub32_kind, b.data());
        }

        std::vector<uint8_t> s_pub32_data(const data_sym & d)
        {
            byte_writer b{};
            b.u32(0);
            b.u32(d.off);
            b.u16(d.seg);
            b.cstr(d.name);
            pad_sym(b.data());
            return frame(s_pub32_kind, b.data());
        }

        std::vector<uint8_t> s_gdata32(const data_sym & d)
        {
            byte_writer b{};
            b.u32(d.type_index);
            b.u32(d.off);
            b.u16(d.seg);
            b.cstr(d.name);
            pad_sym(b.data());
            return frame(s_gdata32_kind, b.data());
        }

        std::vector<uint8_t> s_procref(const proc & p, uint32_t mod_off)
        {
            byte_writer b{};
            b.u32(0);
            b.u32(mod_off);
            b.u16(1);
            b.cstr(p.name);
            pad_sym(b.data());
            return frame(s_procref_kind, b.data());
        }

        std::vector<uint8_t> build_hash(const std::vector<entry> & entries)
        {
            std::vector<std::vector<std::size_t>> buckets(iphr_hash);
            for (std::size_t i = 0; i < entries.size(); ++i)
            {
                buckets[entries[i].name_hash % iphr_hash].push_back(i);
            }
            for (std::vector<std::size_t> & b : buckets)
            {
                std::stable_sort(b.begin(), b.end(),
                    [&entries](std::size_t a, std::size_t c)
                    {
                        const std::vector<uint8_t> & na = entries[a].name;
                        const std::vector<uint8_t> & nc = entries[c].name;
                        if (na.size() != nc.size())
                        {
                            return na.size() < nc.size();
                        }
                        if (na != nc)
                        {
                            return na < nc;
                        }
                        return entries[a].off < entries[c].off;
                    });
            }

            byte_writer hash_records{};
            byte_writer bucket_offsets{};
            std::vector<uint32_t> bitmap(iphr_hash / 32 + 1, 0);
            uint32_t rec_index = 0;
            for (std::size_t bi = 0; bi < buckets.size(); ++bi)
            {
                const std::vector<std::size_t> & b = buckets[bi];
                if (b.empty())
                {
                    continue;
                }
                bitmap[bi / 32] |= (1u << (bi % 32));
                bucket_offsets.u32(rec_index * 12);
                for (const std::size_t i : b)
                {
                    hash_records.u32(entries[i].off + 1);
                    hash_records.u32(1);
                    ++rec_index;
                }
            }

            byte_writer bucket_section{};
            for (const uint32_t w : bitmap)
            {
                bucket_section.u32(w);
            }
            bucket_section.bytes(bucket_offsets.data());

            byte_writer out{};
            out.u32(0xFFFFFFFF);
            out.u32(0xF12F091A);
            out.u32(static_cast<uint32_t>(hash_records.size()));
            out.u32(static_cast<uint32_t>(bucket_section.size()));
            out.bytes(hash_records.data());
            out.bytes(bucket_section.data());
            return out.data();
        }
    }

    gsi_streams gsi_build(const std::vector<proc> & procs,
        const std::vector<uint32_t> & proc_mod_offsets, const std::vector<data_sym> & data_syms)
    {
        byte_writer sym{};
        std::vector<entry> pub_entries{};
        std::vector<entry> ref_entries{};
        std::vector<uint16_t> pub_seg{};
        std::vector<uint32_t> pub_off{};
        pub_entries.reserve(procs.size() + data_syms.size());
        ref_entries.reserve(procs.size());

        for (const proc & p : procs)
        {
            const uint32_t off = static_cast<uint32_t>(sym.size());
            sym.bytes(s_pub32(p));
            const std::vector<uint8_t> nm(p.name.begin(), p.name.end());
            pub_entries.push_back(entry{off, hash_string_v1(as_bytes(p.name)), nm});
            pub_seg.push_back(p.seg);
            pub_off.push_back(p.off);
        }
        for (const data_sym & d : data_syms)
        {
            const uint32_t off = static_cast<uint32_t>(sym.size());
            sym.bytes(s_pub32_data(d));
            const std::vector<uint8_t> nm(d.name.begin(), d.name.end());
            pub_entries.push_back(entry{off, hash_string_v1(as_bytes(d.name)), nm});
            pub_seg.push_back(d.seg);
            pub_off.push_back(d.off);
        }
        for (std::size_t i = 0; i < procs.size(); ++i)
        {
            const proc & p = procs[i];
            const uint32_t off = static_cast<uint32_t>(sym.size());
            sym.bytes(s_procref(p, proc_mod_offsets[i]));
            const std::vector<uint8_t> nm(p.name.begin(), p.name.end());
            ref_entries.push_back(entry{off, hash_string_v1(as_bytes(p.name)), nm});
        }
        for (const data_sym & d : data_syms)
        {
            const uint32_t off = static_cast<uint32_t>(sym.size());
            sym.bytes(s_gdata32(d));
            const std::vector<uint8_t> nm(d.name.begin(), d.name.end());
            ref_entries.push_back(entry{off, hash_string_v1(as_bytes(d.name)), nm});
        }

        const std::vector<uint8_t> globals = build_hash(ref_entries);
        const std::vector<uint8_t> pub_hash = build_hash(pub_entries);

        std::vector<std::size_t> addr_order(pub_entries.size());
        for (std::size_t i = 0; i < pub_entries.size(); ++i)
        {
            addr_order[i] = i;
        }
        std::stable_sort(addr_order.begin(), addr_order.end(),
            [&pub_seg, &pub_off](std::size_t a, std::size_t b)
            {
                if (pub_seg[a] != pub_seg[b])
                {
                    return pub_seg[a] < pub_seg[b];
                }
                return pub_off[a] < pub_off[b];
            });
        byte_writer addrmap{};
        for (const std::size_t i : addr_order)
        {
            addrmap.u32(pub_entries[i].off);
        }

        byte_writer publics{};
        publics.u32(static_cast<uint32_t>(pub_hash.size()));
        publics.u32(static_cast<uint32_t>(addrmap.size()));
        publics.u32(0);
        publics.u32(0);
        publics.u16(0);
        publics.u16(0);
        publics.u32(0);
        publics.u32(0);
        publics.bytes(pub_hash);
        publics.bytes(addrmap.data());

        return gsi_streams{sym.data(), globals, publics.data()};
    }
}
