#include "tpi.hpp"

#include "writer.hpp"

#include <limits>

namespace il2pdb
{
    namespace
    {
        constexpr uint16_t lf_pointer = 0x1002;
        constexpr uint16_t lf_procedure = 0x1008;
        constexpr uint16_t lf_arglist = 0x1201;
        constexpr uint16_t lf_fieldlist = 0x1203;
        constexpr uint16_t lf_array = 0x1503;
        constexpr uint16_t lf_structure = 0x1505;
        constexpr uint16_t lf_union = 0x1506;
        constexpr uint16_t lf_member = 0x150D;
        constexpr uint16_t lf_index = 0x1404;
        constexpr uint16_t lf_enum = 0x1507;
        constexpr uint16_t lf_enumerate = 0x1502;

        constexpr uint16_t cv_prop_fwdref = 0x80;
        constexpr uint16_t cv_prop_has_unique_name = 0x200;

        void numeric(byte_writer & w, uint64_t v)
        {
            if (v < 0x8000)
            {
                w.u16(static_cast<uint16_t>(v));
            }
            else if (v <= 0xFFFF)
            {
                w.u16(0x8002);
                w.u16(static_cast<uint16_t>(v));
            }
            else if (v <= 0xFFFFFFFF)
            {
                w.u16(0x8004);
                w.u32(static_cast<uint32_t>(v));
            }
            else
            {
                w.u16(0x800A);
                for (int i = 0; i < 8; ++i)
                {
                    w.u8(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
                }
            }
        }

        void numeric_signed(byte_writer & w, int64_t v)
        {
            if (v >= 0 && v < 0x8000)
            {
                w.u16(static_cast<uint16_t>(v));
            }
            else if (v < 0)
            {
                if (v >= -128)
                {
                    w.u16(0x8000);
                    w.u8(static_cast<uint8_t>(static_cast<int8_t>(v)));
                }
                else if (v >= -32768)
                {
                    w.u16(0x8001);
                    w.u16(static_cast<uint16_t>(static_cast<int16_t>(v)));
                }
                else if (v >= static_cast<int64_t>(std::numeric_limits<int32_t>::min()))
                {
                    w.u16(0x8003);
                    w.u32(static_cast<uint32_t>(static_cast<int32_t>(v)));
                }
                else
                {
                    w.u16(0x8009);
                    for (int i = 0; i < 8; ++i)
                    {
                        w.u8(static_cast<uint8_t>((static_cast<uint64_t>(v) >> (8 * i)) & 0xFF));
                    }
                }
            }
            else if (v <= 0xFFFF)
            {
                w.u16(0x8002);
                w.u16(static_cast<uint16_t>(v));
            }
            else if (v <= 0xFFFFFFFF)
            {
                w.u16(0x8004);
                w.u32(static_cast<uint32_t>(v));
            }
            else
            {
                w.u16(0x800A);
                for (int i = 0; i < 8; ++i)
                {
                    w.u8(static_cast<uint8_t>((static_cast<uint64_t>(v) >> (8 * i)) & 0xFF));
                }
            }
        }

        type_rec finish(uint16_t kind, std::vector<uint8_t> body,
            std::optional<std::string> name, bool fwdref)
        {
            pad_type(body);
            return type_rec{frame(kind, body), kind, std::move(name), fwdref};
        }

        uint32_t hash_buffer_v8(std::span<const uint8_t> data)
        {
            return hash_string_v1(data.subspan(2));
        }

        uint32_t hash_record(const type_rec & r, uint32_t buckets)
        {
            uint32_t h = 0;
            if ((r.kind == lf_structure || r.kind == lf_union || r.kind == lf_enum) && !r.fwdref)
            {
                if (r.name.has_value())
                {
                    const std::string & n = *r.name;
                    h = hash_string_v1(std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(n.data()), n.size()));
                }
                else
                {
                    h = hash_buffer_v8(r.bytes);
                }
            }
            else
            {
                h = hash_buffer_v8(r.bytes);
            }
            return h % buckets;
        }
    }

    type_rec ptr64(uint32_t referent)
    {
        byte_writer b{};
        b.u32(referent);
        b.u32(0x1000C);
        return finish(lf_pointer, b.data(), std::nullopt, false);
    }

    type_rec arglist(std::span<const uint32_t> args)
    {
        byte_writer b{};
        b.u32(static_cast<uint32_t>(args.size()));
        for (const uint32_t a : args)
        {
            b.u32(a);
        }
        return finish(lf_arglist, b.data(), std::nullopt, false);
    }

    type_rec procedure(uint32_t ret, uint32_t arglist_ti, uint16_t nparams)
    {
        byte_writer b{};
        b.u32(ret);
        b.u8(0);
        b.u8(0);
        b.u16(nparams);
        b.u32(arglist_ti);
        return finish(lf_procedure, b.data(), std::nullopt, false);
    }

    type_rec fieldlist(std::span<const member> members)
    {
        return fieldlist_cont(members, std::nullopt);
    }

    type_rec fieldlist_cont(std::span<const member> members, std::optional<uint32_t> cont)
    {
        byte_writer b{};
        for (const member & m : members)
        {
            b.u16(lf_member);
            b.u16(3);
            b.u32(m.ty);
            numeric(b, m.offset);
            b.cstr(m.name);
            const std::size_t rem = b.size() % 4;
            if (rem != 0)
            {
                for (std::size_t i = 4 - rem; i >= 1; --i)
                {
                    b.u8(static_cast<uint8_t>(0xF0 | i));
                }
            }
        }
        if (cont.has_value())
        {
            b.u16(lf_index);
            b.u16(0);
            b.u32(*cont);
        }
        return finish(lf_fieldlist, b.data(), std::nullopt, false);
    }

    type_rec struct_fwdref(std::string_view name, std::string_view unique)
    {
        byte_writer b{};
        b.u16(0);
        b.u16(cv_prop_fwdref | cv_prop_has_unique_name);
        b.u32(0);
        b.u32(0);
        b.u32(0);
        numeric(b, 0);
        b.cstr(name);
        b.cstr(unique);
        return finish(lf_structure, b.data(), std::string(name), true);
    }

    type_rec struct_def(std::string_view name, std::string_view unique,
        uint16_t count, uint32_t fieldlist_ti, uint64_t size)
    {
        byte_writer b{};
        b.u16(count);
        b.u16(cv_prop_has_unique_name);
        b.u32(fieldlist_ti);
        b.u32(0);
        b.u32(0);
        numeric(b, size);
        b.cstr(name);
        b.cstr(unique);
        return finish(lf_structure, b.data(), std::string(name), false);
    }

    type_rec union_fwdref(std::string_view name, std::string_view unique)
    {
        byte_writer b{};
        b.u16(0);
        b.u16(cv_prop_fwdref | cv_prop_has_unique_name);
        b.u32(0);
        numeric(b, 0);
        b.cstr(name);
        b.cstr(unique);
        return finish(lf_union, b.data(), std::string(name), true);
    }

    type_rec union_def(std::string_view name, std::string_view unique,
        uint16_t count, uint32_t fieldlist_ti, uint64_t size)
    {
        byte_writer b{};
        b.u16(count);
        b.u16(cv_prop_has_unique_name);
        b.u32(fieldlist_ti);
        numeric(b, size);
        b.cstr(name);
        b.cstr(unique);
        return finish(lf_union, b.data(), std::string(name), false);
    }

    type_rec array_type(uint32_t elem, uint64_t size)
    {
        byte_writer b{};
        b.u32(elem);
        b.u32(t_uquad_idx);
        numeric(b, size);
        b.cstr("");
        return finish(lf_array, b.data(), std::nullopt, false);
    }

    type_rec enum_fieldlist(std::span<const enum_member> members)
    {
        byte_writer b{};
        for (const enum_member & m : members)
        {
            b.u16(lf_enumerate);
            b.u16(3);
            numeric_signed(b, m.value);
            b.cstr(m.name);
            const std::size_t rem = b.size() % 4;
            if (rem != 0)
            {
                for (std::size_t i = 4 - rem; i >= 1; --i)
                {
                    b.u8(static_cast<uint8_t>(0xF0 | i));
                }
            }
        }
        return finish(lf_fieldlist, b.data(), std::nullopt, false);
    }

    type_rec enum_def(std::string_view name, std::string_view unique, uint32_t underlying,
        uint16_t count, uint32_t fieldlist_ti)
    {
        byte_writer b{};
        b.u16(count);
        b.u16(cv_prop_has_unique_name);
        b.u32(underlying);
        b.u32(fieldlist_ti);
        b.cstr(name);
        b.cstr(unique);
        return finish(lf_enum, b.data(), std::string(name), false);
    }

    tpi_streams build_tpi(const std::vector<type_rec> & records, uint16_t hash_stream_index)
    {
        constexpr uint32_t buckets = 0x3FFFF;

        std::vector<uint8_t> recbytes{};
        byte_writer hashvals{};
        byte_writer indexoff{};
        int64_t last_emit = -1;
        for (std::size_t i = 0; i < records.size(); ++i)
        {
            const type_rec & r = records[i];
            const uint32_t ti = 0x1000 + static_cast<uint32_t>(i);
            if (last_emit < 0
                || (static_cast<int64_t>(recbytes.size()) - last_emit) >= 8192)
            {
                indexoff.u32(ti);
                indexoff.u32(static_cast<uint32_t>(recbytes.size()));
                last_emit = static_cast<int64_t>(recbytes.size());
            }
            recbytes.insert(recbytes.end(), r.bytes.begin(), r.bytes.end());
            hashvals.u32(hash_record(r, buckets));
        }
        const uint32_t type_index_end = 0x1000 + static_cast<uint32_t>(records.size());

        const uint32_t hv_off = 0;
        const uint32_t hv_len = static_cast<uint32_t>(hashvals.size());
        const uint32_t io_off = hv_len;
        const uint32_t io_len = static_cast<uint32_t>(indexoff.size());

        std::vector<uint8_t> hash{};
        hash.insert(hash.end(), hashvals.data().begin(), hashvals.data().end());
        hash.insert(hash.end(), indexoff.data().begin(), indexoff.data().end());

        byte_writer h{};
        h.u32(20040203);
        h.u32(56);
        h.u32(0x1000);
        h.u32(type_index_end);
        h.u32(static_cast<uint32_t>(recbytes.size()));
        h.u16(hash_stream_index);
        h.u16(0xFFFF);
        h.u32(4);
        h.u32(buckets);
        h.u32(hv_off);
        h.u32(hv_len);
        h.u32(io_off);
        h.u32(io_len);
        h.u32(0);
        h.u32(0);

        std::vector<uint8_t> tpi = h.data();
        tpi.insert(tpi.end(), recbytes.begin(), recbytes.end());

        return tpi_streams{std::move(tpi), std::move(hash), type_index_end};
    }
}
