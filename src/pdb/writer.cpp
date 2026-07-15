#include "writer.hpp"

namespace il2pdb
{
    void byte_writer::u8(uint8_t v)
    {
        buf_.push_back(v);
    }

    void byte_writer::u16(uint16_t v)
    {
        buf_.push_back(static_cast<uint8_t>(v & 0xFF));
        buf_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    }

    void byte_writer::u32(uint32_t v)
    {
        buf_.push_back(static_cast<uint8_t>(v & 0xFF));
        buf_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf_.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf_.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    }

    void byte_writer::i32(int32_t v)
    {
        u32(static_cast<uint32_t>(v));
    }

    void byte_writer::bytes(std::span<const uint8_t> b)
    {
        buf_.insert(buf_.end(), b.begin(), b.end());
    }

    void byte_writer::cstr(std::string_view s)
    {
        for (const char ch : s)
        {
            buf_.push_back(static_cast<uint8_t>(ch));
        }
        buf_.push_back(0);
    }

    std::size_t byte_writer::size() const noexcept
    {
        return buf_.size();
    }

    const std::vector<uint8_t> & byte_writer::data() const noexcept
    {
        return buf_;
    }

    std::vector<uint8_t> & byte_writer::data() noexcept
    {
        return buf_;
    }

    void pad_type(std::vector<uint8_t> & body)
    {
        const std::size_t rem = body.size() % 4;
        if (rem != 0)
        {
            const std::size_t pad = 4 - rem;
            for (std::size_t i = pad; i >= 1; --i)
            {
                body.push_back(static_cast<uint8_t>(0xF0 | i));
            }
        }
    }

    void pad_sym(std::vector<uint8_t> & body)
    {
        while (body.size() % 4 != 0)
        {
            body.push_back(0);
        }
    }

    std::vector<uint8_t> frame(uint16_t kind, std::span<const uint8_t> body)
    {
        const uint16_t len = static_cast<uint16_t>(2 + body.size());
        std::vector<uint8_t> out{};
        out.reserve(static_cast<std::size_t>(2) + body.size());
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(kind & 0xFF));
        out.push_back(static_cast<uint8_t>((kind >> 8) & 0xFF));
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }

    uint32_t hash_string_v1(std::span<const uint8_t> s) noexcept
    {
        uint32_t result = 0;
        const std::size_t n_longs = s.size() / 4;
        for (std::size_t i = 0; i < n_longs; ++i)
        {
            const std::size_t off = i * 4;
            const uint32_t v = static_cast<uint32_t>(s[off])
                | (static_cast<uint32_t>(s[off + 1]) << 8)
                | (static_cast<uint32_t>(s[off + 2]) << 16)
                | (static_cast<uint32_t>(s[off + 3]) << 24);
            result ^= v;
        }
        std::size_t rem_off = n_longs * 4;
        std::size_t rem_len = s.size() - rem_off;
        if (rem_len >= 2)
        {
            const uint32_t v = static_cast<uint32_t>(s[rem_off])
                | (static_cast<uint32_t>(s[rem_off + 1]) << 8);
            result ^= v;
            rem_off += 2;
            rem_len -= 2;
        }
        if (rem_len == 1)
        {
            result ^= static_cast<uint32_t>(s[rem_off]);
        }
        result |= 0x20202020u;
        result ^= result >> 11;
        result ^= result << 16;
        return result;
    }
}
