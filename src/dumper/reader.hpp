#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace il2pdb::dump
{
    class byte_reader
    {
    public:
        explicit byte_reader(std::vector<uint8_t> data) : data_(std::move(data))
        {
        }

        [[nodiscard]] const std::vector<uint8_t> & data() const noexcept
        {
            return data_;
        }

        [[nodiscard]] std::size_t pos() const noexcept
        {
            return pos_;
        }

        void seek(std::size_t p) noexcept
        {
            pos_ = p;
        }

        uint8_t u8()
        {
            return data_.at(pos_++);
        }

        uint16_t u16()
        {
            const uint16_t v = static_cast<uint16_t>(data_.at(pos_) | (data_.at(pos_ + 1) << 8));
            pos_ += 2;
            return v;
        }

        uint32_t u32()
        {
            const uint32_t v = static_cast<uint32_t>(data_.at(pos_))
                | (static_cast<uint32_t>(data_.at(pos_ + 1)) << 8)
                | (static_cast<uint32_t>(data_.at(pos_ + 2)) << 16)
                | (static_cast<uint32_t>(data_.at(pos_ + 3)) << 24);
            pos_ += 4;
            return v;
        }

        int16_t i16()
        {
            return static_cast<int16_t>(u16());
        }

        int32_t i32()
        {
            return static_cast<int32_t>(u32());
        }

        uint64_t u64()
        {
            const uint64_t lo = u32();
            const uint64_t hi = u32();
            return lo | (hi << 32);
        }

        int32_t index(int size)
        {
            if (size == 1)
            {
                const uint8_t v = u8();
                return v == 0xFF ? -1 : static_cast<int32_t>(v);
            }
            if (size == 2)
            {
                const uint16_t v = u16();
                return v == 0xFFFF ? -1 : static_cast<int32_t>(v);
            }
            const uint32_t v = u32();
            return v == 0xFFFFFFFFu ? -1 : static_cast<int32_t>(v);
        }

        [[nodiscard]] uint8_t u8_at(std::size_t off) const
        {
            return off < data_.size() ? data_[off] : 0;
        }

        [[nodiscard]] uint16_t u16_at(std::size_t off) const
        {
            return static_cast<uint16_t>(u8_at(off) | (u8_at(off + 1) << 8));
        }

        [[nodiscard]] uint32_t u32_at(std::size_t off) const
        {
            return static_cast<uint32_t>(u8_at(off)) | (static_cast<uint32_t>(u8_at(off + 1)) << 8)
                | (static_cast<uint32_t>(u8_at(off + 2)) << 16)
                | (static_cast<uint32_t>(u8_at(off + 3)) << 24);
        }

        [[nodiscard]] uint64_t u64_at(std::size_t off) const
        {
            return static_cast<uint64_t>(u32_at(off))
                | (static_cast<uint64_t>(u32_at(off + 4)) << 32);
        }

        [[nodiscard]] uint32_t compressed_u32_at(std::size_t & off) const
        {
            const uint8_t read = u8_at(off++);
            if ((read & 0x80) == 0)
            {
                return read;
            }
            if ((read & 0xC0) == 0x80)
            {
                uint32_t v = static_cast<uint32_t>(read & ~0x80u) << 8;
                v |= u8_at(off++);
                return v;
            }
            if ((read & 0xE0) == 0xC0)
            {
                uint32_t v = static_cast<uint32_t>(read & ~0xC0u) << 24;
                v |= static_cast<uint32_t>(u8_at(off++)) << 16;
                v |= static_cast<uint32_t>(u8_at(off++)) << 8;
                v |= u8_at(off++);
                return v;
            }
            if (read == 0xF0)
            {
                const uint32_t v = u32_at(off);
                off += 4;
                return v;
            }
            if (read == 0xFE)
            {
                return 0xFFFFFFFEu;
            }
            return 0xFFFFFFFFu;
        }

        [[nodiscard]] std::string cstr_at(std::size_t off) const
        {
            std::string out{};
            std::size_t i = off;
            while (i < data_.size() && data_[i] != 0)
            {
                out.push_back(static_cast<char>(data_[i]));
                ++i;
            }
            return out;
        }

    private:
        std::vector<uint8_t> data_;
        std::size_t pos_ = 0;
    };
}
