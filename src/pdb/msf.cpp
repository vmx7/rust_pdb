#include "msf.hpp"

#include <algorithm>
#include <array>
#include <cstddef>

namespace il2pdb
{
    namespace
    {
        constexpr std::size_t block_size = 4096;

        constexpr std::array<uint8_t, 32> magic = {
            'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'C', '/', 'C', '+', '+', ' ',
            'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', 0x1A, 'D', 'S', 0, 0, 0};

        std::size_t num_blocks(std::size_t len)
        {
            return (len + block_size - 1) / block_size;
        }

        bool is_fpm(std::size_t block)
        {
            const std::size_t m = block % block_size;
            return m == 1 || m == 2;
        }

        class allocator
        {
        public:
            uint32_t one()
            {
                while (is_fpm(next_))
                {
                    ++next_;
                }
                const std::size_t b = next_;
                ++next_;
                return static_cast<uint32_t>(b);
            }

            std::vector<uint32_t> many(std::size_t n)
            {
                std::vector<uint32_t> out{};
                out.reserve(n);
                for (std::size_t i = 0; i < n; ++i)
                {
                    out.push_back(one());
                }
                return out;
            }

            [[nodiscard]] std::size_t next() const noexcept
            {
                return next_;
            }

        private:
            std::size_t next_ = 1;
        };

        void le32(std::vector<uint8_t> & v, uint32_t x)
        {
            v.push_back(static_cast<uint8_t>(x & 0xFF));
            v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
            v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
            v.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
        }

        void put32(std::vector<uint8_t> & file, std::size_t off, uint32_t val)
        {
            file[off] = static_cast<uint8_t>(val & 0xFF);
            file[off + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
            file[off + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
            file[off + 3] = static_cast<uint8_t>((val >> 24) & 0xFF);
        }
    }

    std::vector<uint8_t> msf_build(const std::vector<std::vector<uint8_t>> & streams)
    {
        allocator alloc{};

        std::vector<std::vector<uint32_t>> stream_blocks{};
        stream_blocks.reserve(streams.size());
        for (const auto & s : streams)
        {
            stream_blocks.push_back(alloc.many(num_blocks(s.size())));
        }

        std::vector<uint8_t> dir{};
        le32(dir, static_cast<uint32_t>(streams.size()));
        for (const auto & s : streams)
        {
            le32(dir, static_cast<uint32_t>(s.size()));
        }
        for (const auto & blks : stream_blocks)
        {
            for (const uint32_t b : blks)
            {
                le32(dir, b);
            }
        }

        const std::vector<uint32_t> dir_blocks = alloc.many(num_blocks(dir.size()));
        std::vector<uint8_t> blockmap{};
        for (const uint32_t b : dir_blocks)
        {
            le32(blockmap, b);
        }
        const std::vector<uint32_t> blockmap_blocks =
            alloc.many(num_blocks(std::max<std::size_t>(blockmap.size(), 1)));
        const uint32_t block_map_addr = blockmap_blocks[0];

        const std::size_t total_blocks = alloc.next();

        std::vector<uint8_t> file(total_blocks * block_size, 0);

        std::copy(magic.begin(), magic.end(), file.begin());
        put32(file, 32, static_cast<uint32_t>(block_size));
        put32(file, 36, 1);
        put32(file, 40, static_cast<uint32_t>(total_blocks));
        put32(file, 44, static_cast<uint32_t>(dir.size()));
        put32(file, 48, 0);
        put32(file, 52, block_map_addr);

        const auto write_blocks =
            [&file](const std::vector<uint32_t> & blocks, const std::vector<uint8_t> & data)
        {
            for (std::size_t i = 0; i < blocks.size(); ++i)
            {
                const std::size_t src_off = i * block_size;
                const std::size_t src_end = std::min((i + 1) * block_size, data.size());
                const std::size_t dst = static_cast<std::size_t>(blocks[i]) * block_size;
                std::copy(data.begin() + static_cast<std::ptrdiff_t>(src_off),
                    data.begin() + static_cast<std::ptrdiff_t>(src_end),
                    file.begin() + static_cast<std::ptrdiff_t>(dst));
            }
        };

        for (std::size_t i = 0; i < streams.size(); ++i)
        {
            write_blocks(stream_blocks[i], streams[i]);
        }
        write_blocks(dir_blocks, dir);
        write_blocks(blockmap_blocks, blockmap);

        std::vector<bool> used(total_blocks, false);
        used[0] = true;
        for (std::size_t b = 0; b < total_blocks; ++b)
        {
            if (is_fpm(b))
            {
                used[b] = true;
            }
        }
        for (const auto & blks : stream_blocks)
        {
            for (const uint32_t b : blks)
            {
                used[b] = true;
            }
        }
        for (const uint32_t b : dir_blocks)
        {
            used[b] = true;
        }
        for (const uint32_t b : blockmap_blocks)
        {
            used[b] = true;
        }

        constexpr std::size_t fpm_cover = block_size * 8;
        const std::size_t num_fpm = (total_blocks + fpm_cover - 1) / fpm_cover;

        std::size_t pos = 1;
        while (pos < total_blocks)
        {
            for (std::size_t byte = 0; byte < block_size; ++byte)
            {
                file[pos * block_size + byte] = 0xFF;
            }
            pos += (pos % block_size == 1) ? 1 : (block_size - 1);
        }
        for (std::size_t k = 0; k < num_fpm; ++k)
        {
            const std::size_t fpm_index = 1 + k * block_size;
            const std::size_t base = fpm_index * block_size;
            for (std::size_t byte = 0; byte < block_size; ++byte)
            {
                uint8_t v = 0;
                for (std::size_t bit = 0; bit < 8; ++bit)
                {
                    const std::size_t blk = k * fpm_cover + byte * 8 + bit;
                    const bool is_free = (blk < total_blocks) ? !used[blk] : true;
                    if (is_free)
                    {
                        v = static_cast<uint8_t>(v | (1u << bit));
                    }
                }
                file[base + byte] = v;
            }
        }

        return file;
    }
}
