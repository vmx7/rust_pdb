#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace il2pdb
{
    class byte_writer
    {
    public:
        void u8(uint8_t v);
        void u16(uint16_t v);
        void u32(uint32_t v);
        void i32(int32_t v);
        void bytes(std::span<const uint8_t> b);
        void cstr(std::string_view s);

        [[nodiscard]] std::size_t size() const noexcept;
        [[nodiscard]] const std::vector<uint8_t> & data() const noexcept;
        [[nodiscard]] std::vector<uint8_t> & data() noexcept;

    private:
        std::vector<uint8_t> buf_{};
    };

    void pad_type(std::vector<uint8_t> & body);
    void pad_sym(std::vector<uint8_t> & body);
    [[nodiscard]] std::vector<uint8_t> frame(uint16_t kind, std::span<const uint8_t> body);
    [[nodiscard]] uint32_t hash_string_v1(std::span<const uint8_t> s) noexcept;
}
