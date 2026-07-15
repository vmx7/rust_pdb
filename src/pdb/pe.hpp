#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace il2pdb
{
    struct pe_section
    {
        uint32_t vaddr;
        uint32_t vsize;
        uint16_t seg;
    };

    struct seg_off_result
    {
        uint16_t seg;
        uint32_t off;
        uint32_t sec_end;
    };

    struct pe_info
    {
        std::vector<pe_section> sections{};
        std::array<uint8_t, 16> guid{};
        uint32_t age = 1;
        bool has_rsds = false;
        std::vector<uint8_t> section_headers{};

        [[nodiscard]] std::optional<seg_off_result> seg_off(uint32_t rva) const;
    };

    [[nodiscard]] pe_info pe_parse(std::string_view path);
}
