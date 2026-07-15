#pragma once

#include "proc.hpp"
#include "tpi.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace il2pdb
{
    struct build_input
    {
        std::array<uint8_t, 16> guid;
        uint32_t age;
        std::vector<proc> procs;
        std::vector<type_rec> types;
        std::vector<uint8_t> section_headers;
        std::vector<data_sym> data_syms;
    };

    [[nodiscard]] std::vector<uint8_t> build_pdb(const build_input & input);
}
