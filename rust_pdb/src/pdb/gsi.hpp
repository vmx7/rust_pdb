#pragma once

#include "proc.hpp"

#include <cstdint>
#include <vector>

namespace il2pdb
{
    struct gsi_streams
    {
        std::vector<uint8_t> symrecord;
        std::vector<uint8_t> globals;
        std::vector<uint8_t> publics;
    };

    [[nodiscard]] gsi_streams gsi_build(const std::vector<proc> & procs,
        const std::vector<uint32_t> & proc_mod_offsets, const std::vector<data_sym> & data_syms);
}
