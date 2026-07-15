#pragma once

#include <cstdint>
#include <vector>

namespace il2pdb
{
    [[nodiscard]] std::vector<uint8_t> msf_build(const std::vector<std::vector<uint8_t>> & streams);
}
