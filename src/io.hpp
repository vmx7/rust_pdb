#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace il2pdb
{
    [[nodiscard]] std::vector<uint8_t> read_bytes(std::string_view path);
    [[nodiscard]] std::string read_text(std::string_view path);
    void write_bytes(std::string_view path, std::span<const uint8_t> data);
}
