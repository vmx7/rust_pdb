#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace il2pdb
{
    struct script_method
    {
        uint64_t address;
        std::string name;
        bool has_sig;
        std::string sig;
    };

    struct script
    {
        std::vector<script_method> methods;
        std::vector<uint64_t> addresses;
    };

    [[nodiscard]] script parse_script_json(const std::string & text);
}
