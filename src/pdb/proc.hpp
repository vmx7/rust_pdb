#pragma once

#include <cstdint>
#include <string>

namespace il2pdb
{
    struct proc
    {
        std::string name;
        uint16_t seg;
        uint32_t off;
        uint32_t size;
        uint32_t type_index;
    };

    struct data_sym
    {
        std::string name;
        uint16_t seg;
        uint32_t off;
        uint32_t type_index;
    };
}
