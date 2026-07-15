#pragma once

#include "executor.hpp"
#include "il2cpp_binary.hpp"
#include "metadata.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace il2pdb::dump
{
    struct script_method_entry
    {
        uint64_t address;
        std::string name;
        std::string signature;
    };

    struct data_symbol
    {
        uint64_t rva;
        std::string name;
        std::string type_base;
        uint32_t pointer_depth = 1;
        uint64_t array_count = 0;
    };

    struct dump_result
    {
        std::vector<script_method_entry> methods;
        std::vector<uint64_t> addresses;
        std::string il2cpp_h;
        std::vector<data_symbol> data_symbols;
    };

    [[nodiscard]] dump_result run_dump(const metadata & md, const il2cpp_binary & bin,
        executor & ex);
}
