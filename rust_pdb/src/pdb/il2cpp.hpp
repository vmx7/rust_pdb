#pragma once

#include "tpi.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace il2pdb
{
    struct tdef
    {
        bool is_void_ptr;
        uint32_t i;
        uint64_t s;
        uint32_t a;
    };

    class il2cpp_types
    {
    public:
        std::vector<type_rec> records{};
        std::unordered_map<std::string, uint32_t> name_to_complete{};
        std::unordered_map<std::string, uint32_t> name_to_fwd{};
        std::unordered_map<std::string, std::pair<uint32_t, uint64_t>> name_to_enum{};
        std::unordered_map<std::string, tdef> typedefs{};
        std::unordered_map<uint32_t, uint32_t> ptr_cache{};
        std::map<std::pair<uint32_t, std::vector<uint32_t>>, uint32_t> proc_cache{};
        std::map<std::vector<uint32_t>, uint32_t> arglist_cache{};

        uint32_t intern_ptr(uint32_t referent);
        uint32_t make_array(uint32_t elem, uint64_t byte_size);
        uint32_t resolve_typeref(std::string_view base, uint32_t ptrs);
        uint32_t proc_type(uint32_t ret, const std::vector<uint32_t> & params);
        uint32_t sig_to_proc(std::string_view sig);
    };

    [[nodiscard]] il2cpp_types parse_and_build(const std::string & header);
}
