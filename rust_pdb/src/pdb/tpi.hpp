#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace il2pdb
{
    constexpr uint32_t t_void = 0x0003;
    constexpr uint32_t t_bool08 = 0x0030;
    constexpr uint32_t t_int4 = 0x0074;
    constexpr uint32_t t_uquad_idx = 0x0023;

    struct type_rec
    {
        std::vector<uint8_t> bytes{};
        uint16_t kind = 0;
        std::optional<std::string> name{};
        bool fwdref = false;
    };

    struct member
    {
        std::string name;
        uint32_t ty;
        uint64_t offset;
    };

    [[nodiscard]] type_rec ptr64(uint32_t referent);
    [[nodiscard]] type_rec arglist(std::span<const uint32_t> args);
    [[nodiscard]] type_rec procedure(uint32_t ret, uint32_t arglist_ti, uint16_t nparams);
    [[nodiscard]] type_rec fieldlist(std::span<const member> members);
    [[nodiscard]] type_rec fieldlist_cont(std::span<const member> members,
        std::optional<uint32_t> cont);
    [[nodiscard]] type_rec struct_fwdref(std::string_view name, std::string_view unique);
    [[nodiscard]] type_rec struct_def(std::string_view name, std::string_view unique,
        uint16_t count, uint32_t fieldlist_ti, uint64_t size);
    [[nodiscard]] type_rec union_fwdref(std::string_view name, std::string_view unique);
    [[nodiscard]] type_rec union_def(std::string_view name, std::string_view unique,
        uint16_t count, uint32_t fieldlist_ti, uint64_t size);
    [[nodiscard]] type_rec array_type(uint32_t elem, uint64_t size);

    struct enum_member
    {
        std::string name;
        int64_t value;
    };

    [[nodiscard]] type_rec enum_fieldlist(std::span<const enum_member> members);
    [[nodiscard]] type_rec enum_def(std::string_view name, std::string_view unique,
        uint32_t underlying, uint16_t count, uint32_t fieldlist_ti);

    struct tpi_streams
    {
        std::vector<uint8_t> tpi;
        std::vector<uint8_t> hash;
        uint32_t type_index_end;
    };

    [[nodiscard]] tpi_streams build_tpi(const std::vector<type_rec> & records,
        uint16_t hash_stream_index);
}
