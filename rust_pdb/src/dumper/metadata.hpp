#pragma once

#include "reader.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace il2pdb::dump
{
    struct section_meta
    {
        uint32_t offset;
        uint32_t size;
        uint32_t count;
    };

    struct image_def
    {
        uint32_t name_index;
        int32_t assembly_index;
        int32_t type_start;
        uint32_t type_count;
        int32_t exported_type_start;
        uint32_t exported_type_count;
        int32_t entry_point_index;
        uint32_t token;
        int32_t custom_attribute_start;
        uint32_t custom_attribute_count;
    };

    struct type_def
    {
        uint32_t name_index;
        uint32_t namespace_index;
        int32_t byval_type_index;
        int32_t declaring_type_index;
        int32_t parent_index;
        int32_t generic_container_index;
        uint32_t flags;
        int32_t field_start;
        int32_t method_start;
        int32_t event_start;
        int32_t property_start;
        int32_t nested_types_start;
        int32_t interfaces_start;
        int32_t vtable_start;
        int32_t interface_offsets_start;
        uint16_t method_count;
        uint16_t property_count;
        uint16_t field_count;
        uint16_t event_count;
        uint16_t nested_type_count;
        uint16_t vtable_count;
        uint16_t interfaces_count;
        uint16_t interface_offsets_count;
        uint32_t bitfield;
        uint32_t token;

        [[nodiscard]] bool is_value_type() const noexcept
        {
            return (bitfield & 0x1) == 1;
        }

        [[nodiscard]] bool is_enum() const noexcept
        {
            return ((bitfield >> 1) & 0x1) == 1;
        }
    };

    struct method_def
    {
        uint32_t name_index;
        int32_t declaring_type;
        int32_t return_type;
        int32_t return_parameter_token;
        int32_t parameter_start;
        int32_t generic_container_index;
        uint32_t token;
        uint16_t flags;
        uint16_t iflags;
        uint16_t slot;
        uint16_t parameter_count;
    };

    struct parameter_def
    {
        uint32_t name_index;
        uint32_t token;
        int32_t type_index;
    };

    struct field_def
    {
        uint32_t name_index;
        int32_t type_index;
        uint32_t token;
    };

    struct field_default_value
    {
        int32_t field_index;
        int32_t type_index;
        int32_t data_index;
    };

    struct parameter_default_value
    {
        int32_t parameter_index;
        int32_t type_index;
        int32_t data_index;
    };

    struct property_def
    {
        uint32_t name_index;
        int32_t get;
        int32_t set;
        uint32_t attrs;
        uint32_t token;
    };

    struct event_def
    {
        uint32_t name_index;
        int32_t type_index;
        int32_t add;
        int32_t remove;
        int32_t raise;
        uint32_t token;
    };

    struct generic_container
    {
        int32_t owner_index;
        int32_t type_argc;
        int32_t is_method;
        int32_t generic_parameter_start;
    };

    struct generic_parameter
    {
        int32_t owner_index;
        uint32_t name_index;
        int16_t constraints_start;
        int16_t constraints_count;
        uint16_t num;
        uint16_t flags;
    };

    struct interface_offset_pair
    {
        int32_t interface_type_index;
        int32_t offset;
    };

    struct field_ref
    {
        int32_t type_index;
        int32_t field_index;
    };

    struct string_literal
    {
        int32_t data_index;
    };

    struct assembly_name_def
    {
        uint32_t name_index;
        uint32_t culture_index;
        uint32_t public_key_index;
        uint32_t hash_alg;
        int32_t hash_len;
        uint32_t flags;
        int32_t major;
        int32_t minor;
        int32_t build;
        int32_t revision;
        std::array<uint8_t, 8> public_key_token;
    };

    struct assembly_def
    {
        int32_t image_index;
        uint32_t token;
        uint32_t module_token;
        int32_t referenced_assembly_start;
        int32_t referenced_assembly_count;
        assembly_name_def aname;
    };

    class metadata
    {
    public:
        explicit metadata(std::vector<uint8_t> bytes);

        int version = 0;
        int type_index_size = 4;
        int type_definition_index_size = 4;
        int generic_container_index_size = 4;
        int parameter_index_size = 4;

        std::vector<image_def> image_defs;
        std::vector<type_def> type_defs;
        std::vector<method_def> method_defs;
        std::vector<parameter_def> parameter_defs;
        std::vector<field_def> field_defs;
        std::vector<field_default_value> field_default_values;
        std::vector<parameter_default_value> parameter_default_values;
        std::vector<property_def> property_defs;
        std::vector<event_def> event_defs;
        std::vector<generic_container> generic_containers;
        std::vector<generic_parameter> generic_parameters;
        std::vector<int32_t> constraint_indices;
        std::vector<int32_t> nested_type_indices;
        std::vector<interface_offset_pair> interface_offset_pairs;
        std::vector<uint32_t> vtable_methods;
        std::vector<field_ref> field_refs;
        std::vector<string_literal> string_literals;
        std::vector<assembly_def> assembly_defs;

        [[nodiscard]] std::string get_string(uint32_t index) const;
        [[nodiscard]] std::string get_string_literal(uint32_t index) const;
        [[nodiscard]] bool get_field_default(int32_t field_index, field_default_value & out) const;
        [[nodiscard]] bool get_parameter_default(int32_t parameter_index,
            parameter_default_value & out) const;
        [[nodiscard]] uint32_t default_value_data_offset(int32_t index) const;
        [[nodiscard]] int64_t read_const_int(int32_t data_index, uint8_t type_enum) const;
        [[nodiscard]] const byte_reader & reader() const noexcept
        {
            return r_;
        }

    private:
        byte_reader r_;
        std::array<section_meta, 31> sec_{};
        mutable std::unordered_map<uint32_t, std::string> string_cache_;

        [[nodiscard]] static int get_index_size(uint32_t count);
        [[nodiscard]] image_def read_image_def();
        [[nodiscard]] type_def read_type_def();
        [[nodiscard]] method_def read_method_def();
    };
}
