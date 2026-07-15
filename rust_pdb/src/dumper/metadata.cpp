#include "metadata.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace il2pdb::dump
{
    namespace
    {
        constexpr int sec_string_literals = 0;
        constexpr int sec_strings = 2;
        constexpr int sec_events = 3;
        constexpr int sec_properties = 4;
        constexpr int sec_methods = 5;
        constexpr int sec_parameter_default_values = 6;
        constexpr int sec_field_default_values = 7;
        constexpr int sec_field_and_parameter_default_value_data = 8;
        constexpr int sec_parameters = 10;
        constexpr int sec_fields = 11;
        constexpr int sec_generic_parameters = 12;
        constexpr int sec_generic_parameter_constraints = 13;
        constexpr int sec_generic_containers = 14;
        constexpr int sec_nested_types = 15;
        constexpr int sec_interfaces = 16;
        constexpr int sec_vtable_methods = 17;
        constexpr int sec_type_definitions = 19;
        constexpr int sec_images = 20;
        constexpr int sec_assemblies = 21;
        constexpr int sec_field_refs = 22;
    }

    int metadata::get_index_size(uint32_t count)
    {
        if (count <= 0xFF)
        {
            return 1;
        }
        if (count <= 0xFFFF)
        {
            return 2;
        }
        return 4;
    }

    image_def metadata::read_image_def()
    {
        image_def d{};
        d.name_index = r_.u32();
        d.assembly_index = r_.i32();
        d.type_start = r_.index(type_definition_index_size);
        d.type_count = r_.u32();
        d.exported_type_start = r_.index(type_definition_index_size);
        d.exported_type_count = r_.u32();
        d.entry_point_index = r_.i32();
        d.token = r_.u32();
        d.custom_attribute_start = r_.i32();
        d.custom_attribute_count = r_.u32();
        return d;
    }

    type_def metadata::read_type_def()
    {
        type_def d{};
        d.name_index = r_.u32();
        d.namespace_index = r_.u32();
        d.byval_type_index = r_.index(type_index_size);
        d.declaring_type_index = r_.index(type_index_size);
        d.parent_index = r_.index(type_index_size);
        d.generic_container_index = r_.index(generic_container_index_size);
        d.flags = r_.u32();
        d.field_start = r_.i32();
        d.method_start = r_.i32();
        d.event_start = r_.i32();
        d.property_start = r_.i32();
        d.nested_types_start = r_.i32();
        d.interfaces_start = r_.i32();
        d.vtable_start = r_.i32();
        d.interface_offsets_start = r_.i32();
        d.method_count = r_.u16();
        d.property_count = r_.u16();
        d.field_count = r_.u16();
        d.event_count = r_.u16();
        d.nested_type_count = r_.u16();
        d.vtable_count = r_.u16();
        d.interfaces_count = r_.u16();
        d.interface_offsets_count = r_.u16();
        d.bitfield = r_.u32();
        d.token = r_.u32();
        return d;
    }

    method_def metadata::read_method_def()
    {
        method_def d{};
        d.name_index = r_.u32();
        d.declaring_type = r_.index(type_definition_index_size);
        d.return_type = r_.index(type_index_size);
        d.return_parameter_token = r_.i32();
        d.parameter_start = r_.index(parameter_index_size);
        d.generic_container_index = r_.index(generic_container_index_size);
        d.token = r_.u32();
        d.flags = r_.u16();
        d.iflags = r_.u16();
        d.slot = r_.u16();
        d.parameter_count = r_.u16();
        return d;
    }

    metadata::metadata(std::vector<uint8_t> bytes) : r_(std::move(bytes))
    {
        const uint32_t sanity = r_.u32();
        if (sanity != 0xFAB11BAFu)
        {
            throw std::runtime_error("metadata: bad sanity");
        }
        version = r_.i32();
        if (version != 39)
        {
            throw std::runtime_error("metadata: only v39 supported");
        }
        for (int i = 0; i < 31; ++i)
        {
            sec_[i].offset = r_.u32();
            sec_[i].size = r_.u32();
            sec_[i].count = r_.u32();
        }

        const section_meta & parameters = sec_[sec_parameters];
        type_index_size = static_cast<int>(parameters.size / parameters.count) - 8;
        type_definition_index_size = get_index_size(sec_[sec_type_definitions].count);
        generic_container_index_size = get_index_size(sec_[sec_generic_containers].count);
        parameter_index_size = get_index_size(parameters.count);

        const auto tis = static_cast<uint32_t>(type_index_size);
        const auto tdis = static_cast<uint32_t>(type_definition_index_size);
        const auto gcis = static_cast<uint32_t>(generic_container_index_size);
        const auto pis = static_cast<uint32_t>(parameter_index_size);

        const auto read_array = [this](int sec, uint32_t elem_size, auto reader_fn)
        {
            const section_meta & s = sec_[sec];
            const uint32_t count = elem_size == 0 ? 0 : s.size / elem_size;
            r_.seek(s.offset);
            for (uint32_t i = 0; i < count; ++i)
            {
                reader_fn();
            }
        };

        read_array(sec_images, 32 + 2 * tdis, [&] { image_defs.push_back(read_image_def()); });
        read_array(sec_type_definitions, 68 + 3 * tis + gcis,
            [&] { type_defs.push_back(read_type_def()); });
        read_array(sec_methods, 20 + tdis + tis + pis + gcis,
            [&] { method_defs.push_back(read_method_def()); });
        read_array(sec_parameters, 8 + tis, [&]
            {
                parameter_def d{};
                d.name_index = r_.u32();
                d.token = r_.u32();
                d.type_index = r_.index(type_index_size);
                parameter_defs.push_back(d);
            });
        read_array(sec_fields, 8 + tis, [&]
            {
                field_def d{};
                d.name_index = r_.u32();
                d.type_index = r_.index(type_index_size);
                d.token = r_.u32();
                field_defs.push_back(d);
            });
        read_array(sec_field_default_values, 8 + tis, [&]
            {
                field_default_value d{};
                d.field_index = r_.i32();
                d.type_index = r_.index(type_index_size);
                d.data_index = r_.i32();
                field_default_values.push_back(d);
            });
        read_array(sec_parameter_default_values, pis + tis + 4, [&]
            {
                parameter_default_value d{};
                d.parameter_index = r_.index(parameter_index_size);
                d.type_index = r_.index(type_index_size);
                d.data_index = r_.i32();
                parameter_default_values.push_back(d);
            });
        read_array(sec_properties, 20, [&]
            {
                property_def d{};
                d.name_index = r_.u32();
                d.get = r_.i32();
                d.set = r_.i32();
                d.attrs = r_.u32();
                d.token = r_.u32();
                property_defs.push_back(d);
            });
        read_array(sec_events, 20 + tis, [&]
            {
                event_def d{};
                d.name_index = r_.u32();
                d.type_index = r_.index(type_index_size);
                d.add = r_.i32();
                d.remove = r_.i32();
                d.raise = r_.i32();
                d.token = r_.u32();
                event_defs.push_back(d);
            });
        read_array(sec_generic_containers, 16, [&]
            {
                generic_container d{};
                d.owner_index = r_.i32();
                d.type_argc = r_.i32();
                d.is_method = r_.i32();
                d.generic_parameter_start = r_.i32();
                generic_containers.push_back(d);
            });
        read_array(sec_generic_parameters, gcis + 12, [&]
            {
                generic_parameter d{};
                d.owner_index = r_.index(generic_container_index_size);
                d.name_index = r_.u32();
                d.constraints_start = r_.i16();
                d.constraints_count = r_.i16();
                d.num = r_.u16();
                d.flags = r_.u16();
                generic_parameters.push_back(d);
            });
        read_array(sec_generic_parameter_constraints, tis,
            [&] { constraint_indices.push_back(r_.index(type_index_size)); });
        read_array(sec_nested_types, 4, [&] { nested_type_indices.push_back(r_.i32()); });
        read_array(sec_interfaces, tis + 4, [&]
            {
                interface_offset_pair d{};
                d.interface_type_index = r_.index(type_index_size);
                d.offset = r_.i32();
                interface_offset_pairs.push_back(d);
            });
        read_array(sec_vtable_methods, 4, [&] { vtable_methods.push_back(r_.u32()); });
        read_array(sec_field_refs, tis + 4, [&]
            {
                field_ref d{};
                d.type_index = r_.index(type_index_size);
                d.field_index = r_.i32();
                field_refs.push_back(d);
            });
        read_array(sec_string_literals, 4, [&]
            {
                string_literal d{};
                d.data_index = r_.i32();
                string_literals.push_back(d);
            });
        read_array(sec_assemblies, 68, [&]
            {
                assembly_def d{};
                d.image_index = r_.i32();
                d.token = r_.u32();
                d.module_token = r_.u32();
                d.referenced_assembly_start = r_.i32();
                d.referenced_assembly_count = r_.i32();
                d.aname.name_index = r_.u32();
                d.aname.culture_index = r_.u32();
                d.aname.public_key_index = r_.u32();
                d.aname.hash_alg = r_.u32();
                d.aname.hash_len = r_.i32();
                d.aname.flags = r_.u32();
                d.aname.major = r_.i32();
                d.aname.minor = r_.i32();
                d.aname.build = r_.i32();
                d.aname.revision = r_.i32();
                for (int k = 0; k < 8; ++k)
                {
                    d.aname.public_key_token[static_cast<std::size_t>(k)] = r_.u8();
                }
                assembly_defs.push_back(d);
            });
    }

    std::string metadata::get_string(uint32_t index) const
    {
        if (const auto it = string_cache_.find(index); it != string_cache_.end())
        {
            return it->second;
        }
        std::string s = r_.cstr_at(static_cast<std::size_t>(sec_[sec_strings].offset) + index);
        string_cache_.emplace(index, s);
        return s;
    }

    std::string metadata::get_string_literal(uint32_t index) const
    {
        if (index >= string_literals.size())
        {
            return {};
        }
        constexpr int sec_string_literal_data = 1;
        const int32_t data_index = string_literals[index].data_index;
        const section_meta & data_sec = sec_[sec_string_literal_data];
        const int32_t length = (static_cast<std::size_t>(index) + 1 < string_literals.size())
            ? string_literals[index + 1].data_index - data_index
            : static_cast<int32_t>(data_sec.size) - data_index;
        if (data_index < 0 || length <= 0)
        {
            return {};
        }
        std::string s{};
        s.reserve(static_cast<std::size_t>(length));
        const std::size_t base = static_cast<std::size_t>(data_sec.offset)
            + static_cast<std::size_t>(data_index);
        for (int32_t i = 0; i < length; ++i)
        {
            s.push_back(static_cast<char>(r_.u8_at(base + static_cast<std::size_t>(i))));
        }
        return s;
    }

    bool metadata::get_field_default(int32_t field_index, field_default_value & out) const
    {
        for (const field_default_value & v : field_default_values)
        {
            if (v.field_index == field_index)
            {
                out = v;
                return true;
            }
        }
        return false;
    }

    bool metadata::get_parameter_default(int32_t parameter_index,
        parameter_default_value & out) const
    {
        for (const parameter_default_value & v : parameter_default_values)
        {
            if (v.parameter_index == parameter_index)
            {
                out = v;
                return true;
            }
        }
        return false;
    }

    uint32_t metadata::default_value_data_offset(int32_t index) const
    {
        return sec_[sec_field_and_parameter_default_value_data].offset
            + static_cast<uint32_t>(index);
    }

    int64_t metadata::read_const_int(int32_t data_index, uint8_t type_enum) const
    {
        std::size_t off = default_value_data_offset(data_index);
        switch (type_enum)
        {
        case 0x02:
        case 0x05:
            return r_.u8_at(off);
        case 0x04:
            return static_cast<int8_t>(r_.u8_at(off));
        case 0x03:
        case 0x07:
            return r_.u16_at(off);
        case 0x06:
            return static_cast<int16_t>(r_.u16_at(off));
        case 0x09:
            return r_.compressed_u32_at(off);
        case 0x08:
        {
            const uint32_t enc = r_.compressed_u32_at(off);
            if (enc == 0xFFFFFFFFu)
            {
                return static_cast<int64_t>(std::numeric_limits<int32_t>::min());
            }
            const bool neg = (enc & 1) != 0;
            const uint32_t v = enc >> 1;
            return neg ? -static_cast<int64_t>(v) - 1 : static_cast<int64_t>(v);
        }
        case 0x0B:
            return static_cast<int64_t>(r_.u64_at(off));
        case 0x0A:
            return static_cast<int64_t>(r_.u64_at(off));
        default:
            return 0;
        }
    }
}
