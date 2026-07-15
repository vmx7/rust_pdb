#include "il2cpp_binary.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace il2pdb::dump
{
    namespace
    {
        const std::vector<uint8_t> feature_bytes = {
            'm', 's', 'c', 'o', 'r', 'l', 'i', 'b', '.', 'd', 'l', 'l', 0};
        const std::vector<uint64_t> empty_refs{};
    }

    il2cpp_binary::il2cpp_binary(std::vector<uint8_t> bytes, int metadata_type_def_count,
        int image_count)
        : bytes_(std::move(bytes)), type_def_count_(metadata_type_def_count),
          image_count_(image_count)
    {
    }

    uint64_t il2cpp_binary::u64_at(uint64_t file_off) const
    {
        if (file_off + 8 > bytes_.size())
        {
            return 0;
        }
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
        {
            v |= static_cast<uint64_t>(bytes_[file_off + static_cast<std::size_t>(i)]) << (8 * i);
        }
        return v;
    }

    uint32_t il2cpp_binary::u32_at(uint64_t file_off) const
    {
        if (file_off + 4 > bytes_.size())
        {
            return 0;
        }
        return static_cast<uint32_t>(bytes_[file_off])
            | (static_cast<uint32_t>(bytes_[file_off + 1]) << 8)
            | (static_cast<uint32_t>(bytes_[file_off + 2]) << 16)
            | (static_cast<uint32_t>(bytes_[file_off + 3]) << 24);
    }

    int32_t il2cpp_binary::i32_at(uint64_t file_off) const
    {
        return static_cast<int32_t>(u32_at(file_off));
    }

    il2cpp_type il2cpp_binary::read_type(uint64_t type_va) const
    {
        const uint64_t off = map_vatr(type_va);
        il2cpp_type t{};
        t.datapoint = u64_at(off);
        t.bits = u32_at(off + 8);
        t.attrs = t.bits & 0xFFFF;
        t.type = static_cast<uint8_t>((t.bits >> 16) & 0xFF);
        t.num_mods = (t.bits >> 24) & 0x1F;
        t.byref = (t.bits >> 29) & 1;
        t.pinned = (t.bits >> 30) & 1;
        t.valuetype = t.bits >> 31;
        return t;
    }

    int il2cpp_binary::il2cpp_type_index(uint64_t pointer) const
    {
        const auto it = type_dic_.find(pointer);
        return it == type_dic_.end() ? -1 : it->second;
    }

    const std::vector<rgctx_def> * il2cpp_binary::get_rgctx(const std::string & image_name,
        uint32_t token) const
    {
        const auto mit = rgctx_dictionary.find(image_name);
        if (mit == rgctx_dictionary.end())
        {
            return nullptr;
        }
        const auto tit = mit->second.find(token);
        return tit == mit->second.end() ? nullptr : &tit->second;
    }

    uint64_t il2cpp_binary::u64_va(uint64_t va) const
    {
        return u64_at(map_vatr(va));
    }

    uint8_t il2cpp_binary::u8_va(uint64_t va) const
    {
        const uint64_t off = map_vatr(va);
        return off < bytes_.size() ? bytes_[off] : 0;
    }

    uint64_t il2cpp_binary::map_vatr(uint64_t va) const
    {
        if (va < image_base)
        {
            return 0;
        }
        const uint64_t rva = va - image_base;
        for (const pe_section & s : sections_)
        {
            if (rva >= s.virtual_address && rva <= s.virtual_address + s.virtual_size)
            {
                return rva - s.virtual_address + s.pointer_to_raw_data;
            }
        }
        return 0;
    }

    uint64_t il2cpp_binary::get_rva(uint64_t pointer) const noexcept
    {
        return pointer - image_base;
    }

    std::string il2cpp_binary::cstr_at_va(uint64_t va) const
    {
        const uint64_t off = map_vatr(va);
        std::string out{};
        std::size_t i = off;
        while (i < bytes_.size() && bytes_[i] != 0)
        {
            out.push_back(static_cast<char>(bytes_[i]));
            ++i;
        }
        return out;
    }

    void il2cpp_binary::parse_pe()
    {
        const uint32_t lfanew = u32_at(0x3C);
        if (u32_at(lfanew) != 0x4550u)
        {
            throw std::runtime_error("not a PE");
        }
        const uint64_t file_header = lfanew + 4;
        const uint16_t num_sections = static_cast<uint16_t>(u32_at(file_header + 2) & 0xFFFF);
        const uint16_t size_opt = static_cast<uint16_t>(u32_at(file_header + 16) & 0xFFFF);
        const uint64_t opt = file_header + 20;
        const uint16_t magic = static_cast<uint16_t>(u32_at(opt) & 0xFFFF);
        if (magic != 0x20b)
        {
            throw std::runtime_error("only x64 PE supported");
        }
        image_base = u64_at(opt + 24);

        const uint64_t sec_off = opt + size_opt;
        for (uint16_t i = 0; i < num_sections; ++i)
        {
            const uint64_t s = sec_off + static_cast<uint64_t>(i) * 40;
            pe_section ps{};
            ps.virtual_size = u32_at(s + 8);
            ps.virtual_address = u32_at(s + 12);
            ps.size_of_raw_data = u32_at(s + 16);
            ps.pointer_to_raw_data = u32_at(s + 20);
            ps.characteristics = u32_at(s + 36);
            sections_.push_back(ps);
        }

        for (const pe_section & s : sections_)
        {
            search_section ss{};
            ss.offset = s.pointer_to_raw_data;
            ss.offset_end = static_cast<uint64_t>(s.pointer_to_raw_data) + s.size_of_raw_data;
            ss.address = static_cast<uint64_t>(s.virtual_address) + image_base;
            ss.address_end =
                static_cast<uint64_t>(s.virtual_address) + s.virtual_size + image_base;
            if (s.characteristics == 0x60000020u)
            {
                exec_.push_back(ss);
            }
            else if (s.characteristics == 0x40000040u || s.characteristics == 0xC0000040u)
            {
                data_.push_back(ss);
            }
        }
    }

    void il2cpp_binary::build_ref_map()
    {
        uint64_t image_end = image_base;
        for (const pe_section & s : sections_)
        {
            const uint64_t e = image_base + s.virtual_address + s.virtual_size;
            if (e > image_end)
            {
                image_end = e;
            }
        }
        for (const search_section & sec : data_)
        {
            const uint64_t end = (sec.offset_end < bytes_.size() ? sec.offset_end : bytes_.size());
            for (uint64_t pos = sec.offset; pos + 8 <= end; pos += 8)
            {
                const uint64_t val = u64_at(pos);
                if (val >= image_base && val < image_end)
                {
                    const uint64_t va = pos - sec.offset + sec.address;
                    ref_map_[val].push_back(va);
                }
            }
        }
    }

    const std::vector<uint64_t> & il2cpp_binary::find_reference(uint64_t addr) const
    {
        const auto it = ref_map_.find(addr);
        return it == ref_map_.end() ? empty_refs : it->second;
    }

    uint64_t il2cpp_binary::find_code_registration()
    {
        for (const search_section & sec : data_)
        {
            const uint64_t end = (sec.offset_end < bytes_.size() ? sec.offset_end : bytes_.size());
            for (uint64_t p = sec.offset; p + feature_bytes.size() <= end; ++p)
            {
                bool match = true;
                for (std::size_t k = 0; k < feature_bytes.size(); ++k)
                {
                    if (bytes_[p + k] != feature_bytes[k])
                    {
                        match = false;
                        break;
                    }
                }
                if (!match)
                {
                    continue;
                }
                const uint64_t dllva = p - sec.offset + sec.address;
                for (const uint64_t refva : find_reference(dllva))
                {
                    for (const uint64_t refva2 : find_reference(refva))
                    {
                        for (int i = image_count_ - 1; i >= 0; --i)
                        {
                            const uint64_t target = refva2 - static_cast<uint64_t>(i) * 8;
                            for (const uint64_t refva3 : find_reference(target))
                            {
                                const uint64_t pos = map_vatr(refva3 - 8);
                                if (pos != 0 && u64_at(pos) == static_cast<uint64_t>(image_count_))
                                {
                                    return refva3 - 8 * 16;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

    uint64_t il2cpp_binary::find_metadata_registration() const
    {
        const auto in_data_ra = [this](uint64_t pointer)
        {
            for (const search_section & x : data_)
            {
                if (pointer >= x.offset && pointer <= x.offset_end)
                {
                    return true;
                }
            }
            return false;
        };
        const auto all_in_data_va = [this](uint64_t file_ptr, int count)
        {
            for (int i = 0; i < count; ++i)
            {
                const uint64_t v = u64_at(file_ptr + static_cast<uint64_t>(i) * 8);
                bool ok = false;
                for (const search_section & y : data_)
                {
                    if (v >= y.address && v <= y.address_end)
                    {
                        ok = true;
                        break;
                    }
                }
                if (!ok)
                {
                    return false;
                }
            }
            return true;
        };

        const auto tdc = static_cast<uint64_t>(type_def_count_);
        for (const search_section & sec : data_)
        {
            const uint64_t sec_end = (sec.offset_end < bytes_.size() ? sec.offset_end : bytes_.size());
            const uint64_t end = sec_end - 8;
            for (uint64_t pos = sec.offset; pos < end; pos += 8)
            {
                if (u64_at(pos) != tdc)
                {
                    continue;
                }
                if (u64_at(pos + 16) != tdc)
                {
                    continue;
                }
                const uint64_t pointer = map_vatr(u64_at(pos + 24));
                if (pointer == 0 || !in_data_ra(pointer))
                {
                    continue;
                }
                if (all_in_data_va(pointer, type_def_count_))
                {
                    return pos - 80 - sec.offset + sec.address;
                }
            }
        }
        return 0;
    }

    void il2cpp_binary::init()
    {
        parse_pe();
        build_ref_map();
        code_registration = find_code_registration();
        metadata_registration = find_metadata_registration();
        if (code_registration == 0 || metadata_registration == 0)
        {
            throw std::runtime_error("registration discovery failed");
        }

        const uint64_t cr = map_vatr(code_registration);
        const uint64_t generic_method_pointers_count = u64_at(cr + 2 * 8);
        const uint64_t generic_method_pointers_va = u64_at(cr + 3 * 8);
        const uint64_t code_gen_modules_count = u64_at(cr + 15 * 8);
        const uint64_t code_gen_modules_va = u64_at(cr + 16 * 8);

        const uint64_t mod_arr = map_vatr(code_gen_modules_va);
        for (uint64_t i = 0; i < code_gen_modules_count; ++i)
        {
            const uint64_t mod_ptr = u64_at(mod_arr + i * 8);
            const uint64_t mod_off = map_vatr(mod_ptr);
            const uint64_t module_name_va = u64_at(mod_off);
            const uint64_t method_pointer_count = u64_at(mod_off + 8);
            const uint64_t method_pointers_va = u64_at(mod_off + 16);
            const std::string name = cstr_at_va(module_name_va);
            code_gen_module_vas.emplace_back(name, mod_ptr);
            if (method_pointers_va != 0 && method_pointer_count > 0)
            {
                pointer_tables.push_back(
                    pointer_table{name + "_methodPointers", method_pointers_va, method_pointer_count});
            }

            std::vector<uint64_t> ptrs{};
            ptrs.reserve(method_pointer_count);
            const uint64_t mp_off = map_vatr(method_pointers_va);
            for (uint64_t j = 0; j < method_pointer_count; ++j)
            {
                ptrs.push_back(mp_off == 0 ? 0 : u64_at(mp_off + j * 8));
            }
            code_gen_module_method_pointers.emplace(name, std::move(ptrs));

            const uint64_t rgctx_ranges_count = u64_at(mod_off + 64);
            const uint64_t rgctx_ranges_va = u64_at(mod_off + 72);
            const uint64_t rgctxs_count = u64_at(mod_off + 80);
            const uint64_t rgctxs_va = u64_at(mod_off + 88);
            auto & mod_rgctx = rgctx_dictionary[name];
            if (rgctxs_count > 0)
            {
                const uint64_t rgctxs_off = map_vatr(rgctxs_va);
                const uint64_t ranges_off = map_vatr(rgctx_ranges_va);
                for (uint64_t r = 0; r < rgctx_ranges_count; ++r)
                {
                    const uint64_t roff = ranges_off + r * 12;
                    const uint32_t token = u32_at(roff);
                    const int32_t start = i32_at(roff + 4);
                    const int32_t length = i32_at(roff + 8);
                    std::vector<rgctx_def> defs{};
                    defs.reserve(static_cast<std::size_t>(length < 0 ? 0 : length));
                    for (int k = 0; k < length; ++k)
                    {
                        const uint64_t doff = rgctxs_off + static_cast<uint64_t>(start + k) * 16;
                        const uint64_t type_post29 = u64_at(doff);
                        const uint64_t data_va = u64_at(doff + 8);
                        const int32_t data_dummy = i32_at(map_vatr(data_va));
                        defs.push_back(rgctx_def{type_post29, data_dummy});
                    }
                    mod_rgctx[token] = std::move(defs);
                }
            }
        }

        const uint64_t gmp_off = map_vatr(generic_method_pointers_va);
        generic_method_pointers.reserve(generic_method_pointers_count);
        for (uint64_t i = 0; i < generic_method_pointers_count; ++i)
        {
            generic_method_pointers.push_back(gmp_off == 0 ? 0 : u64_at(gmp_off + i * 8));
        }

        const auto read_ptr_array =
            [this](uint64_t count, uint64_t va, std::vector<uint64_t> & dst)
        {
            if (count == 0 || va == 0)
            {
                return;
            }
            const uint64_t off = map_vatr(va);
            dst.reserve(count);
            for (uint64_t i = 0; i < count; ++i)
            {
                dst.push_back(off == 0 ? 0 : u64_at(off + i * 8));
            }
        };
        read_ptr_array(u64_at(cr + 5 * 8), u64_at(cr + 6 * 8), invoker_pointers);
        read_ptr_array(u64_at(cr + 0 * 8), u64_at(cr + 1 * 8), reverse_pinvoke_wrappers);
        read_ptr_array(u64_at(cr + 7 * 8), u64_at(cr + 8 * 8), unresolved_virtual_call_pointers);

        const auto add_table = [this](const char* nm, uint64_t count, uint64_t va)
        {
            if (count > 0 && va != 0)
            {
                pointer_tables.push_back(pointer_table{nm, va, count});
            }
        };
        add_table("il2cpp_genericMethodPointers", generic_method_pointers_count,
            generic_method_pointers_va);
        add_table("il2cpp_invokerPointers", u64_at(cr + 5 * 8), u64_at(cr + 6 * 8));
        add_table("il2cpp_reversePInvokeWrappers", u64_at(cr + 0 * 8), u64_at(cr + 1 * 8));
        add_table("il2cpp_unresolvedVirtualCallPointers", u64_at(cr + 7 * 8), u64_at(cr + 8 * 8));

        const uint64_t mr = map_vatr(metadata_registration);
        const auto add_meta_table = [this](const char* nm, uint64_t count, uint64_t va,
            const char* elem, uint32_t elem_ptrs)
        {
            if (count > 0 && va != 0)
            {
                pointer_tables.push_back(pointer_table{nm, va, count, elem, elem_ptrs});
            }
        };
        add_meta_table("il2cpp_MetadataRegistration_genericClasses", u64_at(mr + 0 * 8),
            u64_at(mr + 1 * 8), "void", 1);
        add_meta_table("il2cpp_MetadataRegistration_genericInsts", u64_at(mr + 2 * 8),
            u64_at(mr + 3 * 8), "void", 1);
        add_meta_table("il2cpp_MetadataRegistration_types", u64_at(mr + 6 * 8),
            u64_at(mr + 7 * 8), "Il2CppType", 1);

        read_types_and_generics();
    }

    uint64_t il2cpp_binary::map_rtva(uint64_t file_off) const
    {
        for (const pe_section & s : sections_)
        {
            if (file_off >= s.pointer_to_raw_data
                && file_off <= s.pointer_to_raw_data + s.size_of_raw_data)
            {
                return file_off - s.pointer_to_raw_data + s.virtual_address + image_base;
            }
        }
        return 0;
    }

    std::vector<metadata_usage_entry> il2cpp_binary::metadata_usages() const
    {
        std::vector<metadata_usage_entry> out{};
        for (const search_section & sec : data_)
        {
            const uint64_t sec_end = (sec.offset_end < bytes_.size() ? sec.offset_end : bytes_.size());
            if (sec_end < 8)
            {
                continue;
            }
            const uint64_t end = sec_end - 8;
            for (uint64_t pos = sec.offset; pos < end; pos += 8)
            {
                const uint64_t mv = u64_at(pos);
                if (mv >= 0xFFFFFFFFull)
                {
                    continue;
                }
                const uint32_t encoded = static_cast<uint32_t>(mv);
                const uint32_t usage = (encoded & 0xE0000000u) >> 29;
                if (usage == 0 || usage > 6)
                {
                    continue;
                }
                const uint32_t decoded = (encoded & 0x1FFFFFFEu) >> 1;
                if (mv != static_cast<uint64_t>((usage << 29) | (decoded << 1)) + 1)
                {
                    continue;
                }
                const uint64_t va = map_rtva(pos);
                if (va == 0)
                {
                    continue;
                }
                out.push_back(metadata_usage_entry{va - image_base, usage, decoded});
            }
        }
        return out;
    }

    std::vector<uint64_t> il2cpp_binary::ordered_addresses() const
    {
        std::vector<uint64_t> ptrs{};
        for (const auto & kv : code_gen_module_method_pointers)
        {
            ptrs.insert(ptrs.end(), kv.second.begin(), kv.second.end());
        }
        ptrs.insert(ptrs.end(), generic_method_pointers.begin(), generic_method_pointers.end());
        ptrs.insert(ptrs.end(), invoker_pointers.begin(), invoker_pointers.end());
        ptrs.insert(ptrs.end(), reverse_pinvoke_wrappers.begin(), reverse_pinvoke_wrappers.end());
        ptrs.insert(ptrs.end(), unresolved_virtual_call_pointers.begin(),
            unresolved_virtual_call_pointers.end());
        std::sort(ptrs.begin(), ptrs.end());
        ptrs.erase(std::unique(ptrs.begin(), ptrs.end()), ptrs.end());
        ptrs.erase(std::remove(ptrs.begin(), ptrs.end(), 0), ptrs.end());
        std::vector<uint64_t> out{};
        out.reserve(ptrs.size());
        for (const uint64_t p : ptrs)
        {
            out.push_back(get_rva(p));
        }
        return out;
    }

    void il2cpp_binary::read_types_and_generics()
    {
        const uint64_t mr = map_vatr(metadata_registration);
        const uint64_t generic_insts_count = u64_at(mr + 2 * 8);
        const uint64_t generic_insts_va = u64_at(mr + 3 * 8);
        const uint64_t generic_method_table_count = u64_at(mr + 4 * 8);
        const uint64_t generic_method_table_va = u64_at(mr + 5 * 8);
        const uint64_t types_count = u64_at(mr + 6 * 8);
        const uint64_t types_va = u64_at(mr + 7 * 8);
        const uint64_t method_specs_count = u64_at(mr + 8 * 8);
        const uint64_t method_specs_va = u64_at(mr + 9 * 8);

        const uint64_t ptypes = map_vatr(types_va);
        types.reserve(types_count);
        for (uint64_t i = 0; i < types_count; ++i)
        {
            const uint64_t pt = u64_at(ptypes + i * 8);
            types.push_back(read_type(pt));
            type_dic_.emplace(pt, static_cast<int>(i));
        }

        const uint64_t pgi = map_vatr(generic_insts_va);
        generic_inst_pointers.reserve(generic_insts_count);
        generic_insts.reserve(generic_insts_count);
        for (uint64_t i = 0; i < generic_insts_count; ++i)
        {
            const uint64_t gip = u64_at(pgi + i * 8);
            generic_inst_pointers.push_back(gip);
            const uint64_t goff = map_vatr(gip);
            generic_insts.push_back(generic_inst{u64_at(goff), u64_at(goff + 8)});
        }

        const uint64_t pms = map_vatr(method_specs_va);
        method_specs.reserve(method_specs_count);
        for (uint64_t i = 0; i < method_specs_count; ++i)
        {
            const uint64_t off = pms + i * 12;
            method_specs.push_back(method_spec{i32_at(off), i32_at(off + 4), i32_at(off + 8)});
        }

        method_spec_generic_method_pointers.assign(method_specs_count, 0);
        const uint64_t pgmt = map_vatr(generic_method_table_va);
        for (uint64_t i = 0; i < generic_method_table_count; ++i)
        {
            const uint64_t off = pgmt + i * 16;
            const int32_t generic_method_index = i32_at(off);
            const int32_t method_index = i32_at(off + 4);
            if (generic_method_index < 0
                || static_cast<uint64_t>(generic_method_index) >= method_specs_count)
            {
                continue;
            }
            const int md = method_specs[static_cast<std::size_t>(generic_method_index)]
                               .method_definition_index;
            method_definition_method_specs[md].push_back(generic_method_index);
            if (method_index >= 0
                && static_cast<std::size_t>(method_index) < generic_method_pointers.size())
            {
                method_spec_generic_method_pointers[static_cast<std::size_t>(generic_method_index)] =
                    generic_method_pointers[static_cast<std::size_t>(method_index)];
            }
        }
    }

    uint64_t il2cpp_binary::method_pointer(const std::string & image_name, uint32_t token) const
    {
        const auto it = code_gen_module_method_pointers.find(image_name);
        if (it == code_gen_module_method_pointers.end())
        {
            return 0;
        }
        const uint32_t idx = token & 0x00FFFFFFu;
        if (idx == 0 || idx > it->second.size())
        {
            return 0;
        }
        return it->second[idx - 1];
    }
}
