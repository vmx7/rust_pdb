#include "struct_generator.hpp"

#include "header_constants.hpp"

#include <algorithm>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace il2pdb::dump
{
    namespace
    {
        constexpr uint8_t type_object = 0x1C;
        constexpr uint8_t type_ptr = 0x0F;
        constexpr uint8_t type_string = 0x0E;
        constexpr uint8_t type_valuetype = 0x11;
        constexpr uint8_t type_class = 0x12;
        constexpr uint8_t type_var = 0x13;
        constexpr uint8_t type_array = 0x14;
        constexpr uint8_t type_genericinst = 0x15;
        constexpr uint8_t type_szarray = 0x1D;
        constexpr uint8_t type_mvar = 0x1E;

        constexpr uint32_t field_attribute_static = 0x0010;
        constexpr uint32_t field_attribute_literal = 0x0040;
        constexpr uint16_t method_attribute_static = 0x0010;

        std::string replace_all(const std::string & s, const std::string & from,
            const std::string & to)
        {
            if (from.empty())
            {
                return s;
            }
            std::string r{};
            std::size_t pos = 0;
            for (std::size_t f = s.find(from); f != std::string::npos; f = s.find(from, pos))
            {
                r.append(s, pos, f - pos);
                r.append(to);
                pos = f + from.size();
            }
            r.append(s, pos, std::string::npos);
            return r;
        }

        struct field_info
        {
            std::string field_type_name;
            std::string field_name;
            bool is_value_type;
            bool is_custom_type;
        };

        struct rgctx_info
        {
            uint64_t type;
            std::string type_name;
            std::string class_name;
            std::string method_name;
        };

        struct struct_info
        {
            std::string type_name;
            bool is_value_type;
            std::optional<std::string> parent;
            std::vector<field_info> fields;
            std::vector<field_info> static_fields;
            std::vector<std::optional<std::string>> vtable_method;
            std::vector<rgctx_info> rgctxs;
        };

        class generator
        {
        public:
            generator(const metadata & md, const il2cpp_binary & bin, executor & ex)
                : md_(md), bin_(bin), ex_(ex)
            {
            }

            dump_result run();

        private:
            const metadata & md_;
            const il2cpp_binary & bin_;
            executor & ex_;

            std::vector<struct_info> list_;
            std::unordered_map<std::string, std::size_t> by_name_;
            std::unordered_set<std::size_t> cache_;
            std::string method_info_header_;
            std::unordered_set<uint64_t> method_info_cache_;
            std::vector<std::string> image_of_type_;

            [[nodiscard]] int gc_type_def(uint64_t pointer) const;
            [[nodiscard]] int get_type_definition(const il2cpp_type & t) const;
            [[nodiscard]] int resolve_var(const il2cpp_type & t, uint64_t inst_va) const;
            [[nodiscard]] bool is_value_type(const il2cpp_type & t, const generic_context * ctx) const;
            [[nodiscard]] bool is_custom_type(const il2cpp_type & t, const generic_context * ctx) const;

            void add_struct(int td_idx);
            void add_generic_class_struct(uint64_t pointer);
            void add_parents(const type_def & td, struct_info & info);
            void add_fields(const type_def & td, struct_info & info, const generic_context * ctx);
            void add_vtable_method(struct_info & info, const type_def & td);
            void add_rgctx(struct_info & info, const type_def & td, const std::string & image);
            [[nodiscard]] std::vector<rgctx_info> generate_rgctx(const std::string & image,
                const method_def & mdef);
            void fill_rgctx(rgctx_info & r, const rgctx_def & def) const;
            void generate_method_info(const std::string & name, const std::string & struct_type,
                const std::vector<rgctx_info> & rgctxs);
            [[nodiscard]] std::string recursion(std::size_t idx);
            [[nodiscard]] std::string build_enums();
        };

        int generator::gc_type_def(uint64_t pointer) const
        {
            const uint64_t type_va = bin_.u64_va(pointer);
            const int ti = bin_.il2cpp_type_index(type_va);
            if (ti < 0)
            {
                return -1;
            }
            return static_cast<int>(bin_.types[static_cast<std::size_t>(ti)].datapoint);
        }

        int generator::get_type_definition(const il2cpp_type & t) const
        {
            if (t.type == 0x15)
            {
                return gc_type_def(t.datapoint);
            }
            return static_cast<int>(t.datapoint);
        }

        int generator::resolve_var(const il2cpp_type & t, uint64_t inst_va) const
        {
            const int gp = static_cast<int>(t.datapoint);
            const uint16_t num = md_.generic_parameters[static_cast<std::size_t>(gp)].num;
            const uint64_t type_argv = bin_.u64_va(inst_va + 8);
            const uint64_t ptr = bin_.u64_va(type_argv + static_cast<uint64_t>(num) * 8);
            return bin_.il2cpp_type_index(ptr);
        }

        bool generator::is_value_type(const il2cpp_type & t, const generic_context * ctx) const
        {
            switch (t.type)
            {
            case type_valuetype:
            {
                const type_def & d = md_.type_defs[t.datapoint];
                return !d.is_enum();
            }
            case type_genericinst:
            {
                const int td = gc_type_def(t.datapoint);
                if (td < 0)
                {
                    return false;
                }
                const type_def & d = md_.type_defs[static_cast<std::size_t>(td)];
                return d.is_value_type() && !d.is_enum();
            }
            case type_var:
            {
                if (ctx != nullptr)
                {
                    const int ti = resolve_var(t, ctx->class_inst);
                    return ti >= 0 && is_value_type(bin_.types[static_cast<std::size_t>(ti)], nullptr);
                }
                return false;
            }
            case type_mvar:
            {
                if (ctx != nullptr)
                {
                    const int ti = resolve_var(t, ctx->method_inst);
                    return ti >= 0 && is_value_type(bin_.types[static_cast<std::size_t>(ti)], nullptr);
                }
                return false;
            }
            default:
                return false;
            }
        }

        bool generator::is_custom_type(const il2cpp_type & t, const generic_context * ctx) const
        {
            switch (t.type)
            {
            case type_ptr:
            {
                const int ei = bin_.il2cpp_type_index(t.datapoint);
                return ei >= 0 && is_custom_type(bin_.types[static_cast<std::size_t>(ei)], ctx);
            }
            case type_string:
            case type_class:
            case type_array:
            case type_szarray:
                return true;
            case type_valuetype:
            {
                const type_def & d = md_.type_defs[t.datapoint];
                if (d.is_enum())
                {
                    return is_custom_type(bin_.types[static_cast<std::size_t>(d.parent_index)], ctx);
                }
                return true;
            }
            case type_genericinst:
            {
                const int td = gc_type_def(t.datapoint);
                if (td < 0)
                {
                    return true;
                }
                const type_def & d = md_.type_defs[static_cast<std::size_t>(td)];
                if (d.is_enum())
                {
                    return is_custom_type(bin_.types[static_cast<std::size_t>(d.parent_index)], ctx);
                }
                return true;
            }
            case type_var:
            case type_mvar:
            {
                if (ctx != nullptr)
                {
                    if (ctx->method_inst != 0)
                    {
                        const int ti = resolve_var(t, ctx->method_inst);
                        return ti >= 0
                            && is_custom_type(bin_.types[static_cast<std::size_t>(ti)], nullptr);
                    }
                    if (ctx->class_inst != 0)
                    {
                        const int ti = resolve_var(t, ctx->class_inst);
                        return ti >= 0
                            && is_custom_type(bin_.types[static_cast<std::size_t>(ti)], nullptr);
                    }
                }
                return false;
            }
            default:
                return false;
            }
        }

        void generator::add_parents(const type_def & td, struct_info & info)
        {
            if (!td.is_value_type() && !td.is_enum() && td.parent_index >= 0)
            {
                const il2cpp_type & parent = bin_.types[static_cast<std::size_t>(td.parent_index)];
                if (parent.type != type_object)
                {
                    info.parent = ex_.get_il2cpp_struct_name(parent);
                }
            }
        }

        void generator::add_fields(const type_def & td, struct_info & info,
            const generic_context * ctx)
        {
            if (td.field_count == 0)
            {
                return;
            }
            const int field_end = td.field_start + static_cast<int>(td.field_count);
            std::unordered_set<std::string> cache{};
            ex_.set_emit_enum_fields(true);
            for (int i = td.field_start; i < field_end; ++i)
            {
                const field_def & fd = md_.field_defs[static_cast<std::size_t>(i)];
                const il2cpp_type & ft = bin_.types[static_cast<std::size_t>(fd.type_index)];
                if ((ft.attrs & field_attribute_literal) != 0)
                {
                    continue;
                }
                field_info fi{};
                fi.field_type_name = ex_.parse_type(ft, ctx);
                std::string field_name = executor::fix_name(md_.get_string(fd.name_index));
                if (!cache.insert(field_name).second)
                {
                    field_name = "_" + std::to_string(i - td.field_start) + "_" + field_name;
                }
                fi.field_name = field_name;
                fi.is_value_type = is_value_type(ft, ctx);
                fi.is_custom_type = is_custom_type(ft, ctx);
                if ((ft.attrs & field_attribute_static) != 0)
                {
                    info.static_fields.push_back(std::move(fi));
                }
                else
                {
                    info.fields.push_back(std::move(fi));
                }
            }
            ex_.set_emit_enum_fields(false);
        }

        void generator::add_vtable_method(struct_info & info, const type_def & td)
        {
            std::map<int, method_def> dic{};
            for (int i = 0; i < td.vtable_count; ++i)
            {
                const uint32_t encoded =
                    md_.vtable_methods[static_cast<std::size_t>(td.vtable_start + i)];
                const uint32_t usage = (encoded & 0xE0000000u) >> 29;
                const uint32_t index = (encoded & 0x1FFFFFFEu) >> 1;
                method_def mdef{};
                if (usage == 6)
                {
                    const method_spec & ms = bin_.method_specs[static_cast<std::size_t>(index)];
                    mdef = md_.method_defs[static_cast<std::size_t>(ms.method_definition_index)];
                }
                else
                {
                    mdef = md_.method_defs[static_cast<std::size_t>(index)];
                }
                if (mdef.slot != 0xFFFF)
                {
                    dic[mdef.slot] = mdef;
                }
            }
            if (!dic.empty())
            {
                const int max_slot = dic.rbegin()->first;
                info.vtable_method.assign(static_cast<std::size_t>(max_slot + 1), std::nullopt);
                for (const auto & kv : dic)
                {
                    info.vtable_method[static_cast<std::size_t>(kv.first)] =
                        executor::fix_name(md_.get_string(kv.second.name_index));
                }
            }
        }

        void generator::fill_rgctx(rgctx_info & r, const rgctx_def & def) const
        {
            r.type = def.type;
            const int data = def.data_dummy;
            if (def.type == 1)
            {
                r.type_name = executor::fix_name(
                    ex_.get_type_name(bin_.types[static_cast<std::size_t>(data)], true, false));
            }
            else if (def.type == 2)
            {
                r.class_name = executor::fix_name(
                    ex_.get_type_name(bin_.types[static_cast<std::size_t>(data)], true, false));
            }
            else if (def.type == 3)
            {
                const method_spec & ms = bin_.method_specs[static_cast<std::size_t>(data)];
                const auto n = ex_.get_method_spec_name(ms, true);
                r.method_name = executor::fix_name(n.first + "." + n.second);
            }
        }

        void generator::add_rgctx(struct_info & info, const type_def & td, const std::string & image)
        {
            const std::vector<rgctx_def> * defs = bin_.get_rgctx(image, td.token);
            if (defs == nullptr)
            {
                return;
            }
            for (const rgctx_def & def : *defs)
            {
                rgctx_info r{};
                fill_rgctx(r, def);
                info.rgctxs.push_back(std::move(r));
            }
        }

        std::vector<rgctx_info> generator::generate_rgctx(const std::string & image,
            const method_def & mdef)
        {
            std::vector<rgctx_info> out{};
            const std::vector<rgctx_def> * defs = bin_.get_rgctx(image, mdef.token);
            if (defs != nullptr)
            {
                for (const rgctx_def & def : *defs)
                {
                    rgctx_info r{};
                    fill_rgctx(r, def);
                    out.push_back(std::move(r));
                }
            }
            return out;
        }

        void generator::add_struct(int td_idx)
        {
            const type_def & td = md_.type_defs[static_cast<std::size_t>(td_idx)];
            struct_info info{};
            info.type_name = ex_.struct_name_dic[static_cast<std::size_t>(td_idx)];
            info.is_value_type = td.is_value_type();
            add_parents(td, info);
            add_fields(td, info, nullptr);
            add_vtable_method(info, td);
            add_rgctx(info, td, image_of_type_[static_cast<std::size_t>(td_idx)]);
            list_.push_back(std::move(info));
        }

        void generator::add_generic_class_struct(uint64_t pointer)
        {
            const int td_idx = gc_type_def(pointer);
            const type_def & td = md_.type_defs[static_cast<std::size_t>(td_idx)];
            struct_info info{};
            info.type_name = ex_.generic_class_struct_name_dic.at(pointer);
            info.is_value_type = td.is_value_type();
            add_parents(td, info);
            const generic_context ctx{bin_.u64_va(pointer + 8), bin_.u64_va(pointer + 16)};
            add_fields(td, info, &ctx);
            add_vtable_method(info, td);
            list_.push_back(std::move(info));
        }

        void generator::generate_method_info(const std::string & name, const std::string & struct_type,
            const std::vector<rgctx_info> & rgctxs)
        {
            if (!rgctxs.empty())
            {
                method_info_header_ += "struct " + name + "_RGCTXs {\n";
                for (std::size_t i = 0; i < rgctxs.size(); ++i)
                {
                    const rgctx_info & r = rgctxs[i];
                    const std::string pfx = "_" + std::to_string(i) + "_";
                    if (r.type == 1)
                    {
                        method_info_header_ += "\tIl2CppType* " + pfx + r.type_name + ";\n";
                    }
                    else if (r.type == 2)
                    {
                        method_info_header_ += "\tIl2CppClass* " + pfx + r.class_name + ";\n";
                    }
                    else if (r.type == 3)
                    {
                        method_info_header_ += "\tMethodInfo* " + pfx + r.method_name + ";\n";
                    }
                }
                method_info_header_ += "};\n";
            }
            method_info_header_ += "struct " + name + " {\n";
            method_info_header_ += "\tIl2CppMethodPointer methodPointer;\n";
            method_info_header_ += "\tIl2CppMethodPointer virtualMethodPointer;\n";
            method_info_header_ += "\tInvokerMethod invoker_method;\n";
            method_info_header_ += "\tconst char* name;\n";
            method_info_header_ += "\t" + struct_type + "_c *klass;\n";
            method_info_header_ += "\tconst Il2CppType *return_type;\n";
            method_info_header_ += "\tconst Il2CppType** parameters;\n";
            if (!rgctxs.empty())
            {
                method_info_header_ += "\tconst " + name + "_RGCTXs* rgctx_data;\n";
            }
            else
            {
                method_info_header_ += "\tconst Il2CppRGCTXData* rgctx_data;\n";
            }
            method_info_header_ += "\tunion\n\t{\n\t\tconst void* genericMethod;\n"
                "\t\tconst void* genericContainerHandle;\n\t};\n";
            method_info_header_ += "\tuint32_t token;\n\tuint16_t flags;\n\tuint16_t iflags;\n"
                "\tuint16_t slot;\n\tuint8_t parameters_count;\n\tuint8_t bitflags;\n};\n";
        }

        std::string generator::recursion(std::size_t idx)
        {
            if (!cache_.insert(idx).second)
            {
                return {};
            }
            const struct_info & info = list_[idx];
            std::string sb{};
            std::string pre{};

            if (info.parent.has_value())
            {
                const std::string parent_struct = *info.parent + "_o";
                const auto pit = by_name_.find(parent_struct);
                if (pit != by_name_.end())
                {
                    pre += recursion(pit->second);
                }
                sb += "struct " + info.type_name + "_Fields : " + *info.parent + "_Fields {\n";
            }
            else if (!info.is_value_type)
            {
                sb += "struct __declspec(align(8)) " + info.type_name + "_Fields {\n";
            }
            else
            {
                sb += "struct " + info.type_name + "_Fields {\n";
            }
            for (const field_info & f : info.fields)
            {
                if (f.is_value_type)
                {
                    const auto fit = by_name_.find(f.field_type_name);
                    if (fit != by_name_.end())
                    {
                        pre += recursion(fit->second);
                    }
                }
                if (f.is_custom_type)
                {
                    sb += "\tstruct " + f.field_type_name + " " + f.field_name + ";\n";
                }
                else
                {
                    sb += "\t" + f.field_type_name + " " + f.field_name + ";\n";
                }
            }
            sb += "};\n";

            if (!info.rgctxs.empty())
            {
                sb += "struct " + info.type_name + "_RGCTXs {\n";
                for (std::size_t i = 0; i < info.rgctxs.size(); ++i)
                {
                    const rgctx_info & r = info.rgctxs[i];
                    const std::string pfx = "_" + std::to_string(i) + "_";
                    if (r.type == 1)
                    {
                        sb += "\tIl2CppType* " + pfx + r.type_name + ";\n";
                    }
                    else if (r.type == 2)
                    {
                        sb += "\tIl2CppClass* " + pfx + r.class_name + ";\n";
                    }
                    else if (r.type == 3)
                    {
                        sb += "\tMethodInfo* " + pfx + r.method_name + ";\n";
                    }
                }
                sb += "};\n";
            }

            if (!info.vtable_method.empty())
            {
                sb += "struct " + info.type_name + "_VTable {\n";
                for (std::size_t i = 0; i < info.vtable_method.size(); ++i)
                {
                    sb += "\tVirtualInvokeData _" + std::to_string(i) + "_";
                    sb += info.vtable_method[i].has_value() ? *info.vtable_method[i] : "unknown";
                    sb += ";\n";
                }
                sb += "};\n";
            }

            sb += "struct " + info.type_name + "_c {\n\tIl2CppClass_1 _1;\n";
            sb += info.static_fields.empty()
                ? "\tvoid* static_fields;\n"
                : "\tstruct " + info.type_name + "_StaticFields* static_fields;\n";
            sb += info.rgctxs.empty() ? "\tIl2CppRGCTXData* rgctx_data;\n"
                                      : "\t" + info.type_name + "_RGCTXs* rgctx_data;\n";
            sb += "\tIl2CppClass_2 _2;\n";
            sb += info.vtable_method.empty() ? "\tVirtualInvokeData vtable[32];\n"
                                             : "\t" + info.type_name + "_VTable vtable;\n";
            sb += "};\n";

            sb += "struct " + info.type_name + "_o {\n";
            if (!info.is_value_type)
            {
                sb += "\t" + info.type_name + "_c *klass;\n\tvoid *monitor;\n";
            }
            sb += "\t" + info.type_name + "_Fields fields;\n};\n";

            if (!info.static_fields.empty())
            {
                sb += "struct " + info.type_name + "_StaticFields {\n";
                for (const field_info & f : info.static_fields)
                {
                    if (f.is_value_type)
                    {
                        const auto fit = by_name_.find(f.field_type_name);
                        if (fit != by_name_.end())
                        {
                            pre += recursion(fit->second);
                        }
                    }
                    if (f.is_custom_type)
                    {
                        sb += "\tstruct " + f.field_type_name + " " + f.field_name + ";\n";
                    }
                    else
                    {
                        sb += "\t" + f.field_type_name + " " + f.field_name + ";\n";
                    }
                }
                sb += "};\n";
            }

            return pre + sb;
        }

        std::string generator::build_enums()
        {
            std::vector<int> enums = ex_.enum_type_defs;
            std::sort(enums.begin(), enums.end());
            enums.erase(std::unique(enums.begin(), enums.end()), enums.end());

            std::string out{};
            for (const int td_idx : enums)
            {
                const type_def & td = md_.type_defs[static_cast<std::size_t>(td_idx)];
                if (td.parent_index < 0
                    || static_cast<std::size_t>(td.parent_index) >= bin_.types.size())
                {
                    continue;
                }
                const il2cpp_type & ut = bin_.types[static_cast<std::size_t>(td.parent_index)];
                const std::string underlying = ex_.parse_type(ut);
                const std::string name = ex_.struct_name_dic[static_cast<std::size_t>(td_idx)];
                out += "enum " + name + " : " + underlying + " {\n";
                const int field_end = td.field_start + static_cast<int>(td.field_count);
                for (int i = td.field_start; i < field_end; ++i)
                {
                    const field_def & fd = md_.field_defs[static_cast<std::size_t>(i)];
                    const il2cpp_type & ft = bin_.types[static_cast<std::size_t>(fd.type_index)];
                    if ((ft.attrs & field_attribute_literal) == 0)
                    {
                        continue;
                    }
                    field_default_value fdv{};
                    if (!md_.get_field_default(i, fdv))
                    {
                        continue;
                    }
                    const int64_t value = md_.read_const_int(fdv.data_index, ut.type);
                    out += "\t" + executor::fix_name(md_.get_string(fd.name_index)) + " = "
                        + std::to_string(value) + ",\n";
                }
                out += "};\n";
            }
            return out;
        }

        dump_result generator::run()
        {
            dump_result result{};
            image_of_type_.assign(md_.type_defs.size(), std::string{});
            for (const auto & image : md_.image_defs)
            {
                const std::string image_name = md_.get_string(image.name_index);
                const int end = image.type_start + static_cast<int>(image.type_count);
                for (int ti = image.type_start; ti < end; ++ti)
                {
                    image_of_type_[static_cast<std::size_t>(ti)] = image_name;
                }
            }

            ex_.set_emit(true);

            const auto build_sig = [&](const std::string & full_name, const method_def & m,
                                       const type_def & td, const std::string & this_override,
                                       const std::string & method_info_name,
                                       const generic_context * ctx)
            {
                const il2cpp_type & ret_t = bin_.types[static_cast<std::size_t>(m.return_type)];
                std::string return_type = ex_.parse_type(ret_t, ctx);
                if (ret_t.byref == 1)
                {
                    return_type += "*";
                }
                std::string sig = return_type + " " + executor::fix_name(full_name) + " (";
                std::vector<std::string> params{};
                if ((m.flags & method_attribute_static) == 0)
                {
                    const std::string this_str = this_override.empty()
                        ? ex_.parse_type(bin_.types[static_cast<std::size_t>(td.byval_type_index)])
                        : this_override;
                    params.push_back(this_str + " __this");
                }
                for (int j = 0; j < m.parameter_count; ++j)
                {
                    const parameter_def & pd =
                        md_.parameter_defs[static_cast<std::size_t>(m.parameter_start + j)];
                    const il2cpp_type & pt = bin_.types[static_cast<std::size_t>(pd.type_index)];
                    std::string pc = ex_.parse_type(pt, ctx);
                    if (pt.byref == 1)
                    {
                        pc += "*";
                    }
                    params.push_back(pc + " " + executor::fix_name(md_.get_string(pd.name_index)));
                }
                params.push_back("const " + method_info_name + "* method");
                for (std::size_t k = 0; k < params.size(); ++k)
                {
                    if (k > 0)
                    {
                        sig += ", ";
                    }
                    sig += params[k];
                }
                sig += ");";
                return sig;
            };

            for (const auto & image : md_.image_defs)
            {
                const std::string image_name = md_.get_string(image.name_index);
                const int type_end = image.type_start + static_cast<int>(image.type_count);
                for (int ti = image.type_start; ti < type_end; ++ti)
                {
                    add_struct(ti);
                    const type_def & td = md_.type_defs[static_cast<std::size_t>(ti)];
                    const std::string type_name = ex_.get_type_def_name(td, true, true);
                    const int method_end = td.method_start + static_cast<int>(td.method_count);
                    for (int mi = td.method_start; mi < method_end; ++mi)
                    {
                        const method_def & m = md_.method_defs[static_cast<std::size_t>(mi)];
                        const uint64_t mptr = bin_.method_pointer(image_name, m.token);
                        if (mptr != 0)
                        {
                            const std::string full_name =
                                type_name + "$$" + md_.get_string(m.name_index);
                            script_method_entry e{};
                            e.address = bin_.get_rva(mptr);
                            e.name = full_name;
                            e.signature = build_sig(full_name, m, td, "", "MethodInfo", nullptr);
                            result.methods.push_back(std::move(e));
                        }
                        const auto it = bin_.method_definition_method_specs.find(mi);
                        if (it == bin_.method_definition_method_specs.end())
                        {
                            continue;
                        }
                        for (const int spec_idx : it->second)
                        {
                            const uint64_t gptr = bin_.method_spec_generic_method_pointers[
                                static_cast<std::size_t>(spec_idx)];
                            if (gptr == 0)
                            {
                                continue;
                            }
                            const uint64_t addr = bin_.get_rva(gptr);
                            const std::string method_info_name = std::format("MethodInfo_{:X}", addr);
                            const std::string struct_type = ex_.struct_name_dic[
                                static_cast<std::size_t>(ti)];
                            const std::vector<rgctx_info> rgctxs = generate_rgctx(image_name, m);
                            if (method_info_cache_.insert(gptr).second)
                            {
                                generate_method_info(method_info_name, struct_type, rgctxs);
                            }
                            const method_spec & ms =
                                bin_.method_specs[static_cast<std::size_t>(spec_idx)];
                            const auto ms_names = ex_.get_method_spec_name(ms, true);
                            const std::string full_name = ms_names.first + "$$" + ms_names.second;
                            const generic_context ctx = ex_.get_method_spec_generic_context(ms);
                            std::string this_override{};
                            if ((m.flags & method_attribute_static) == 0
                                && ms.class_index_index != -1)
                            {
                                const std::string tsn = replace_all(struct_type,
                                    executor::fix_name(type_name),
                                    executor::fix_name(ms_names.first));
                                const auto nit = ex_.name_generic_class_dic.find(tsn);
                                this_override = nit != ex_.name_generic_class_dic.end()
                                    ? ex_.parse_type(nit->second)
                                    : ex_.parse_type(bin_.types[static_cast<std::size_t>(
                                          td.byval_type_index)]);
                            }
                            script_method_entry e{};
                            e.address = addr;
                            e.name = full_name;
                            e.signature =
                                build_sig(full_name, m, td, this_override, method_info_name, &ctx);
                            result.methods.push_back(std::move(e));
                        }
                    }
                }
            }

            result.addresses = bin_.ordered_addresses();

            const auto sanitize_literal = [](const std::string & v) -> std::string
            {
                std::string out{};
                out.reserve(v.size());
                for (const char c : v)
                {
                    const unsigned char uc = static_cast<unsigned char>(c);
                    if ((uc >= '0' && uc <= '9') || (uc >= 'A' && uc <= 'Z')
                        || (uc >= 'a' && uc <= 'z'))
                    {
                        out.push_back(c);
                    }
                    else
                    {
                        out.push_back('_');
                    }
                    if (out.size() >= 64)
                    {
                        break;
                    }
                }
                return out;
            };
            std::unordered_map<std::string, int> literal_name_seen{};

            for (const metadata_usage_entry & u : bin_.metadata_usages())
            {
                std::string name{};
                std::string type_base{};
                switch (u.usage)
                {
                case 1:
                    if (u.index < bin_.types.size())
                    {
                        const il2cpp_type & t = bin_.types[u.index];
                        const std::string sig = ex_.get_il2cpp_struct_name(t);
                        name = ex_.get_type_name(t, true, false) + "_TypeInfo";
                        type_base = (sig.size() >= 6 && sig.compare(sig.size() - 6, 6, "_array") == 0)
                            ? "Il2CppClass"
                            : executor::fix_name(sig) + "_c";
                    }
                    break;
                case 2:
                    if (u.index < bin_.types.size())
                    {
                        name = ex_.get_type_name(bin_.types[u.index], true, false) + "_var";
                        type_base = "Il2CppType";
                    }
                    break;
                case 3:
                    if (u.index < md_.method_defs.size())
                    {
                        const method_def & mdef = md_.method_defs[u.index];
                        const type_def & td = md_.type_defs[static_cast<std::size_t>(
                            mdef.declaring_type)];
                        name = "Method$" + ex_.get_type_def_name(td, true, true) + "."
                            + md_.get_string(mdef.name_index) + "()";
                        type_base = "MethodInfo";
                    }
                    break;
                case 4:
                    if (u.index < md_.field_refs.size())
                    {
                        const field_ref & fr = md_.field_refs[u.index];
                        const il2cpp_type & t = bin_.types[static_cast<std::size_t>(fr.type_index)];
                        const int tdi = get_type_definition(t);
                        if (tdi >= 0 && static_cast<std::size_t>(tdi) < md_.type_defs.size())
                        {
                            const type_def & td = md_.type_defs[static_cast<std::size_t>(tdi)];
                            const field_def & fd = md_.field_defs[static_cast<std::size_t>(
                                td.field_start + fr.field_index)];
                            name = "Field$" + ex_.get_type_name(t, true, false) + "."
                                + md_.get_string(fd.name_index);
                            type_base = "FieldInfo";
                        }
                    }
                    break;
                case 6:
                    if (u.index < bin_.method_specs.size())
                    {
                        const auto n = ex_.get_method_spec_name(bin_.method_specs[u.index], true);
                        name = "Method$" + n.first + "." + n.second + "()";
                        type_base = "MethodInfo";
                    }
                    break;
                case 5:
                    if (u.index < md_.string_literals.size())
                    {
                        std::string base = "StringLiteral$"
                            + sanitize_literal(md_.get_string_literal(u.index));
                        const int seen = literal_name_seen[base]++;
                        name = seen == 0 ? base : base + "_" + std::to_string(seen);
                        type_base = "System_String_o";
                    }
                    break;
                default:
                    break;
                }
                if (!name.empty())
                {
                    result.data_symbols.push_back(
                        data_symbol{u.rva, std::move(name), std::move(type_base)});
                }
            }

            if (bin_.code_registration != 0)
            {
                result.data_symbols.push_back(data_symbol{
                    bin_.get_rva(bin_.code_registration), "il2cpp_CodeRegistration",
                    "Il2CppCodeRegistration", 0});
            }
            if (bin_.metadata_registration != 0)
            {
                result.data_symbols.push_back(data_symbol{
                    bin_.get_rva(bin_.metadata_registration), "il2cpp_MetadataRegistration",
                    "Il2CppMetadataRegistration", 0});
            }
            for (const auto & mv : bin_.code_gen_module_vas)
            {
                result.data_symbols.push_back(data_symbol{bin_.get_rva(mv.second),
                    sanitize_literal(mv.first) + "_CodeGenModule", "Il2CppCodeGenModule", 0});
            }
            for (const pointer_table & pt : bin_.pointer_tables)
            {
                result.data_symbols.push_back(data_symbol{bin_.get_rva(pt.va),
                    sanitize_literal(pt.name), pt.elem_type, pt.elem_ptrs, pt.count});
            }

            for (std::size_t i = 0; i < ex_.generic_class_list.size(); ++i)
            {
                add_generic_class_struct(ex_.generic_class_list[i]);
            }

            for (std::size_t i = 0; i < list_.size(); ++i)
            {
                by_name_[list_[i].type_name + "_o"] = i;
            }
            std::string header_struct{};
            for (std::size_t i = 0; i < list_.size(); ++i)
            {
                header_struct += recursion(i);
            }

            const std::string enum_header = build_enums();
            result.il2cpp_h.reserve(header_boilerplate.size() + enum_header.size()
                + header_struct.size() + ex_.array_class_header.size()
                + method_info_header_.size());
            result.il2cpp_h.append(header_boilerplate);
            result.il2cpp_h.append(enum_header);
            result.il2cpp_h.append(header_struct);
            result.il2cpp_h.append(ex_.array_class_header);
            result.il2cpp_h.append(method_info_header_);
            return result;
        }
    }

    dump_result run_dump(const metadata & md, const il2cpp_binary & bin, executor & ex)
    {
        generator g(md, bin, ex);
        return g.run();
    }
}
