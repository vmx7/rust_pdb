#include "executor.hpp"

namespace il2pdb::dump
{
    namespace
    {
        constexpr uint8_t type_ptr = 0x0F;
        constexpr uint8_t type_valuetype = 0x11;
        constexpr uint8_t type_class = 0x12;
        constexpr uint8_t type_var = 0x13;
        constexpr uint8_t type_array = 0x14;
        constexpr uint8_t type_genericinst = 0x15;
        constexpr uint8_t type_szarray = 0x1D;
        constexpr uint8_t type_mvar = 0x1E;

        std::string replace_all(const std::string & s, const std::string & from,
            const std::string & to)
        {
            if (from.empty())
            {
                return s;
            }
            std::string out{};
            std::size_t pos = 0;
            while (true)
            {
                const std::size_t f = s.find(from, pos);
                if (f == std::string::npos)
                {
                    out.append(s, pos, std::string::npos);
                    break;
                }
                out.append(s, pos, f - pos);
                out.append(to);
                pos = f + from.size();
            }
            return out;
        }

        std::string type_string(uint8_t t)
        {
            switch (t)
            {
            case 1: return "void";
            case 2: return "bool";
            case 3: return "char";
            case 4: return "sbyte";
            case 5: return "byte";
            case 6: return "short";
            case 7: return "ushort";
            case 8: return "int";
            case 9: return "uint";
            case 10: return "long";
            case 11: return "ulong";
            case 12: return "float";
            case 13: return "double";
            case 14: return "string";
            case 22: return "TypedReference";
            case 24: return "IntPtr";
            case 25: return "UIntPtr";
            case 28: return "object";
            default: return "";
            }
        }
    }

    executor::executor(const metadata & md, const il2cpp_binary & bin) : md_(md), bin_(bin)
    {
    }

    int executor::type_def_from_type(const il2cpp_type & t) const
    {
        return static_cast<int>(t.datapoint);
    }

    int executor::generic_param_from_type(const il2cpp_type & t) const
    {
        return static_cast<int>(t.datapoint);
    }

    int executor::enum_element_type_index(const type_def & td) const
    {
        return td.parent_index;
    }

    int executor::generic_class_type_def(uint64_t generic_class_va) const
    {
        const uint64_t type_va = bin_.u64_va(generic_class_va);
        const int ti = bin_.il2cpp_type_index(type_va);
        if (ti < 0)
        {
            return -1;
        }
        return type_def_from_type(bin_.types[static_cast<std::size_t>(ti)]);
    }

    int executor::resolve_var(const il2cpp_type & t, uint64_t inst_va) const
    {
        const int gp = generic_param_from_type(t);
        if (gp < 0 || static_cast<std::size_t>(gp) >= md_.generic_parameters.size())
        {
            return -1;
        }
        const uint16_t num = md_.generic_parameters[static_cast<std::size_t>(gp)].num;
        const uint64_t type_argv = bin_.u64_va(inst_va + 8);
        const uint64_t ptr = bin_.u64_va(type_argv + static_cast<uint64_t>(num) * 8);
        return bin_.il2cpp_type_index(ptr);
    }

    std::string executor::get_generic_container_params(const generic_container & gc) const
    {
        std::string out = "<";
        for (int i = 0; i < gc.type_argc; ++i)
        {
            const generic_parameter & gp = md_.generic_parameters[
                static_cast<std::size_t>(gc.generic_parameter_start + i)];
            if (i > 0)
            {
                out += ", ";
            }
            out += md_.get_string(gp.name_index);
        }
        out += ">";
        return out;
    }

    std::string executor::get_generic_inst_params(uint64_t type_argc, uint64_t type_argv) const
    {
        std::string out = "<";
        for (uint64_t i = 0; i < type_argc; ++i)
        {
            const uint64_t ptr = bin_.u64_va(type_argv + i * 8);
            const int ti = bin_.il2cpp_type_index(ptr);
            if (i > 0)
            {
                out += ", ";
            }
            if (ti >= 0)
            {
                out += get_type_name(bin_.types[static_cast<std::size_t>(ti)], false, false);
            }
        }
        out += ">";
        return out;
    }

    std::string executor::get_type_name(const il2cpp_type & t, bool add_namespace,
        bool is_nested) const
    {
        switch (t.type)
        {
        case type_array:
        {
            const uint64_t etype_va = bin_.u64_va(t.datapoint);
            const uint8_t rank = bin_.u8_va(t.datapoint + 8);
            const int ei = bin_.il2cpp_type_index(etype_va);
            std::string en = ei < 0 ? std::string{}
                                    : get_type_name(bin_.types[static_cast<std::size_t>(ei)],
                                          add_namespace, false);
            const std::string commas(rank > 0 ? static_cast<std::size_t>(rank - 1) : 0, ',');
            return en + "[" + commas + "]";
        }
        case type_szarray:
        {
            const int ei = bin_.il2cpp_type_index(t.datapoint);
            std::string en = ei < 0 ? std::string{}
                                    : get_type_name(bin_.types[static_cast<std::size_t>(ei)],
                                          add_namespace, false);
            return en + "[]";
        }
        case type_ptr:
        {
            const int ei = bin_.il2cpp_type_index(t.datapoint);
            std::string en = ei < 0 ? std::string{}
                                    : get_type_name(bin_.types[static_cast<std::size_t>(ei)],
                                          add_namespace, false);
            return en + "*";
        }
        case type_var:
        case type_mvar:
        {
            const int gi = generic_param_from_type(t);
            if (gi < 0 || static_cast<std::size_t>(gi) >= md_.generic_parameters.size())
            {
                return {};
            }
            return md_.get_string(md_.generic_parameters[static_cast<std::size_t>(gi)].name_index);
        }
        case type_class:
        case type_valuetype:
        case type_genericinst:
        {
            std::string str{};
            const bool is_generic_inst = (t.type == type_genericinst);
            uint64_t generic_class_va = 0;
            int td_idx = -1;
            if (is_generic_inst)
            {
                generic_class_va = t.datapoint;
                td_idx = generic_class_type_def(generic_class_va);
            }
            else
            {
                td_idx = type_def_from_type(t);
            }
            if (td_idx < 0 || static_cast<std::size_t>(td_idx) >= md_.type_defs.size())
            {
                return str;
            }
            const type_def & td = md_.type_defs[static_cast<std::size_t>(td_idx)];
            if (td.declaring_type_index != -1)
            {
                str += get_type_name(
                    bin_.types[static_cast<std::size_t>(td.declaring_type_index)], add_namespace,
                    true);
                str += '.';
            }
            else if (add_namespace)
            {
                const std::string ns = md_.get_string(td.namespace_index);
                if (!ns.empty())
                {
                    str += ns + ".";
                }
            }
            const std::string type_name = md_.get_string(td.name_index);
            const std::size_t bt = type_name.find('`');
            str += bt != std::string::npos ? type_name.substr(0, bt) : type_name;
            if (is_nested)
            {
                return str;
            }
            if (is_generic_inst)
            {
                const uint64_t class_inst_va = bin_.u64_va(generic_class_va + 8);
                const uint64_t argc = bin_.u64_va(class_inst_va);
                const uint64_t argv = bin_.u64_va(class_inst_va + 8);
                str += get_generic_inst_params(argc, argv);
            }
            else if (td.generic_container_index >= 0)
            {
                str += get_generic_container_params(md_.generic_containers[
                    static_cast<std::size_t>(td.generic_container_index)]);
            }
            return str;
        }
        default:
            return type_string(t.type);
        }
    }

    std::string executor::get_type_def_name(const type_def & td, bool add_namespace,
        bool generic_parameter) const
    {
        std::string prefix{};
        if (td.declaring_type_index != -1)
        {
            prefix = get_type_name(
                         bin_.types[static_cast<std::size_t>(td.declaring_type_index)],
                         add_namespace, true)
                + ".";
        }
        else if (add_namespace)
        {
            const std::string ns = md_.get_string(td.namespace_index);
            if (!ns.empty())
            {
                prefix = ns + ".";
            }
        }
        std::string type_name = md_.get_string(td.name_index);
        if (td.generic_container_index >= 0)
        {
            const std::size_t bt = type_name.find('`');
            if (bt != std::string::npos)
            {
                type_name = type_name.substr(0, bt);
            }
            if (generic_parameter)
            {
                type_name += get_generic_container_params(md_.generic_containers[
                    static_cast<std::size_t>(td.generic_container_index)]);
            }
        }
        return prefix + type_name;
    }

    std::string executor::fix_name(const std::string & in)
    {
        static const std::unordered_set<std::string> keyword = {
            "klass", "monitor", "register", "_cs", "auto", "friend", "template", "flat",
            "default", "_ds", "interrupt", "unsigned", "signed", "asm", "if", "case", "break",
            "continue", "do", "new", "_", "short", "union", "class", "namespace"};
        static const std::unordered_set<std::string> special = {"inline", "near", "far"};

        std::string str = in;
        if (keyword.count(str) != 0)
        {
            str = "_" + str;
        }
        else if (special.count(str) != 0)
        {
            str = "_" + str + "_";
        }
        if (!str.empty() && str[0] >= '0' && str[0] <= '9')
        {
            return "_" + str;
        }
        std::string out{};
        out.reserve(str.size());
        for (const char c : str)
        {
            const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '_';
            out.push_back(ok ? c : '_');
        }
        return out;
    }

    std::string executor::get_unique_name(const std::string & name)
    {
        std::string fix = name;
        int i = 1;
        while (!struct_name_hash_set_.insert(fix).second)
        {
            fix = name + "_" + std::to_string(i++);
        }
        return fix;
    }

    void executor::build_struct_names()
    {
        struct_name_dic.assign(md_.type_defs.size(), std::string{});
        for (const auto & image : md_.image_defs)
        {
            const int end = image.type_start + static_cast<int>(image.type_count);
            for (int ti = image.type_start; ti < end; ++ti)
            {
                const auto & td = md_.type_defs[static_cast<std::size_t>(ti)];
                struct_name_dic[static_cast<std::size_t>(ti)] =
                    get_unique_name(fix_name(get_type_def_name(td, true, true)));
            }
        }
        for (const auto & t : bin_.types)
        {
            if (t.type != type_genericinst)
            {
                continue;
            }
            const uint64_t gc_va = t.datapoint;
            const int td_idx = generic_class_type_def(gc_va);
            if (td_idx < 0 || static_cast<std::size_t>(td_idx) >= md_.type_defs.size())
            {
                continue;
            }
            const std::string type_base_name = struct_name_dic[static_cast<std::size_t>(td_idx)];
            const std::string to_replace =
                fix_name(get_type_def_name(md_.type_defs[static_cast<std::size_t>(td_idx)], true,
                    true));
            const std::string replace_with = fix_name(get_type_name(t, true, false));
            const std::string ts = replace_all(type_base_name, to_replace, replace_with);
            name_generic_class_dic[ts] = t;
            generic_class_struct_name_dic[gc_va] = ts;
        }
    }

    void executor::parse_array_class_struct(const il2cpp_type & elem, const generic_context * ctx)
    {
        const std::string sn = get_il2cpp_struct_name(elem, ctx);
        array_class_header += "struct " + sn + "_array {\n\tIl2CppObject obj;\n"
            "\tIl2CppArrayBounds *bounds;\n\til2cpp_array_size_t max_length;\n\t"
            + parse_type(elem, ctx) + " m_Items[65535];\n};\n";
    }

    std::string executor::get_il2cpp_struct_name(const il2cpp_type & t, const generic_context * ctx)
    {
        switch (t.type)
        {
        case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: case 10:
        case 11: case 12: case 13: case 14: case 22: case 24: case 25:
        case type_valuetype: case type_class: case 28:
        {
            const int td = type_def_from_type(t);
            if (td < 0 || static_cast<std::size_t>(td) >= struct_name_dic.size())
            {
                return {};
            }
            return struct_name_dic[static_cast<std::size_t>(td)];
        }
        case type_ptr:
        {
            const int ei = bin_.il2cpp_type_index(t.datapoint);
            return ei < 0 ? std::string{}
                          : get_il2cpp_struct_name(bin_.types[static_cast<std::size_t>(ei)]);
        }
        case type_array:
        {
            const uint64_t etype_va = bin_.u64_va(t.datapoint);
            const int ei = bin_.il2cpp_type_index(etype_va);
            const il2cpp_type & elem = bin_.types[static_cast<std::size_t>(ei)];
            const std::string en = ei < 0 ? std::string{} : get_il2cpp_struct_name(elem, ctx);
            const std::string ts = en + "_array";
            if (emit_ && ei >= 0 && struct_name_hash_set_.insert(ts).second)
            {
                parse_array_class_struct(elem, ctx);
            }
            return ts;
        }
        case type_szarray:
        {
            const int ei = bin_.il2cpp_type_index(t.datapoint);
            const il2cpp_type & elem = bin_.types[static_cast<std::size_t>(ei)];
            const std::string en = ei < 0 ? std::string{} : get_il2cpp_struct_name(elem, ctx);
            const std::string ts = en + "_array";
            if (emit_ && ei >= 0 && struct_name_hash_set_.insert(ts).second)
            {
                parse_array_class_struct(elem, ctx);
            }
            return ts;
        }
        case type_genericinst:
        {
            const auto it = generic_class_struct_name_dic.find(t.datapoint);
            const std::string ts = it == generic_class_struct_name_dic.end() ? std::string{}
                                                                             : it->second;
            if (emit_ && struct_name_hash_set_.insert(ts).second)
            {
                generic_class_list.push_back(t.datapoint);
            }
            return ts;
        }
        case type_var:
        {
            if (ctx != nullptr)
            {
                const int ti = resolve_var(t, ctx->class_inst);
                return ti < 0 ? std::string{}
                              : get_il2cpp_struct_name(bin_.types[static_cast<std::size_t>(ti)]);
            }
            return "System_Object";
        }
        case type_mvar:
        {
            if (ctx != nullptr)
            {
                const int ti = resolve_var(t, ctx->method_inst);
                return ti < 0 ? std::string{}
                              : get_il2cpp_struct_name(bin_.types[static_cast<std::size_t>(ti)]);
            }
            return "System_Object";
        }
        default:
            return {};
        }
    }

    std::string executor::parse_type(const il2cpp_type & t, const generic_context * ctx)
    {
        switch (t.type)
        {
        case 1: return "void";
        case 2: return "bool";
        case 3: return "uint16_t";
        case 4: return "int8_t";
        case 5: return "uint8_t";
        case 6: return "int16_t";
        case 7: return "uint16_t";
        case 8: return "int32_t";
        case 9: return "uint32_t";
        case 10: return "int64_t";
        case 11: return "uint64_t";
        case 12: return "float";
        case 13: return "double";
        case 14: return "System_String_o*";
        case type_ptr:
        {
            const int ei = bin_.il2cpp_type_index(t.datapoint);
            return (ei < 0 ? std::string{}
                           : parse_type(bin_.types[static_cast<std::size_t>(ei)]))
                + "*";
        }
        case type_valuetype:
        {
            const int td = type_def_from_type(t);
            const type_def & d = md_.type_defs[static_cast<std::size_t>(td)];
            if (d.is_enum())
            {
                if (emit_enum_fields_)
                {
                    enum_type_defs.push_back(td);
                    return struct_name_dic[static_cast<std::size_t>(td)];
                }
                return parse_type(bin_.types[static_cast<std::size_t>(enum_element_type_index(d))]);
            }
            return struct_name_dic[static_cast<std::size_t>(td)] + "_o";
        }
        case type_class:
        {
            const int td = type_def_from_type(t);
            return struct_name_dic[static_cast<std::size_t>(td)] + "_o*";
        }
        case type_var:
        {
            if (ctx != nullptr)
            {
                const int ti = resolve_var(t, ctx->class_inst);
                return ti < 0 ? std::string{} : parse_type(bin_.types[static_cast<std::size_t>(ti)]);
            }
            return "Il2CppObject*";
        }
        case type_array:
        {
            const uint64_t etype_va = bin_.u64_va(t.datapoint);
            const int ei = bin_.il2cpp_type_index(etype_va);
            const il2cpp_type & elem = bin_.types[static_cast<std::size_t>(ei)];
            const std::string en = ei < 0 ? std::string{} : get_il2cpp_struct_name(elem, ctx);
            const std::string ts = en + "_array";
            if (emit_ && ei >= 0 && struct_name_hash_set_.insert(ts).second)
            {
                parse_array_class_struct(elem, ctx);
            }
            return ts + "*";
        }
        case type_genericinst:
        {
            const int td = generic_class_type_def(t.datapoint);
            const auto it = generic_class_struct_name_dic.find(t.datapoint);
            const std::string ts = it == generic_class_struct_name_dic.end() ? std::string{}
                                                                             : it->second;
            if (emit_ && struct_name_hash_set_.insert(ts).second)
            {
                generic_class_list.push_back(t.datapoint);
            }
            const type_def & d = md_.type_defs[static_cast<std::size_t>(td)];
            if (d.is_value_type())
            {
                if (d.is_enum())
                {
                    return parse_type(
                        bin_.types[static_cast<std::size_t>(enum_element_type_index(d))]);
                }
                return ts + "_o";
            }
            return ts + "_o*";
        }
        case 0x16: return "Il2CppObject*";
        case 0x18: return "intptr_t";
        case 0x19: return "uintptr_t";
        case 0x1c: return "Il2CppObject*";
        case type_szarray:
        {
            const int ei = bin_.il2cpp_type_index(t.datapoint);
            const il2cpp_type & elem = bin_.types[static_cast<std::size_t>(ei)];
            const std::string en = ei < 0 ? std::string{} : get_il2cpp_struct_name(elem, ctx);
            const std::string ts = en + "_array";
            if (emit_ && ei >= 0 && struct_name_hash_set_.insert(ts).second)
            {
                parse_array_class_struct(elem, ctx);
            }
            return ts + "*";
        }
        case type_mvar:
        {
            if (ctx != nullptr)
            {
                if (ctx->method_inst == 0 && ctx->class_inst != 0)
                {
                    const int ti = resolve_var(t, ctx->class_inst);
                    return ti < 0 ? std::string{}
                                  : parse_type(bin_.types[static_cast<std::size_t>(ti)]);
                }
                const int ti = resolve_var(t, ctx->method_inst);
                return ti < 0 ? std::string{} : parse_type(bin_.types[static_cast<std::size_t>(ti)]);
            }
            return "Il2CppObject*";
        }
        default:
            return {};
        }
    }

    std::pair<std::string, std::string> executor::get_method_spec_name(const method_spec & ms,
        bool add_namespace) const
    {
        const method_def & mdef = md_.method_defs[static_cast<std::size_t>(ms.method_definition_index)];
        const type_def & td = md_.type_defs[static_cast<std::size_t>(mdef.declaring_type)];
        std::string type_name = get_type_def_name(td, add_namespace, false);
        if (ms.class_index_index != -1)
        {
            const generic_inst & ci = bin_.generic_insts[static_cast<std::size_t>(ms.class_index_index)];
            type_name += get_generic_inst_params(ci.type_argc, ci.type_argv);
        }
        std::string method_name = md_.get_string(mdef.name_index);
        if (ms.method_index_index != -1)
        {
            const generic_inst & mi = bin_.generic_insts[static_cast<std::size_t>(ms.method_index_index)];
            method_name += get_generic_inst_params(mi.type_argc, mi.type_argv);
        }
        return {type_name, method_name};
    }

    generic_context executor::get_method_spec_generic_context(const method_spec & ms) const
    {
        const uint64_t ci = ms.class_index_index != -1
            ? bin_.generic_inst_pointers[static_cast<std::size_t>(ms.class_index_index)]
            : 0;
        const uint64_t mi = ms.method_index_index != -1
            ? bin_.generic_inst_pointers[static_cast<std::size_t>(ms.method_index_index)]
            : 0;
        return generic_context{ci, mi};
    }
}
