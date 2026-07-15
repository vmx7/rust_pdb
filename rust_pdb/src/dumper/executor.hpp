#pragma once

#include "il2cpp_binary.hpp"
#include "metadata.hpp"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace il2pdb::dump
{
    struct generic_context
    {
        uint64_t class_inst;
        uint64_t method_inst;
    };

    class executor
    {
    public:
        executor(const metadata & md, const il2cpp_binary & bin);

        std::vector<std::string> struct_name_dic;
        std::unordered_map<uint64_t, std::string> generic_class_struct_name_dic;
        std::unordered_map<std::string, il2cpp_type> name_generic_class_dic;

        std::string array_class_header;
        std::vector<uint64_t> generic_class_list;
        std::vector<int> enum_type_defs;

        void build_struct_names();
        void set_emit(bool on)
        {
            emit_ = on;
        }
        void set_emit_enum_fields(bool on)
        {
            emit_enum_fields_ = on;
        }

        [[nodiscard]] std::string get_type_def_name(const type_def & td, bool add_namespace,
            bool generic_parameter) const;
        [[nodiscard]] std::string get_type_name(const il2cpp_type & t, bool add_namespace,
            bool is_nested) const;
        std::string parse_type(const il2cpp_type & t, const generic_context * ctx = nullptr);
        std::string get_il2cpp_struct_name(const il2cpp_type & t,
            const generic_context * ctx = nullptr);

        [[nodiscard]] std::pair<std::string, std::string> get_method_spec_name(
            const method_spec & ms, bool add_namespace) const;
        [[nodiscard]] generic_context get_method_spec_generic_context(const method_spec & ms) const;

        [[nodiscard]] static std::string fix_name(const std::string & s);

    private:
        const metadata & md_;
        const il2cpp_binary & bin_;
        std::unordered_set<std::string> struct_name_hash_set_;
        bool emit_ = false;
        bool emit_enum_fields_ = false;

        void parse_array_class_struct(const il2cpp_type & elem, const generic_context * ctx);

        [[nodiscard]] std::string get_generic_container_params(const generic_container & gc) const;
        [[nodiscard]] std::string get_generic_inst_params(uint64_t type_argc,
            uint64_t type_argv) const;
        [[nodiscard]] int type_def_from_type(const il2cpp_type & t) const;
        [[nodiscard]] int generic_param_from_type(const il2cpp_type & t) const;
        [[nodiscard]] int generic_class_type_def(uint64_t generic_class_va) const;
        [[nodiscard]] int enum_element_type_index(const type_def & td) const;
        [[nodiscard]] int resolve_var(const il2cpp_type & t, uint64_t inst_va) const;
        [[nodiscard]] std::string get_unique_name(const std::string & name);
    };
}
