#pragma once

#include "reader.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace il2pdb::dump
{
    struct pe_section
    {
        uint32_t virtual_size;
        uint32_t virtual_address;
        uint32_t size_of_raw_data;
        uint32_t pointer_to_raw_data;
        uint32_t characteristics;
    };

    struct search_section
    {
        uint64_t offset;
        uint64_t offset_end;
        uint64_t address;
        uint64_t address_end;
    };

    struct il2cpp_type
    {
        uint64_t datapoint;
        uint32_t bits;
        uint32_t attrs;
        uint8_t type;
        uint32_t num_mods;
        uint32_t byref;
        uint32_t pinned;
        uint32_t valuetype;
    };

    struct generic_inst
    {
        uint64_t type_argc;
        uint64_t type_argv;
    };

    struct method_spec
    {
        int32_t method_definition_index;
        int32_t class_index_index;
        int32_t method_index_index;
    };

    struct rgctx_def
    {
        uint64_t type;
        int32_t data_dummy;
    };

    struct metadata_usage_entry
    {
        uint64_t rva;
        uint32_t usage;
        uint32_t index;
    };

    struct pointer_table
    {
        std::string name;
        uint64_t va;
        uint64_t count;
        std::string elem_type = "void";
        uint32_t elem_ptrs = 1;
    };

    class il2cpp_binary
    {
    public:
        il2cpp_binary(std::vector<uint8_t> bytes, int metadata_type_def_count, int image_count);

        uint64_t image_base = 0;
        uint64_t code_registration = 0;
        uint64_t metadata_registration = 0;

        std::unordered_map<std::string, std::vector<uint64_t>> code_gen_module_method_pointers;
        std::vector<std::pair<std::string, uint64_t>> code_gen_module_vas;
        std::vector<pointer_table> pointer_tables;
        std::vector<uint64_t> generic_method_pointers;
        std::vector<uint64_t> invoker_pointers;
        std::vector<uint64_t> reverse_pinvoke_wrappers;
        std::vector<uint64_t> unresolved_virtual_call_pointers;

        [[nodiscard]] std::vector<uint64_t> ordered_addresses() const;
        [[nodiscard]] std::vector<metadata_usage_entry> metadata_usages() const;

        std::vector<il2cpp_type> types;
        std::vector<generic_inst> generic_insts;
        std::vector<uint64_t> generic_inst_pointers;
        std::vector<method_spec> method_specs;
        std::unordered_map<int, std::vector<int>> method_definition_method_specs;
        std::vector<uint64_t> method_spec_generic_method_pointers;
        std::unordered_map<std::string, std::unordered_map<uint32_t, std::vector<rgctx_def>>>
            rgctx_dictionary;

        [[nodiscard]] const std::vector<rgctx_def> * get_rgctx(const std::string & image_name,
            uint32_t token) const;

        [[nodiscard]] uint64_t map_vatr(uint64_t va) const;
        [[nodiscard]] uint64_t map_rtva(uint64_t file_off) const;
        [[nodiscard]] uint64_t get_rva(uint64_t pointer) const noexcept;
        [[nodiscard]] uint64_t method_pointer(const std::string & image_name, uint32_t token) const;
        [[nodiscard]] int il2cpp_type_index(uint64_t pointer) const;
        [[nodiscard]] uint64_t u64_va(uint64_t va) const;
        [[nodiscard]] uint8_t u8_va(uint64_t va) const;

        void init();

    private:
        std::vector<uint8_t> bytes_;
        std::vector<pe_section> sections_;
        std::vector<search_section> exec_;
        std::vector<search_section> data_;
        int type_def_count_;
        int image_count_;
        std::unordered_map<uint64_t, std::vector<uint64_t>> ref_map_;
        std::unordered_map<uint64_t, int> type_dic_;

        [[nodiscard]] uint64_t u64_at(uint64_t file_off) const;
        [[nodiscard]] uint32_t u32_at(uint64_t file_off) const;
        [[nodiscard]] int32_t i32_at(uint64_t file_off) const;
        [[nodiscard]] il2cpp_type read_type(uint64_t type_va) const;
        void read_types_and_generics();
        [[nodiscard]] std::string cstr_at_va(uint64_t va) const;

        void parse_pe();
        void build_ref_map();
        [[nodiscard]] const std::vector<uint64_t> & find_reference(uint64_t addr) const;
        [[nodiscard]] uint64_t find_code_registration();
        [[nodiscard]] uint64_t find_metadata_registration() const;
    };
}
