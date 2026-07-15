#include "il2cpp.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <tuple>

namespace il2pdb
{
    namespace
    {
        struct field
        {
            std::string base;
            uint32_t ptrs;
            std::vector<uint64_t> dims;
            std::string name;
        };

        struct agg
        {
            bool is_union;
            std::optional<uint32_t> align_override;
            std::vector<field> fields;
        };

        struct layout
        {
            uint64_t size;
            uint32_t align;
            std::vector<uint64_t> offsets;
        };

        using defs_map = std::unordered_map<std::string, agg>;
        using typedef_map = std::unordered_map<std::string, tdef>;
        using layout_map = std::unordered_map<std::string, layout>;
        using arr_cache_t = std::map<std::pair<uint32_t, uint64_t>, uint32_t>;

        bool is_ws(char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
        }

        std::string_view trim(std::string_view s)
        {
            std::size_t a = 0;
            std::size_t b = s.size();
            while (a < b && is_ws(s[a]))
            {
                ++a;
            }
            while (b > a && is_ws(s[b - 1]))
            {
                --b;
            }
            return s.substr(a, b - a);
        }

        bool starts_with(std::string_view s, std::string_view p)
        {
            return s.size() >= p.size() && s.substr(0, p.size()) == p;
        }

        bool ends_with(std::string_view s, std::string_view p)
        {
            return s.size() >= p.size() && s.substr(s.size() - p.size()) == p;
        }

        std::vector<std::string_view> split_ws(std::string_view s)
        {
            std::vector<std::string_view> out{};
            std::size_t i = 0;
            while (i < s.size())
            {
                while (i < s.size() && is_ws(s[i]))
                {
                    ++i;
                }
                const std::size_t start = i;
                while (i < s.size() && !is_ws(s[i]))
                {
                    ++i;
                }
                if (i > start)
                {
                    out.push_back(s.substr(start, i - start));
                }
            }
            return out;
        }

        std::vector<std::string_view> split_char(std::string_view s, char ch)
        {
            std::vector<std::string_view> out{};
            std::size_t start = 0;
            for (std::size_t i = 0; i < s.size(); ++i)
            {
                if (s[i] == ch)
                {
                    out.push_back(s.substr(start, i - start));
                    start = i + 1;
                }
            }
            out.push_back(s.substr(start));
            return out;
        }

        std::string replace_all(std::string_view s, std::string_view from, std::string_view to)
        {
            std::string out{};
            std::size_t i = 0;
            while (i < s.size())
            {
                if (i + from.size() <= s.size() && s.substr(i, from.size()) == from)
                {
                    out.append(to);
                    i += from.size();
                }
                else
                {
                    out.push_back(s[i]);
                    ++i;
                }
            }
            return out;
        }

        std::string join_ws(const std::vector<std::string_view> & toks, std::size_t begin,
            std::size_t end)
        {
            std::string out{};
            for (std::size_t i = begin; i < end; ++i)
            {
                if (i > begin)
                {
                    out.push_back(' ');
                }
                out.append(toks[i]);
            }
            return out;
        }

        std::optional<std::tuple<uint32_t, uint64_t, uint32_t>> primitive(std::string_view n)
        {
            if (n == "void")
                return std::make_tuple(0x0003u, 0ull, 1u);
            if (n == "bool")
                return std::make_tuple(0x0030u, 1ull, 1u);
            if (n == "char")
                return std::make_tuple(0x0070u, 1ull, 1u);
            if (n == "signed char" || n == "int8_t")
                return std::make_tuple(0x0068u, 1ull, 1u);
            if (n == "unsigned char" || n == "uint8_t")
                return std::make_tuple(0x0069u, 1ull, 1u);
            if (n == "short" || n == "short int" || n == "int16_t")
                return std::make_tuple(0x0072u, 2ull, 2u);
            if (n == "unsigned short" || n == "uint16_t" || n == "wchar_t")
                return std::make_tuple(0x0073u, 2ull, 2u);
            if (n == "int" || n == "int32_t" || n == "long" || n == "long int")
                return std::make_tuple(0x0074u, 4ull, 4u);
            if (n == "unsigned int" || n == "unsigned" || n == "uint32_t" || n == "unsigned long")
                return std::make_tuple(0x0075u, 4ull, 4u);
            if (n == "long long" || n == "long long int" || n == "int64_t")
                return std::make_tuple(0x0076u, 8ull, 8u);
            if (n == "unsigned long long" || n == "uint64_t")
                return std::make_tuple(0x0077u, 8ull, 8u);
            if (n == "intptr_t")
                return std::make_tuple(0x0076u, 8ull, 8u);
            if (n == "uintptr_t" || n == "size_t")
                return std::make_tuple(0x0077u, 8ull, 8u);
            if (n == "float")
                return std::make_tuple(0x0040u, 4ull, 4u);
            if (n == "double" || n == "long double")
                return std::make_tuple(0x0041u, 8ull, 8u);
            return std::nullopt;
        }

        std::string unique_name(std::string_view n)
        {
            std::string out = ".?AU";
            out.append(n);
            out.append("@@");
            return out;
        }

        std::optional<field> parse_field(std::string_view t)
        {
            std::string s{};
            {
                std::string_view v = t;
                while (!v.empty() && v.back() == ';')
                {
                    v = v.substr(0, v.size() - 1);
                }
                s = std::string(trim(v));
            }
            if (s.empty())
            {
                return std::nullopt;
            }

            if (const std::size_t p = s.find("(*"); p != std::string::npos)
            {
                std::string_view after = std::string_view(s).substr(p + 2);
                if (const std::size_t e = after.find(')'); e != std::string_view::npos)
                {
                    std::string_view nm = trim(after.substr(0, e));
                    while (!nm.empty() && nm.front() == '*')
                    {
                        nm = nm.substr(1);
                    }
                    return field{"void", 1, {}, std::string(nm)};
                }
            }

            if (const std::size_t c = s.find(':'); c != std::string::npos)
            {
                s = std::string(trim(std::string_view(s).substr(0, c)));
            }

            std::vector<uint64_t> dims{};
            while (true)
            {
                const std::size_t open = s.rfind('[');
                if (open == std::string::npos)
                {
                    break;
                }
                const std::size_t close_rel = s.find(']', open);
                if (close_rel == std::string::npos)
                {
                    break;
                }
                const std::string_view inner =
                    trim(std::string_view(s).substr(open + 1, close_rel - open - 1));
                uint64_t d = 0;
                {
                    uint64_t acc = 0;
                    bool ok = !inner.empty();
                    for (const char ch : inner)
                    {
                        if (ch < '0' || ch > '9')
                        {
                            ok = false;
                            break;
                        }
                        acc = acc * 10 + static_cast<uint64_t>(ch - '0');
                    }
                    d = ok ? acc : 0;
                }
                dims.insert(dims.begin(), d);
                s.erase(open, close_rel - open + 1);
            }

            std::string cleaned = replace_all(s, "const", " ");
            cleaned = replace_all(cleaned, "volatile", " ");
            const std::string_view cleaned_t = trim(cleaned);
            uint32_t ptrs = 0;
            for (const char ch : cleaned_t)
            {
                if (ch == '*')
                {
                    ++ptrs;
                }
            }
            const std::string no_star = replace_all(cleaned_t, "*", " ");
            std::vector<std::string_view> toks = split_ws(no_star);
            if (!toks.empty() && (toks[0] == "struct" || toks[0] == "union" || toks[0] == "enum"))
            {
                toks.erase(toks.begin());
            }
            if (toks.size() < 2)
            {
                return std::nullopt;
            }
            std::string name(toks.back());
            std::string base = join_ws(toks, 0, toks.size() - 1);
            return field{std::move(base), ptrs, std::move(dims), std::move(name)};
        }

        std::optional<std::tuple<std::string, std::optional<uint32_t>, bool>> parse_open(
            std::string_view t)
        {
            const bool brace = ends_with(t, "{");
            std::string_view body = t;
            while (!body.empty() && body.back() == '{')
            {
                body = body.substr(0, body.size() - 1);
            }
            body = trim(body);
            std::string_view rest{};
            if (starts_with(body, "struct"))
            {
                rest = trim(body.substr(6));
            }
            else if (starts_with(body, "union"))
            {
                rest = trim(body.substr(5));
            }
            else
            {
                return std::nullopt;
            }
            std::optional<uint32_t> align{};
            const std::string_view decl = "__declspec(align(";
            if (starts_with(rest, decl))
            {
                std::string_view a = rest.substr(decl.size());
                const std::size_t end = a.find("))");
                if (end == std::string_view::npos)
                {
                    return std::nullopt;
                }
                uint32_t val = 0;
                bool ok = end > 0;
                for (std::size_t i = 0; i < end; ++i)
                {
                    const char ch = a[i];
                    if (ch < '0' || ch > '9')
                    {
                        ok = false;
                        break;
                    }
                    val = val * 10 + static_cast<uint32_t>(ch - '0');
                }
                if (ok)
                {
                    align = val;
                }
                rest = trim(a.substr(end + 2));
            }
            const std::vector<std::string_view> toks = split_ws(rest);
            if (toks.empty() || toks[0].empty())
            {
                return std::nullopt;
            }
            return std::make_tuple(std::string(toks[0]), align, brace);
        }

        void parse_typedef(std::string_view t, typedef_map & typedefs)
        {
            std::string_view body = t;
            if (starts_with(body, "typedef"))
            {
                body = body.substr(7);
            }
            body = trim(body);
            while (!body.empty() && body.back() == ';')
            {
                body = body.substr(0, body.size() - 1);
            }

            if (const std::size_t p = body.find("(*"); p != std::string_view::npos)
            {
                std::string_view after = body.substr(p + 2);
                if (const std::size_t e = after.find(')'); e != std::string_view::npos)
                {
                    const std::string_view name = trim(after.substr(0, e));
                    if (!name.empty())
                    {
                        typedefs[std::string(name)] = tdef{true, 0, 0, 0};
                    }
                    return;
                }
            }

            const std::vector<std::string_view> toks = split_ws(body);
            if (toks.size() >= 2)
            {
                const std::string name(toks.back());
                const std::string underlying = join_ws(toks, 0, toks.size() - 1);
                if (const auto pr = primitive(underlying))
                {
                    typedefs[name] =
                        tdef{false, std::get<0>(*pr), std::get<1>(*pr), std::get<2>(*pr)};
                }
            }
        }

        void parse(const std::string & header, defs_map & defs, std::vector<std::string> & order,
            typedef_map & typedefs, std::vector<std::string> & fwd_only)
        {
            std::optional<std::pair<std::string, agg>> cur{};
            std::optional<std::tuple<std::string, bool, std::optional<uint32_t>>> pending{};

            std::size_t pos = 0;
            const std::size_t len = header.size();
            while (pos <= len)
            {
                std::size_t nl = header.find('\n', pos);
                std::size_t line_end = (nl == std::string::npos) ? len : nl;
                std::string_view raw(header.data() + pos, line_end - pos);
                pos = (nl == std::string::npos) ? len + 1 : nl + 1;

                const std::string_view tsv = trim(raw);
                if (tsv.empty() || starts_with(tsv, "//"))
                {
                    continue;
                }

                if (cur.has_value())
                {
                    if (tsv == "};" || tsv == "}" || (!tsv.empty() && tsv.front() == '}'))
                    {
                        std::string name = std::move(cur->first);
                        agg a = std::move(cur->second);
                        cur.reset();
                        if (defs.find(name) == defs.end())
                        {
                            order.push_back(name);
                        }
                        defs[name] = std::move(a);
                        continue;
                    }
                    if (auto f = parse_field(tsv))
                    {
                        cur->second.fields.push_back(std::move(*f));
                    }
                    continue;
                }

                if (pending.has_value())
                {
                    if (!tsv.empty() && tsv.front() == '{')
                    {
                        auto [name, is_union, align] = std::move(*pending);
                        pending.reset();
                        cur = std::make_pair(std::move(name),
                            agg{is_union, align, std::vector<field>{}});
                        continue;
                    }
                    pending.reset();
                }

                if (starts_with(tsv, "typedef"))
                {
                    parse_typedef(tsv, typedefs);
                    continue;
                }
                if (starts_with(tsv, "struct") || starts_with(tsv, "union"))
                {
                    const bool is_union = starts_with(tsv, "union");
                    if (ends_with(tsv, ";") && tsv.find('{') == std::string_view::npos)
                    {
                        std::string_view nm = tsv;
                        while (!nm.empty() && nm.back() == ';')
                        {
                            nm = nm.substr(0, nm.size() - 1);
                        }
                        const std::vector<std::string_view> toks = split_ws(nm);
                        if (!toks.empty())
                        {
                            fwd_only.push_back(std::string(toks.back()));
                        }
                        continue;
                    }
                    if (auto op = parse_open(tsv))
                    {
                        auto [name, align, brace] = std::move(*op);
                        if (brace)
                        {
                            cur = std::make_pair(std::move(name),
                                agg{is_union, align, std::vector<field>{}});
                        }
                        else
                        {
                            pending = std::make_tuple(std::move(name), is_union, align);
                        }
                    }
                }
            }
        }

        uint64_t align_up(uint64_t v, uint64_t a)
        {
            if (a <= 1)
            {
                return v;
            }
            return (v + a - 1) / a * a;
        }

        struct enum_parsed
        {
            std::string name;
            std::string underlying;
            std::vector<enum_member> members;
        };

        std::vector<enum_parsed> parse_enums(const std::string & header)
        {
            std::vector<enum_parsed> out{};
            std::size_t pos = 0;
            const std::size_t len = header.size();
            int cur = -1;
            while (pos <= len)
            {
                const std::size_t nl = header.find('\n', pos);
                const std::size_t line_end = (nl == std::string::npos) ? len : nl;
                const std::string_view t = trim(std::string_view(header.data() + pos, line_end - pos));
                pos = (nl == std::string::npos) ? len + 1 : nl + 1;

                if (cur < 0)
                {
                    if (starts_with(t, "enum ") && ends_with(t, "{"))
                    {
                        std::string_view body = trim(t.substr(5));
                        body = trim(body.substr(0, body.size() - 1));
                        const std::size_t colon = body.find(" : ");
                        if (colon != std::string_view::npos)
                        {
                            enum_parsed e{};
                            e.name = std::string(trim(body.substr(0, colon)));
                            e.underlying = std::string(trim(body.substr(colon + 3)));
                            out.push_back(std::move(e));
                            cur = static_cast<int>(out.size()) - 1;
                        }
                    }
                    continue;
                }
                if (t == "};")
                {
                    cur = -1;
                    continue;
                }
                const std::size_t eq = t.find(" = ");
                if (eq != std::string_view::npos)
                {
                    std::string_view val = t.substr(eq + 3);
                    if (!val.empty() && val.back() == ',')
                    {
                        val = val.substr(0, val.size() - 1);
                    }
                    int64_t v = 0;
                    bool neg = false;
                    std::size_t i = 0;
                    if (!val.empty() && val[0] == '-')
                    {
                        neg = true;
                        i = 1;
                    }
                    for (; i < val.size(); ++i)
                    {
                        if (val[i] < '0' || val[i] > '9')
                        {
                            break;
                        }
                        v = v * 10 + (val[i] - '0');
                    }
                    out[static_cast<std::size_t>(cur)].members.push_back(
                        enum_member{std::string(t.substr(0, eq)), neg ? -v : v});
                }
            }
            return out;
        }

        std::pair<uint64_t, uint32_t> compute_layout(const std::string & name, const defs_map & defs,
            const typedef_map & typedefs, layout_map & out, std::vector<std::string> & stack);

        std::pair<uint64_t, uint32_t> field_size_align(const field & f, const defs_map & defs,
            const typedef_map & typedefs, layout_map & out, std::vector<std::string> & stack)
        {
            uint64_t elem_size = 1;
            uint32_t elem_align = 1;
            if (f.ptrs > 0)
            {
                elem_size = 8;
                elem_align = 8;
            }
            else if (const auto pr = primitive(f.base))
            {
                elem_size = std::get<1>(*pr);
                elem_align = std::get<2>(*pr);
            }
            else if (const auto td = typedefs.find(f.base); td != typedefs.end())
            {
                if (td->second.is_void_ptr)
                {
                    elem_size = 8;
                    elem_align = 8;
                }
                else
                {
                    elem_size = td->second.s;
                    elem_align = td->second.a;
                }
            }
            else if (defs.find(f.base) != defs.end())
            {
                const auto r = compute_layout(f.base, defs, typedefs, out, stack);
                elem_size = r.first;
                elem_align = r.second;
            }
            uint64_t n = 1;
            for (const uint64_t d : f.dims)
            {
                n *= d;
            }
            return {elem_size * n, elem_align};
        }

        std::pair<uint64_t, uint32_t> compute_layout(const std::string & name, const defs_map & defs,
            const typedef_map & typedefs, layout_map & out, std::vector<std::string> & stack)
        {
            if (const auto it = out.find(name); it != out.end())
            {
                return {it->second.size, it->second.align};
            }
            const auto da = defs.find(name);
            if (da == defs.end())
            {
                return {1, 1};
            }
            const agg & agg_ = da->second;
            for (const std::string & s : stack)
            {
                if (s == name)
                {
                    return {1, 1};
                }
            }
            stack.push_back(name);

            std::vector<uint64_t> offsets{};
            offsets.reserve(agg_.fields.size());
            uint32_t max_align = 1;
            uint64_t size = 0;
            for (const field & f : agg_.fields)
            {
                const auto [fsize, falign] = field_size_align(f, defs, typedefs, out, stack);
                if (!agg_.is_union)
                {
                    const uint64_t off = align_up(size, falign);
                    offsets.push_back(off);
                    size = off + fsize;
                }
                else
                {
                    offsets.push_back(0);
                    size = std::max(size, fsize);
                }
                max_align = std::max(max_align, falign);
            }
            if (agg_.align_override.has_value())
            {
                max_align = std::max(max_align, *agg_.align_override);
            }
            const uint64_t total = align_up(size, max_align);
            stack.pop_back();
            out[name] = layout{total, max_align, std::move(offsets)};
            return {total, max_align};
        }

        std::vector<std::string> topo_sort(const std::vector<std::string> & order,
            const defs_map & defs, const typedef_map & typedefs)
        {
            std::vector<std::string> result{};
            result.reserve(order.size());
            std::unordered_map<std::string, uint8_t> state{};
            for (const std::string & start : order)
            {
                if (const auto it = state.find(start); it != state.end() && it->second == 2)
                {
                    continue;
                }
                std::vector<std::pair<std::string, std::size_t>> stack{};
                stack.push_back({start, 0});
                while (!stack.empty())
                {
                    const std::string node = stack.back().first;
                    const std::size_t idx = stack.back().second;
                    if (uint8_t & e = state[node]; e == 0)
                    {
                        e = 1;
                    }
                    const agg & a = defs.at(node);
                    bool moved = false;
                    std::size_t i = idx;
                    while (i < a.fields.size())
                    {
                        const field & f = a.fields[i];
                        ++i;
                        if (f.ptrs == 0 && !primitive(f.base)
                            && typedefs.find(f.base) == typedefs.end()
                            && defs.find(f.base) != defs.end())
                        {
                            uint8_t st = 0;
                            if (const auto s2 = state.find(f.base); s2 != state.end())
                            {
                                st = s2->second;
                            }
                            if (st == 0)
                            {
                                stack.back().second = i;
                                stack.push_back({f.base, 0});
                                moved = true;
                                break;
                            }
                        }
                    }
                    if (!moved)
                    {
                        state[node] = 2;
                        result.push_back(node);
                        stack.pop_back();
                    }
                }
            }
            return result;
        }

        std::pair<uint32_t, uint64_t> base_value_index(il2cpp_types & t, const std::string & base)
        {
            if (const auto pr = primitive(base))
            {
                return {std::get<0>(*pr), std::get<1>(*pr)};
            }
            if (const auto en = t.name_to_enum.find(base); en != t.name_to_enum.end())
            {
                return {en->second.first, en->second.second};
            }
            if (const auto td = t.typedefs.find(base); td != t.typedefs.end())
            {
                if (td->second.is_void_ptr)
                {
                    return {t.intern_ptr(t_void), 8};
                }
                return {td->second.i, td->second.s};
            }
            if (const auto c = t.name_to_complete.find(base); c != t.name_to_complete.end())
            {
                return {c->second, 0};
            }
            if (const auto f = t.name_to_fwd.find(base); f != t.name_to_fwd.end())
            {
                return {f->second, 1};
            }
            return {t_void, 1};
        }

        uint32_t intern_arr(il2cpp_types & t, uint32_t elem, uint64_t size, arr_cache_t & cache)
        {
            const auto key = std::make_pair(elem, size);
            if (const auto it = cache.find(key); it != cache.end())
            {
                return it->second;
            }
            const uint32_t ti = 0x1000 + static_cast<uint32_t>(t.records.size());
            t.records.push_back(array_type(elem, size));
            cache[key] = ti;
            return ti;
        }

        uint32_t resolve_field_index(il2cpp_types & t, const field & f,
            const layout_map & layouts, arr_cache_t & arr_cache)
        {
            uint32_t elem_index = t_void;
            uint64_t elem_size = 1;
            if (f.ptrs > 0)
            {
                uint32_t referent = t_void;
                if (const auto pr = primitive(f.base))
                {
                    referent = std::get<0>(*pr);
                }
                else if (const auto td = t.typedefs.find(f.base); td != t.typedefs.end())
                {
                    referent = td->second.is_void_ptr ? t.intern_ptr(t_void) : td->second.i;
                }
                else if (const auto fi = t.name_to_fwd.find(f.base); fi != t.name_to_fwd.end())
                {
                    referent = fi->second;
                }
                uint32_t idx = t.intern_ptr(referent);
                for (uint32_t k = 1; k < f.ptrs; ++k)
                {
                    idx = t.intern_ptr(idx);
                }
                elem_index = idx;
                elem_size = 8;
            }
            else
            {
                const auto [i, s] = base_value_index(t, f.base);
                uint64_t sz = s;
                if (s == 0)
                {
                    const auto l = layouts.find(f.base);
                    sz = (l != layouts.end()) ? l->second.size : 1;
                }
                elem_index = i;
                elem_size = sz;
            }

            if (f.dims.empty())
            {
                return elem_index;
            }
            uint64_t n = 1;
            for (const uint64_t d : f.dims)
            {
                n *= d;
            }
            return intern_arr(t, elem_index, elem_size * n, arr_cache);
        }

        uint32_t build_fieldlist(il2cpp_types & t, const std::vector<member> & members)
        {
            constexpr std::size_t limit = 0xFF00;
            std::vector<std::pair<std::size_t, std::size_t>> chunks{};
            std::size_t start = 0;
            std::size_t acc = 0;
            for (std::size_t i = 0; i < members.size(); ++i)
            {
                const std::size_t sz = 2 + 2 + 4 + 8 + members[i].name.size() + 1 + 3;
                if (acc + sz > limit && i > start)
                {
                    chunks.push_back({start, i});
                    start = i;
                    acc = 0;
                }
                acc += sz;
            }
            chunks.push_back({start, members.size()});

            const std::span<const member> all(members);
            if (chunks.size() == 1)
            {
                const uint32_t ti = 0x1000 + static_cast<uint32_t>(t.records.size());
                t.records.push_back(fieldlist(
                    all.subspan(chunks[0].first, chunks[0].second - chunks[0].first)));
                return ti;
            }
            const uint32_t first_ti = 0x1000 + static_cast<uint32_t>(t.records.size());
            const std::size_t n = chunks.size();
            for (std::size_t k = 0; k < n; ++k)
            {
                std::optional<uint32_t> cont{};
                if (k + 1 < n)
                {
                    cont = first_ti + static_cast<uint32_t>(k) + 1;
                }
                t.records.push_back(fieldlist_cont(
                    all.subspan(chunks[k].first, chunks[k].second - chunks[k].first), cont));
            }
            return first_ti;
        }
    }

    uint32_t il2cpp_types::intern_ptr(uint32_t referent)
    {
        if (const auto it = ptr_cache.find(referent); it != ptr_cache.end())
        {
            return it->second;
        }
        const uint32_t ti = 0x1000 + static_cast<uint32_t>(records.size());
        records.push_back(ptr64(referent));
        ptr_cache[referent] = ti;
        return ti;
    }

    uint32_t il2cpp_types::make_array(uint32_t elem, uint64_t byte_size)
    {
        const uint32_t ti = 0x1000 + static_cast<uint32_t>(records.size());
        records.push_back(array_type(elem, byte_size));
        return ti;
    }

    uint32_t il2cpp_types::resolve_typeref(std::string_view base, uint32_t ptrs)
    {
        const std::string b(base);
        if (ptrs > 0)
        {
            uint32_t referent = t_void;
            if (const auto pr = primitive(base))
            {
                referent = std::get<0>(*pr);
            }
            else if (const auto td = typedefs.find(b); td != typedefs.end())
            {
                referent = td->second.is_void_ptr ? intern_ptr(t_void) : td->second.i;
            }
            else if (const auto fi = name_to_fwd.find(b); fi != name_to_fwd.end())
            {
                referent = fi->second;
            }
            uint32_t idx = intern_ptr(referent);
            for (uint32_t k = 1; k < ptrs; ++k)
            {
                idx = intern_ptr(idx);
            }
            return idx;
        }
        if (const auto pr = primitive(base))
        {
            return std::get<0>(*pr);
        }
        if (const auto td = typedefs.find(b); td != typedefs.end())
        {
            return td->second.is_void_ptr ? intern_ptr(t_void) : td->second.i;
        }
        if (const auto c = name_to_complete.find(b); c != name_to_complete.end())
        {
            return c->second;
        }
        if (const auto f = name_to_fwd.find(b); f != name_to_fwd.end())
        {
            return f->second;
        }
        return t_void;
    }

    uint32_t il2cpp_types::proc_type(uint32_t ret, const std::vector<uint32_t> & params)
    {
        const auto key = std::make_pair(ret, params);
        if (const auto it = proc_cache.find(key); it != proc_cache.end())
        {
            return it->second;
        }
        uint32_t arglist_ti = 0;
        if (const auto it = arglist_cache.find(params); it != arglist_cache.end())
        {
            arglist_ti = it->second;
        }
        else
        {
            arglist_ti = 0x1000 + static_cast<uint32_t>(records.size());
            records.push_back(arglist(params));
            arglist_cache[params] = arglist_ti;
        }
        const uint32_t ti = 0x1000 + static_cast<uint32_t>(records.size());
        records.push_back(procedure(ret, arglist_ti, static_cast<uint16_t>(params.size())));
        proc_cache[key] = ti;
        return ti;
    }

    uint32_t il2cpp_types::sig_to_proc(std::string_view sig)
    {
        const std::size_t p = sig.find('(');
        if (p == std::string_view::npos)
        {
            return 0;
        }
        std::size_t rp = sig.rfind(')');
        if (rp == std::string_view::npos)
        {
            rp = sig.size();
        }
        const std::string_view head = sig.substr(0, p);
        const std::size_t params_len = (rp >= p + 1) ? rp - (p + 1) : 0;
        const std::string_view params_str = sig.substr(p + 1, params_len);

        uint32_t ret = t_void;
        {
            std::string hf(trim(head));
            hf.push_back(';');
            if (const auto f = parse_field(hf))
            {
                ret = resolve_typeref(f->base, f->ptrs);
            }
        }

        std::vector<uint32_t> params{};
        const std::string_view ps = trim(params_str);
        if (!ps.empty() && ps != "void")
        {
            for (const std::string_view part : split_char(ps, ','))
            {
                const std::string_view pt = trim(part);
                if (pt.empty())
                {
                    continue;
                }
                if (pt.find("(*") != std::string_view::npos)
                {
                    params.push_back(resolve_typeref("void", 1));
                    continue;
                }
                std::string pf(pt);
                pf.push_back(';');
                if (const auto f = parse_field(pf))
                {
                    params.push_back(resolve_typeref(f->base, f->ptrs));
                }
            }
        }
        return proc_type(ret, params);
    }

    il2cpp_types parse_and_build(const std::string & header)
    {
        defs_map defs{};
        std::vector<std::string> order{};
        std::vector<std::string> fwd_only{};
        il2cpp_types t{};

        parse(header, defs, order, t.typedefs, fwd_only);

        const std::vector<enum_parsed> enums = parse_enums(header);
        for (const enum_parsed & e : enums)
        {
            const auto pr = primitive(e.underlying);
            const uint32_t pi = pr ? std::get<0>(*pr) : t_int4;
            const uint64_t ps = pr ? std::get<1>(*pr) : 4;
            const uint32_t pa = pr ? std::get<2>(*pr) : 4;
            t.typedefs[e.name] = tdef{false, pi, ps, pa};
        }

        layout_map layouts{};
        for (const std::string & n : order)
        {
            std::vector<std::string> stack{};
            compute_layout(n, defs, t.typedefs, layouts, stack);
        }

        std::vector<std::pair<std::string, bool>> all_names{};
        for (const std::string & n : order)
        {
            all_names.push_back({n, defs.at(n).is_union});
        }
        for (const std::string & n : fwd_only)
        {
            if (defs.find(n) == defs.end())
            {
                all_names.push_back({n, false});
            }
        }
        for (const auto & [n, is_union] : all_names)
        {
            const uint32_t ti = 0x1000 + static_cast<uint32_t>(t.records.size());
            const std::string uniq = unique_name(n);
            t.records.push_back(is_union ? union_fwdref(n, uniq) : struct_fwdref(n, uniq));
            t.name_to_fwd[n] = ti;
        }

        for (const enum_parsed & e : enums)
        {
            if (e.members.size() > 2000)
            {
                continue;
            }
            const auto pr = primitive(e.underlying);
            const uint32_t pi = pr ? std::get<0>(*pr) : t_int4;
            const uint64_t ps = pr ? std::get<1>(*pr) : 4;
            const uint32_t fl = 0x1000 + static_cast<uint32_t>(t.records.size());
            t.records.push_back(enum_fieldlist(e.members));
            const uint32_t ti = 0x1000 + static_cast<uint32_t>(t.records.size());
            const std::string uniq = ".?AW4" + e.name + "@@";
            t.records.push_back(enum_def(e.name, uniq, pi,
                static_cast<uint16_t>(e.members.size()), fl));
            t.name_to_enum[e.name] = {ti, ps};
        }

        const std::vector<std::string> topo = topo_sort(order, defs, t.typedefs);
        arr_cache_t arr_cache{};

        for (const std::string & name : topo)
        {
            const agg & a = defs.at(name);
            const layout & lay = layouts.at(name);
            std::vector<member> members{};
            members.reserve(a.fields.size());
            for (std::size_t fi = 0; fi < a.fields.size(); ++fi)
            {
                const uint32_t idx = resolve_field_index(t, a.fields[fi], layouts, arr_cache);
                members.push_back(member{a.fields[fi].name, idx, lay.offsets[fi]});
            }
            const uint32_t fl_idx = build_fieldlist(t, members);
            const uint32_t ti = 0x1000 + static_cast<uint32_t>(t.records.size());
            const std::string uniq = unique_name(name);
            const uint16_t count = static_cast<uint16_t>(members.size());
            t.records.push_back(a.is_union
                    ? union_def(name, uniq, count, fl_idx, lay.size)
                    : struct_def(name, uniq, count, fl_idx, lay.size));
            t.name_to_complete[name] = ti;
        }

        return t;
    }
}
