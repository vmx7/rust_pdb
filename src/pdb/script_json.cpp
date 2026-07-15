#include "script_json.hpp"

#include <stdexcept>

namespace il2pdb
{
    namespace
    {
        class parser
        {
        public:
            explicit parser(const std::string & s) : s_(s)
            {
            }

            script parse_root()
            {
                script out{};
                ws();
                expect('{');
                ws();
                if (peek() == '}')
                {
                    ++i_;
                    return out;
                }
                while (true)
                {
                    ws();
                    const std::string key = parse_string();
                    ws();
                    expect(':');
                    ws();
                    if (key == "ScriptMethod")
                    {
                        parse_methods(out.methods);
                    }
                    else if (key == "Addresses")
                    {
                        parse_addresses(out.addresses);
                    }
                    else
                    {
                        skip_value();
                    }
                    ws();
                    const char c = peek();
                    if (c == ',')
                    {
                        ++i_;
                        continue;
                    }
                    if (c == '}')
                    {
                        ++i_;
                        break;
                    }
                    throw std::runtime_error("json: expected , or } in root");
                }
                return out;
            }

        private:
            const std::string & s_;
            std::size_t i_ = 0;

            char peek() const
            {
                return i_ < s_.size() ? s_[i_] : '\0';
            }

            void ws()
            {
                while (i_ < s_.size())
                {
                    const char c = s_[i_];
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                    {
                        ++i_;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            void expect(char c)
            {
                if (peek() != c)
                {
                    throw std::runtime_error(std::string("json: expected '") + c + "'");
                }
                ++i_;
            }

            static void encode_utf8(uint32_t cp, std::string & out)
            {
                if (cp < 0x80)
                {
                    out.push_back(static_cast<char>(cp));
                }
                else if (cp < 0x800)
                {
                    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
                else if (cp < 0x10000)
                {
                    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
                else
                {
                    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
            }

            uint32_t parse_hex4()
            {
                uint32_t v = 0;
                for (int k = 0; k < 4; ++k)
                {
                    const char c = s_[i_++];
                    v <<= 4;
                    if (c >= '0' && c <= '9')
                    {
                        v |= static_cast<uint32_t>(c - '0');
                    }
                    else if (c >= 'a' && c <= 'f')
                    {
                        v |= static_cast<uint32_t>(c - 'a' + 10);
                    }
                    else if (c >= 'A' && c <= 'F')
                    {
                        v |= static_cast<uint32_t>(c - 'A' + 10);
                    }
                }
                return v;
            }

            std::string parse_string()
            {
                expect('"');
                std::string out{};
                while (i_ < s_.size())
                {
                    const char c = s_[i_++];
                    if (c == '"')
                    {
                        return out;
                    }
                    if (c == '\\')
                    {
                        const char e = s_[i_++];
                        switch (e)
                        {
                        case '"': out.push_back('"'); break;
                        case '\\': out.push_back('\\'); break;
                        case '/': out.push_back('/'); break;
                        case 'b': out.push_back('\b'); break;
                        case 'f': out.push_back('\f'); break;
                        case 'n': out.push_back('\n'); break;
                        case 'r': out.push_back('\r'); break;
                        case 't': out.push_back('\t'); break;
                        case 'u':
                        {
                            uint32_t cp = parse_hex4();
                            if (cp >= 0xD800 && cp <= 0xDBFF && i_ + 1 < s_.size()
                                && s_[i_] == '\\' && s_[i_ + 1] == 'u')
                            {
                                i_ += 2;
                                const uint32_t lo = parse_hex4();
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            }
                            encode_utf8(cp, out);
                            break;
                        }
                        default: out.push_back(e); break;
                        }
                    }
                    else
                    {
                        out.push_back(c);
                    }
                }
                throw std::runtime_error("json: unterminated string");
            }

            uint64_t parse_uint()
            {
                if (peek() == '-')
                {
                    ++i_;
                }
                uint64_t v = 0;
                while (i_ < s_.size())
                {
                    const char c = s_[i_];
                    if (c < '0' || c > '9')
                    {
                        break;
                    }
                    v = v * 10 + static_cast<uint64_t>(c - '0');
                    ++i_;
                }
                return v;
            }

            void skip_number()
            {
                while (i_ < s_.size())
                {
                    const char c = s_[i_];
                    if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.'
                        || c == 'e' || c == 'E')
                    {
                        ++i_;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            void skip_literal()
            {
                while (i_ < s_.size())
                {
                    const char c = s_[i_];
                    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
                    {
                        ++i_;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            void skip_value()
            {
                ws();
                const char c = peek();
                if (c == '"')
                {
                    parse_string();
                }
                else if (c == '{')
                {
                    skip_object();
                }
                else if (c == '[')
                {
                    skip_array();
                }
                else if (c == 't' || c == 'f' || c == 'n')
                {
                    skip_literal();
                }
                else
                {
                    skip_number();
                }
            }

            void skip_object()
            {
                expect('{');
                ws();
                if (peek() == '}')
                {
                    ++i_;
                    return;
                }
                while (true)
                {
                    ws();
                    parse_string();
                    ws();
                    expect(':');
                    skip_value();
                    ws();
                    const char c = peek();
                    if (c == ',')
                    {
                        ++i_;
                        continue;
                    }
                    if (c == '}')
                    {
                        ++i_;
                        break;
                    }
                    throw std::runtime_error("json: expected , or } in object");
                }
            }

            void skip_array()
            {
                expect('[');
                ws();
                if (peek() == ']')
                {
                    ++i_;
                    return;
                }
                while (true)
                {
                    skip_value();
                    ws();
                    const char c = peek();
                    if (c == ',')
                    {
                        ++i_;
                        continue;
                    }
                    if (c == ']')
                    {
                        ++i_;
                        break;
                    }
                    throw std::runtime_error("json: expected , or ] in array");
                }
            }

            void parse_addresses(std::vector<uint64_t> & out)
            {
                expect('[');
                ws();
                if (peek() == ']')
                {
                    ++i_;
                    return;
                }
                while (true)
                {
                    ws();
                    out.push_back(parse_uint());
                    ws();
                    const char c = peek();
                    if (c == ',')
                    {
                        ++i_;
                        continue;
                    }
                    if (c == ']')
                    {
                        ++i_;
                        break;
                    }
                    throw std::runtime_error("json: expected , or ] in addresses");
                }
            }

            void parse_methods(std::vector<script_method> & out)
            {
                expect('[');
                ws();
                if (peek() == ']')
                {
                    ++i_;
                    return;
                }
                while (true)
                {
                    ws();
                    out.push_back(parse_method_obj());
                    ws();
                    const char c = peek();
                    if (c == ',')
                    {
                        ++i_;
                        continue;
                    }
                    if (c == ']')
                    {
                        ++i_;
                        break;
                    }
                    throw std::runtime_error("json: expected , or ] in methods");
                }
            }

            script_method parse_method_obj()
            {
                script_method m{0, {}, false, {}};
                expect('{');
                ws();
                if (peek() == '}')
                {
                    ++i_;
                    return m;
                }
                while (true)
                {
                    ws();
                    const std::string key = parse_string();
                    ws();
                    expect(':');
                    ws();
                    if (key == "Address")
                    {
                        m.address = parse_uint();
                    }
                    else if (key == "Name")
                    {
                        m.name = parse_string();
                    }
                    else if (key == "Signature")
                    {
                        if (peek() == '"')
                        {
                            m.sig = parse_string();
                            m.has_sig = true;
                        }
                        else
                        {
                            skip_value();
                        }
                    }
                    else
                    {
                        skip_value();
                    }
                    ws();
                    const char c = peek();
                    if (c == ',')
                    {
                        ++i_;
                        continue;
                    }
                    if (c == '}')
                    {
                        ++i_;
                        break;
                    }
                    throw std::runtime_error("json: expected , or } in method");
                }
                return m;
            }
        };
    }

    script parse_script_json(const std::string & text)
    {
        parser p(text);
        return p.parse_root();
    }
}
