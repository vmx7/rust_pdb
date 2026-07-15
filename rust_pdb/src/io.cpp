#include "io.hpp"

#include <fstream>
#include <ios>
#include <stdexcept>

namespace il2pdb
{
    std::vector<uint8_t> read_bytes(std::string_view path)
    {
        std::ifstream f(std::string(path), std::ios::binary);
        if (!f)
        {
            throw std::runtime_error("cannot open " + std::string(path));
        }
        f.seekg(0, std::ios::end);
        const std::streamoff len = f.tellg();
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> out(static_cast<std::size_t>(len));
        f.read(reinterpret_cast<char*>(out.data()), len);
        return out;
    }

    std::string read_text(std::string_view path)
    {
        std::ifstream f(std::string(path), std::ios::binary);
        if (!f)
        {
            throw std::runtime_error("cannot open " + std::string(path));
        }
        f.seekg(0, std::ios::end);
        const std::streamoff len = f.tellg();
        f.seekg(0, std::ios::beg);
        std::string out(static_cast<std::size_t>(len), '\0');
        f.read(out.data(), len);
        return out;
    }

    void write_bytes(std::string_view path, std::span<const uint8_t> data)
    {
        std::ofstream f(std::string(path), std::ios::binary);
        if (!f)
        {
            throw std::runtime_error("cannot write " + std::string(path));
        }
        f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    }
}
