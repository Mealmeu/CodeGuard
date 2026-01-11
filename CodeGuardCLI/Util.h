#pragma once

#include <string>
#include <vector>
#include <filesystem>

namespace codeguard
{
struct LineIndex
{
    std::vector<size_t> line_starts;

    static LineIndex Build(const std::string& text);

    size_t LineFromIndex(size_t index) const;
    size_t ColFromIndex(size_t index, size_t line) const;
    std::string_view LineText(const std::string& text, size_t line) const;
};

std::string Trim(const std::string& s);
std::string StripQuotes(const std::string& s);

std::wstring ToWideFromConsoleInput(const std::string& s);

bool IsLikelyTextFileExtension(const std::filesystem::path& p);

bool ReadFileAll(const std::filesystem::path& p, std::string& out, std::string& err);

std::string SanitizeKeepLayout(const std::string& input);

bool IsIdentChar(unsigned char c);
}
