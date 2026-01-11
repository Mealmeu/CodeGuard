#include "Util.h"

#include <windows.h>
#include <fstream>
#include <sstream>
#include <cctype>

namespace codeguard
{
LineIndex LineIndex::Build(const std::string& text)
{
    LineIndex idx;
    idx.line_starts.reserve(1024);
    idx.line_starts.push_back(0);
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] == '\n')
        {
            idx.line_starts.push_back(i + 1);
        }
    }
    return idx;
}

size_t LineIndex::LineFromIndex(size_t index) const
{
    if (line_starts.empty())
    {
        return 1;
    }

    size_t lo = 0;
    size_t hi = line_starts.size();
    while (lo + 1 < hi)
    {
        const size_t mid = lo + (hi - lo) / 2;
        if (line_starts[mid] <= index)
        {
            lo = mid;
        }
        else
        {
            hi = mid;
        }
    }
    return lo + 1;
}

size_t LineIndex::ColFromIndex(size_t index, size_t line) const
{
    if (line == 0 || line > line_starts.size())
    {
        return 1;
    }
    const size_t start = line_starts[line - 1];
    return (index >= start) ? (index - start + 1) : 1;
}

std::string_view LineIndex::LineText(const std::string& text, size_t line) const
{
    if (line == 0 || line > line_starts.size())
    {
        return std::string_view();
    }

    const size_t start = line_starts[line - 1];
    size_t end = text.find('\n', start);
    if (end == std::string::npos)
    {
        end = text.size();
    }
    if (end > start && text[end - 1] == '\r')
    {
        end--;
    }
    return std::string_view(text.data() + start, end - start);
}

static std::string LTrim(const std::string& s)
{
    size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
    {
        i++;
    }
    return s.substr(i);
}

static std::string RTrim(const std::string& s)
{
    if (s.empty())
    {
        return s;
    }
    size_t i = s.size();
    while (i > 0 && std::isspace(static_cast<unsigned char>(s[i - 1])))
    {
        i--;
    }
    return s.substr(0, i);
}

std::string Trim(const std::string& s)
{
    return RTrim(LTrim(s));
}

std::string StripQuotes(const std::string& s)
{
    if (s.size() >= 2)
    {
        const char a = s.front();
        const char b = s.back();
        if ((a == '"' && b == '"') || (a == '\'' && b == '\''))
        {
            return s.substr(1, s.size() - 2);
        }
    }
    return s;
}

std::wstring ToWideFromConsoleInput(const std::string& s)
{
    if (s.empty())
    {
        return std::wstring();
    }

    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (wlen <= 0)
    {
        wlen = MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
        if (wlen <= 0)
        {
            return std::wstring();
        }
        std::wstring out;
        out.resize(static_cast<size_t>(wlen));
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), out.data(), wlen);
        return out;
    }

    std::wstring out;
    out.resize(static_cast<size_t>(wlen));
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), static_cast<int>(s.size()), out.data(), wlen);
    return out;
}

bool IsLikelyTextFileExtension(const std::filesystem::path& p)
{
    const auto ext = p.extension().wstring();
    if (ext.empty())
    {
        return false;
    }

    const std::wstring e = [&]()
    {
        std::wstring t;
        t.reserve(ext.size());
        for (wchar_t c : ext)
        {
            t.push_back(static_cast<wchar_t>(towlower(c)));
        }
        return t;
    }();

    return e == L".c" || e == L".cc" || e == L".cpp" || e == L".cxx" || e == L".h" || e == L".hpp" || e == L".hh" || e == L".hxx" || e == L".inl";
}

bool ReadFileAll(const std::filesystem::path& p, std::string& out, std::string& err)
{
    out.clear();
    err.clear();

    std::error_code ec;
    const auto sz = std::filesystem::file_size(p, ec);
    if (!ec)
    {
        const uintmax_t maxBytes = 10ull * 1024ull * 1024ull;
        if (sz > maxBytes)
        {
            err = "file too large";
            return false;
        }
    }

    std::ifstream f(p, std::ios::binary);
    if (!f)
    {
        err = "failed to open file";
        return false;
    }

    f.seekg(0, std::ios::end);
    const std::streamoff len = f.tellg();
    if (len < 0)
    {
        err = "failed to determine file size";
        return false;
    }
    f.seekg(0, std::ios::beg);

    out.resize(static_cast<size_t>(len));
    if (len > 0)
    {
        f.read(out.data(), len);
        if (!f)
        {
            err = "failed to read file";
            return false;
        }
    }

    return true;
}

std::string SanitizeKeepLayout(const std::string& input)
{
    enum class State
    {
        Normal,
        LineComment,
        BlockComment,
        String,
        StringEscape,
        Char,
        CharEscape
    };

    State state = State::Normal;
    std::string out;
    out.resize(input.size());

    for (size_t i = 0; i < input.size(); i++)
    {
        const char c = input[i];
        const char n = (i + 1 < input.size()) ? input[i + 1] : '\0';

        if (state == State::Normal)
        {
            if (c == '/' && n == '/')
            {
                out[i] = ' ';
                out[i + 1] = ' ';
                i++;
                state = State::LineComment;
                continue;
            }
            if (c == '/' && n == '*')
            {
                out[i] = ' ';
                out[i + 1] = ' ';
                i++;
                state = State::BlockComment;
                continue;
            }
            if (c == '"')
            {
                out[i] = ' ';
                state = State::String;
                continue;
            }
            if (c == '\'')
            {
                out[i] = ' ';
                state = State::Char;
                continue;
            }

            out[i] = c;
            continue;
        }

        if (state == State::LineComment)
        {
            if (c == '\n')
            {
                out[i] = '\n';
                state = State::Normal;
            }
            else
            {
                out[i] = ' ';
            }
            continue;
        }

        if (state == State::BlockComment)
        {
            if (c == '*' && n == '/')
            {
                out[i] = ' ';
                out[i + 1] = ' ';
                i++;
                state = State::Normal;
            }
            else if (c == '\n')
            {
                out[i] = '\n';
            }
            else
            {
                out[i] = ' ';
            }
            continue;
        }

        if (state == State::String)
        {
            if (c == '\\')
            {
                out[i] = ' ';
                state = State::StringEscape;
            }
            else if (c == '"')
            {
                out[i] = ' ';
                state = State::Normal;
            }
            else if (c == '\n')
            {
                out[i] = '\n';
                state = State::Normal;
            }
            else
            {
                out[i] = ' ';
            }
            continue;
        }

        if (state == State::StringEscape)
        {
            if (c == '\n')
            {
                out[i] = '\n';
                state = State::Normal;
            }
            else
            {
                out[i] = ' ';
                state = State::String;
            }
            continue;
        }

        if (state == State::Char)
        {
            if (c == '\\')
            {
                out[i] = ' ';
                state = State::CharEscape;
            }
            else if (c == '\'')
            {
                out[i] = ' ';
                state = State::Normal;
            }
            else if (c == '\n')
            {
                out[i] = '\n';
                state = State::Normal;
            }
            else
            {
                out[i] = ' ';
            }
            continue;
        }

        if (state == State::CharEscape)
        {
            if (c == '\n')
            {
                out[i] = '\n';
                state = State::Normal;
            }
            else
            {
                out[i] = ' ';
                state = State::Char;
            }
            continue;
        }
    }

    return out;
}

bool IsIdentChar(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}
}
