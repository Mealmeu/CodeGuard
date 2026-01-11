#include "Scanner.h"

#include "Util.h"

#include <iostream>
#include <system_error>
#include <cctype>

namespace codeguard
{
Scanner::Scanner()
{
    root_path.clear();
    options = { true, true };
    InitDefaultRules();
}

void Scanner::SetRoot(const std::filesystem::path& root)
{
    root_path = root;
}

void Scanner::SetOptions(const ScanOptions& opt)
{
    options = opt;
}

void Scanner::InitDefaultRules()
{
    banned_functions = {
        "gets",
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "system",
        "popen"
    };
}

static void AddFinding(
    ScanResult& out,
    const std::filesystem::path& file_path,
    size_t line,
    size_t col,
    const std::string& rule_id,
    Severity sev,
    const std::string& msg,
    std::string_view line_text
)
{
    Finding f;
    f.file_path = file_path;
    f.line = line;
    f.column = col;
    f.rule_id = rule_id;
    f.severity = sev;
    f.message = msg;
    f.line_text = std::string(line_text);
    out.findings.push_back(std::move(f));
    out.stats.findings++;
}

static size_t SkipSpaces(const std::string& s, size_t i)
{
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n'))
    {
        i++;
    }
    return i;
}

static bool IsWordBoundaryBefore(const std::string& s, size_t i)
{
    if (i == 0)
    {
        return true;
    }
    const unsigned char c = static_cast<unsigned char>(s[i - 1]);
    return !IsIdentChar(c);
}

static bool IsWordBoundaryAfter(const std::string& s, size_t i)
{
    if (i >= s.size())
    {
        return true;
    }
    const unsigned char c = static_cast<unsigned char>(s[i]);
    return !IsIdentChar(c);
}

static bool LooksLikeCallAt(const std::string& sanitized, size_t name_pos, size_t name_len)
{
    if (!IsWordBoundaryBefore(sanitized, name_pos))
    {
        return false;
    }
    if (!IsWordBoundaryAfter(sanitized, name_pos + name_len))
    {
        return false;
    }

    size_t i = name_pos + name_len;
    i = SkipSpaces(sanitized, i);
    if (i >= sanitized.size() || sanitized[i] != '(')
    {
        return false;
    }

    return true;
}

static std::string ReadStringLiteralAt(const std::string& raw, size_t& i)
{
    if (i >= raw.size() || raw[i] != '"')
    {
        return std::string();
    }

    i++;
    std::string out;
    out.reserve(128);

    while (i < raw.size())
    {
        const char c = raw[i];
        if (c == '\\')
        {
            if (i + 1 < raw.size())
            {
                out.push_back('\\');
                out.push_back(raw[i + 1]);
                i += 2;
                continue;
            }
            out.push_back('\\');
            i++;
            continue;
        }

        if (c == '"')
        {
            i++;
            break;
        }

        if (c == '\n')
        {
            break;
        }

        out.push_back(c);
        i++;
    }

    return out;
}

ScanResult Scanner::Run()
{
    ScanResult out;
    out.stats = { 0, 0, 0, 0 };

    std::error_code ec;
    if (root_path.empty() || !std::filesystem::exists(root_path, ec) || !std::filesystem::is_directory(root_path, ec))
    {
        return out;
    }

    std::filesystem::recursive_directory_iterator it(
        root_path,
        std::filesystem::directory_options::skip_permission_denied,
        ec
    );

    const auto end = std::filesystem::recursive_directory_iterator();

    for (; it != end; it.increment(ec))
    {
        if (ec)
        {
            ec.clear();
            continue;
        }

        const auto& entry = *it;
        out.stats.files_seen++;

        if (!entry.is_regular_file(ec))
        {
            continue;
        }

        const auto p = entry.path();
        if (!IsLikelyTextFileExtension(p))
        {
            continue;
        }

        ScanFile(p, out);
    }

    return out;
}

void Scanner::ScanFile(const std::filesystem::path& p, ScanResult& out)
{
    std::string raw;
    std::string err;
    if (!ReadFileAll(p, raw, err))
    {
        return;
    }

    out.stats.files_scanned++;
    out.stats.bytes_scanned += static_cast<uint64_t>(raw.size());

    std::string sanitized = SanitizeKeepLayout(raw);

    if (options.check_banned_functions)
    {
        FindBannedFunctionCalls(p, raw, sanitized, out);
    }

    if (options.check_scanf_unsafe_percent_s)
    {
        FindScanfUnsafePercentS(p, raw, sanitized, out);
    }
}

void Scanner::FindBannedFunctionCalls(
    const std::filesystem::path& file_path,
    const std::string& raw,
    const std::string& sanitized,
    ScanResult& out
)
{
    (void)raw;

    const auto idx = LineIndex::Build(raw);

    for (const auto& name : banned_functions)
    {
        const size_t name_len = name.size();
        size_t pos = 0;
        while (pos < sanitized.size())
        {
            const size_t found = sanitized.find(name, pos);
            if (found == std::string::npos)
            {
                break;
            }

            if (LooksLikeCallAt(sanitized, found, name_len))
            {
                const size_t line = idx.LineFromIndex(found);
                const size_t col = idx.ColFromIndex(found, line);

                const std::string rule_id = "CG0001";
                const Severity sev = (name == "gets" || name == "strcpy" || name == "strcat" || name == "sprintf" || name == "vsprintf") ? Severity::High : Severity::Medium;
                const std::string msg = "banned function call detected: " + name;

                AddFinding(out, file_path, line, col, rule_id, sev, msg, idx.LineText(raw, line));
            }

            pos = found + name_len;
        }
    }
}

bool Scanner::HasUnsafePercentS(const std::string& fmt)
{
    for (size_t i = 0; i < fmt.size(); i++)
    {
        if (fmt[i] != '%')
        {
            continue;
        }

        if (i + 1 < fmt.size() && fmt[i + 1] == '%')
        {
            i++;
            continue;
        }

        i++;

        bool suppressed = false;
        if (i < fmt.size() && fmt[i] == '*')
        {
            suppressed = true;
            i++;
        }

        bool hasWidth = false;
        while (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i])))
        {
            hasWidth = true;
            i++;
        }

        if (i < fmt.size() && (fmt[i] == 'h' || fmt[i] == 'l' || fmt[i] == 'j' || fmt[i] == 'z' || fmt[i] == 't' || fmt[i] == 'L'))
        {
            const char first = fmt[i];
            i++;
            if (i < fmt.size() && (fmt[i] == first) && (first == 'h' || first == 'l'))
            {
                i++;
            }
        }

        if (i >= fmt.size())
        {
            break;
        }

        const char conv = fmt[i];
        if (conv == 's')
        {
            if (!suppressed && !hasWidth)
            {
                return true;
            }
        }
    }

    return false;
}

void Scanner::FindScanfUnsafePercentS(
    const std::filesystem::path& file_path,
    const std::string& raw,
    const std::string& sanitized,
    ScanResult& out
)
{
    const auto idx = LineIndex::Build(raw);

    const std::string name = "scanf";
    const size_t name_len = name.size();

    size_t pos = 0;
    while (pos < sanitized.size())
    {
        const size_t found = sanitized.find(name, pos);
        if (found == std::string::npos)
        {
            break;
        }

        if (!LooksLikeCallAt(sanitized, found, name_len))
        {
            pos = found + name_len;
            continue;
        }

        size_t i = found + name_len;
        i = SkipSpaces(raw, i);
        if (i >= raw.size() || raw[i] != '(')
        {
            pos = found + name_len;
            continue;
        }

        i++;
        i = SkipSpaces(raw, i);

        if (i >= raw.size() || raw[i] != '"')
        {
            pos = found + name_len;
            continue;
        }

        size_t fmt_start = i;
        std::string fmt = ReadStringLiteralAt(raw, i);
        if (fmt.empty())
        {
            pos = found + name_len;
            continue;
        }

        if (HasUnsafePercentS(fmt))
        {
            const size_t line = idx.LineFromIndex(fmt_start);
            const size_t col = idx.ColFromIndex(fmt_start, line);

            const std::string rule_id = "CG0002";
            const Severity sev = Severity::High;
            const std::string msg = "scanf format uses %s without width (potential overflow)";

            AddFinding(out, file_path, line, col, rule_id, sev, msg, idx.LineText(raw, line));
        }

        pos = found + name_len;
    }
}

std::string Scanner::SeverityToString(Severity s)
{
    switch (s)
    {
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MED";
        case Severity::High: return "HIGH";
        default: return "UNK";
    }
}
}
