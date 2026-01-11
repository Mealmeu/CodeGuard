#include <iostream>
#include <filesystem>
#include <string>

#include "Scanner.h"
#include "Util.h"

static void PrintBanner()
{
    std::cout << "CodeGuardCLI" << std::endl;
    std::cout << "Enter project root path:" << std::endl;
    std::cout << ">" << std::endl;
}

static std::filesystem::path ReadRootPath()
{
    std::string line;
    std::getline(std::cin, line);
    line = codeguard::Trim(line);
    line = codeguard::StripQuotes(line);

    std::wstring w = codeguard::ToWideFromConsoleInput(line);
    if (!w.empty())
    {
        return std::filesystem::path(w);
    }

    return std::filesystem::path(line);
}

static void PrintFinding(const codeguard::Finding& f)
{
    std::cout
        << f.file_path.u8string()
        << ":" << f.line
        << ":" << f.column
        << " [" << f.rule_id << "] "
        << f.message
        << std::endl;

    if (!f.line_text.empty())
    {
        std::cout << "  " << f.line_text << std::endl;
        std::cout << "  ";
        if (f.column > 1)
        {
            for (size_t i = 1; i < f.column; i++)
            {
                std::cout << ' ';
            }
        }
        std::cout << "^" << std::endl;
    }
}

int main()
{
    PrintBanner();

    const auto root = ReadRootPath();

    std::error_code ec;
    if (root.empty() || !std::filesystem::exists(root, ec) || !std::filesystem::is_directory(root, ec))
    {
        std::cout << "Invalid directory." << std::endl;
        return 2;
    }

    codeguard::Scanner scanner;
    scanner.SetRoot(root);

    codeguard::ScanOptions opt;
    opt.check_banned_functions = true;
    opt.check_scanf_unsafe_percent_s = true;
    scanner.SetOptions(opt);

    const auto result = scanner.Run();

    for (const auto& f : result.findings)
    {
        PrintFinding(f);
    }

    std::cout << std::endl;
    std::cout << "Files seen: " << result.stats.files_seen << std::endl;
    std::cout << "Files scanned: " << result.stats.files_scanned << std::endl;
    std::cout << "Bytes scanned: " << result.stats.bytes_scanned << std::endl;
    std::cout << "Findings: " << result.stats.findings << std::endl;

    return (result.stats.findings > 0) ? 1 : 0;
}
