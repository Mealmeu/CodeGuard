#pragma once

#include <string>
#include <vector>
#include <filesystem>

namespace codeguard
{
enum class Severity
{
    Low,
    Medium,
    High
};

struct Finding
{
    std::filesystem::path file_path;
    size_t line;
    size_t column;
    std::string rule_id;
    Severity severity;
    std::string message;
    std::string line_text;
};

struct ScanStats
{
    uint64_t files_seen;
    uint64_t files_scanned;
    uint64_t bytes_scanned;
    uint64_t findings;
};

struct ScanResult
{
    std::vector<Finding> findings;
    ScanStats stats;
};

struct ScanOptions
{
    bool check_banned_functions;
    bool check_scanf_unsafe_percent_s;
};

class Scanner final
{
public:
    Scanner();

    void SetRoot(const std::filesystem::path& root);
    void SetOptions(const ScanOptions& opt);

    ScanResult Run();

private:
    std::filesystem::path root_path;
    ScanOptions options;

    std::vector<std::string> banned_functions;

    void InitDefaultRules();

    void ScanFile(const std::filesystem::path& p, ScanResult& out);

    void FindBannedFunctionCalls(
        const std::filesystem::path& file_path,
        const std::string& raw,
        const std::string& sanitized,
        ScanResult& out
    );

    void FindScanfUnsafePercentS(
        const std::filesystem::path& file_path,
        const std::string& raw,
        const std::string& sanitized,
        ScanResult& out
    );

    static bool HasUnsafePercentS(const std::string& fmt);

    static std::string SeverityToString(Severity s);
};
}
