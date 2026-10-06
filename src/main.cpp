#include "audit.h"
#include <algorithm>
#include <cstdio>
#include <exception>
#include <limits>

namespace {
bool output(const std::string& text, DWORD stream) {
    const HANDLE handle = GetStdHandle(stream);
    if (handle == INVALID_HANDLE_VALUE || handle == nullptr) return false;
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode)) {
        if (text.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) return false;
        const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (size <= 0) return false;
        std::wstring wide(static_cast<size_t>(size), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), wide.data(), size) == 0) return false;
        size_t offset = 0;
        while (offset < wide.size()) {
            const DWORD chunk = static_cast<DWORD>((std::min)(wide.size() - offset, size_t{8192}));
            DWORD written = 0;
            if (!WriteConsoleW(handle, wide.data() + offset, chunk, &written, nullptr) || written == 0) return false;
            offset += written;
        }
    } else {
        size_t offset = 0;
        while (offset < text.size()) {
            const DWORD chunk = static_cast<DWORD>((std::min)(text.size() - offset, size_t{8192}));
            DWORD written = 0;
            if (!WriteFile(handle, text.data() + offset, chunk, &written, nullptr) || written == 0) return false;
            offset += written;
        }
    }
    return true;
}
}
int wmain(int argc, wchar_t* argv[]) {
    try {
        std::vector<std::wstring> args;
        for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
        const auto mode = msa::parse(args);
        if (mode == msa::Mode::invalid) {
            output("Invalid arguments. Use --help.\n", STD_ERROR_HANDLE);
            return 2;
        }
        std::string text;
        if (mode == msa::Mode::help) text = "Usage: modern-standby-auditor [--json | --help | --version]\nRead-only Windows sleep capability audit. No network or external commands.\nExit codes: 0=completed (including unsupported/unavailable evidence), 1=runtime/output failure, 2=invalid arguments.\n";
        else if (mode == msa::Mode::version) text = "modern-standby-auditor 1.0.0\n";
        else {
            const auto report = msa::collect();
            text = mode == msa::Mode::json ? msa::json(report) : msa::human(report);
        }
        return output(text, STD_OUTPUT_HANDLE) ? 0 : 1;
    } catch (const std::exception&) {
        output("Audit failed due to a runtime error.\n", STD_ERROR_HANDLE);
        return 1;
    }
}
