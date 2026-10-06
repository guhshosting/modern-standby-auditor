#ifndef MSA_AUDIT_H
#define MSA_AUDIT_H
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace msa {
enum class Status : std::uint8_t { supported, unsupported, unavailable, access_denied, not_applicable };
struct Evidence {
    std::string name;
    Status status = Status::unavailable;
    std::string value;
    std::string explanation;
    DWORD error = 0;
};
struct Report {
    std::vector<Evidence> context, capabilities, snapshot, wake, history, limitations;
    std::vector<std::string> findings;
};
const char* status_name(Status status);
Status error_status(DWORD error);
std::string power_state(unsigned int state);
std::string quote(const std::string& text);
std::vector<Evidence> decode_capabilities(const SYSTEM_POWER_CAPABILITIES& caps, bool connectivity_field);
std::vector<Evidence> decode_battery(const SYSTEM_POWER_STATUS& status);
Report collect();
std::string json(const Report& report);
std::string human(const Report& report);
enum class Mode : std::uint8_t { audit, json, help, version, invalid };
Mode parse(const std::vector<std::wstring>& args);
}
#endif
