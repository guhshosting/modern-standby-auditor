#include "audit.h"
#include <powrprof.h>
#include <array>
#include <sstream>
#include <iomanip>
#include <utility>

namespace msa {
const char* status_name(Status status) {
    switch (status) {
    case Status::supported: return "supported";
    case Status::unsupported: return "unsupported";
    case Status::access_denied: return "access_denied";
    case Status::not_applicable: return "not_applicable";
    default: return "unavailable";
    }
}
Status error_status(DWORD error) { return error == ERROR_ACCESS_DENIED ? Status::access_denied : Status::unavailable; }
std::string power_state(unsigned int state) {
    constexpr std::array<const char*, 7> names{{"unspecified", "S0 (working)", "S1", "S2", "S3", "S4 (hibernate)", "S5 (shutdown)"}};
    return state < names.size() ? names[state] : "unknown(" + std::to_string(state) + ")";
}
std::string quote(const std::string& text) {
    std::ostringstream out;
    out << '"';
    for (const unsigned char c : text) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned int>(c) << std::dec;
            else out << static_cast<char>(c);
        }
    }
    out << '"';
    return out.str();
}
static Evidence flag(const char* name, BOOLEAN value, const char* explanation) {
    return {name, value ? Status::supported : Status::unsupported, value ? "true" : "false", explanation, 0};
}
std::vector<Evidence> decode_capabilities(const SYSTEM_POWER_CAPABILITIES& c, bool connectivity_field) {
    std::vector<Evidence> result{
        flag("s0_low_power_idle", c.AoAc, "GetPwrCapabilities AoAc; capability does not establish current use."),
        flag("s1", c.SystemS1, "Windows-reported capability; this API does not provide a reason for absence."),
        flag("s2", c.SystemS2, "Windows-reported capability; this API does not provide a reason for absence."),
        flag("s3", c.SystemS3, "Windows-reported capability; this API does not provide a reason for absence."),
        flag("s4", c.SystemS4, "Hibernate capability; hiberfile availability is reported separately."),
        flag("s5", c.SystemS5, "Shutdown capability, not a sleep or Modern Standby state."),
        flag("hiberfile_present", c.HiberFilePresent, "Hiberfile presence alone does not establish full hibernation availability."),
        flag("wake_alarm_present", c.WakeAlarmPresent, "Platform wake-alarm capability, not an inventory of armed timers."),
        flag("system_battery_present", c.SystemBatteriesPresent, "Windows-reported system battery capability; absence is normal on desktops/servers.")};
    if (!c.AoAc) result.push_back({"standby_network_connectivity", Status::not_applicable, "", "S0 low-power idle is not reported.", 0});
    else if (!connectivity_field) result.push_back({"standby_network_connectivity", Status::unavailable, "", "OS version could not be established; version-dependent field was not interpreted.", 0});
    else result.push_back(flag("standby_network_connectivity", c.AoAcConnectivitySupported, "Windows 10+ AoAcConnectivitySupported metadata; does not establish current connectivity, policy, or a separate disconnected mode. No network test is performed."));
    result.push_back({"hiberfile_type_raw", Status::supported, std::to_string(c.HiberFileType), "Raw Windows field preserved; 0=none, 1=reduced, 2=full; future values remain numeric.", 0});
    return result;
}
std::vector<Evidence> decode_battery(const SYSTEM_POWER_STATUS& s) {
    std::vector<Evidence> result;
    result.push_back({"ac_line", s.ACLineStatus <= 1 ? Status::supported : Status::unavailable,
        s.ACLineStatus == 0 ? "offline" : s.ACLineStatus == 1 ? "online" : "unknown", "GetSystemPowerStatus snapshot; raw=" + std::to_string(s.ACLineStatus), 0});
    const bool known = s.BatteryFlag != 255;
    const bool absent = known && (s.BatteryFlag & 128U) != 0;
    result.push_back({"battery_flags_raw", known ? Status::supported : Status::unavailable, std::to_string(s.BatteryFlag), "Bitmask preserved: 1=high, 2=low, 4=critical, 8=charging, 128=no battery; 255=unknown.", 0});
    result.push_back({"battery_presence", !known ? Status::unavailable : absent ? Status::unsupported : Status::supported,
        !known ? "unknown" : absent ? "absent" : "present", "No battery is a normal platform result.", 0});
    result.push_back({"battery_percent", absent ? Status::not_applicable : s.BatteryLifePercent <= 100 ? Status::supported : Status::unavailable,
        !absent && s.BatteryLifePercent <= 100 ? std::to_string(s.BatteryLifePercent) : "", "Current charge snapshot; 255 means unknown.", 0});
    result.push_back({"battery_life_seconds", absent ? Status::not_applicable : s.BatteryLifeTime != MAXDWORD ? Status::supported : Status::unavailable,
        !absent && s.BatteryLifeTime != MAXDWORD ? std::to_string(s.BatteryLifeTime) : "", "OS estimate; unknown is not zero.", 0});
    result.push_back({"battery_saver", s.SystemStatusFlag <= 1 ? Status::supported : Status::unavailable,
        s.SystemStatusFlag <= 1 ? std::to_string(s.SystemStatusFlag) : "", "0=off, 1=on; Windows 10+ snapshot.", 0});
    return result;
}
static Evidence registry_text(const wchar_t* key, const char* name) {
    std::array<wchar_t, 256> buffer{};
    DWORD bytes = static_cast<DWORD>(sizeof(buffer));
    const LSTATUS error = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", key,
        RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, buffer.data(), &bytes);
    if (error != ERROR_SUCCESS) return {name, error_status(static_cast<DWORD>(error)), "", "Read-only Windows version registry metadata.", static_cast<DWORD>(error)};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data(), -1, nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {name, Status::unavailable, "", "Version metadata could not be converted to UTF-8.", GetLastError()};
    std::string text(static_cast<size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data(), -1, text.data(), length, nullptr, nullptr) == 0)
        return {name, Status::unavailable, "", "Version metadata conversion failed.", GetLastError()};
    text.pop_back();
    return {name, Status::supported, text, "Read-only Windows version registry metadata; product branding can be stale after OS upgrades.", 0};
}
static std::string architecture(WORD a) {
    switch (a) {
    case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
    case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
    case PROCESSOR_ARCHITECTURE_ARM64: return "arm64";
    case PROCESSOR_ARCHITECTURE_ARM: return "arm";
    default: return "unknown(" + std::to_string(a) + ")";
    }
}
Report collect() {
    Report r;
    r.context = {registry_text(L"ProductName", "windows_product"), registry_text(L"DisplayVersion", "windows_release"), registry_text(L"CurrentBuildNumber", "windows_build")};
    DWORD major = 0, minor = 0, revision = 0;
    for (auto pair : {std::pair<const wchar_t*, DWORD*>{L"CurrentMajorVersionNumber", &major}, {L"CurrentMinorVersionNumber", &minor}, {L"UBR", &revision}}) {
        DWORD size = sizeof(DWORD);
        const LSTATUS err = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", pair.first,
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, pair.second, &size);
        const char* name = pair.second == &major ? "windows_major" : pair.second == &minor ? "windows_minor" : "windows_revision";
        r.context.push_back({name, err == ERROR_SUCCESS ? Status::supported : error_status(static_cast<DWORD>(err)),
            err == ERROR_SUCCESS ? std::to_string(*pair.second) : "", "Read-only Windows version registry metadata.", static_cast<DWORD>(err)});
    }
    SYSTEM_INFO native{}, process{};
    GetNativeSystemInfo(&native);
    GetSystemInfo(&process);
    r.context.push_back({"native_architecture", Status::supported, architecture(native.wProcessorArchitecture), "GetNativeSystemInfo.", 0});
    r.context.push_back({"process_architecture", Status::supported, architecture(process.wProcessorArchitecture), "GetSystemInfo for this process.", 0});
    SYSTEM_POWER_CAPABILITIES c{};
    if (GetPwrCapabilities(&c)) {
        r.capabilities = decode_capabilities(c, major >= 10);
        for (auto pair : {std::pair<const char*, SYSTEM_POWER_STATE>{"ac_online_wake", c.AcOnLineWake}, {"lid_wake", c.SoftLidWake}, {"rtc_wake", c.RtcWake}, {"minimum_device_wake_state", c.MinDeviceWakeState}, {"default_low_latency_wake", c.DefaultLowLatencyWake}})
            r.wake.push_back({pair.first, pair.second == PowerSystemUnspecified ? Status::unavailable : Status::supported,
                power_state(static_cast<unsigned int>(pair.second)), "GetPwrCapabilities system-level wake-state metadata; not an armed device/timer inventory or a last wake source.", 0});
        r.findings.push_back(c.AoAc ? "Windows reports S0 low-power idle capability. This does not establish that Modern Standby is currently in use." : "Windows does not report S0 low-power idle capability. This is a valid platform result.");
    } else {
        const DWORD error = GetLastError();
        for (const auto* name : {"s0_low_power_idle", "s1", "s2", "s3", "s4", "s5", "hiberfile_present", "wake_alarm_present", "system_battery_present", "standby_network_connectivity", "hiberfile_type_raw"})
            r.capabilities.push_back({name, error_status(error), "", "GetPwrCapabilities failed; absence of data is not unsupported capability.", error});
        r.wake.push_back({"wake_state_metadata", error_status(error), "", "GetPwrCapabilities failed.", error});
    }
    SYSTEM_POWER_STATUS s{};
    if (GetSystemPowerStatus(&s)) r.snapshot = decode_battery(s);
    else {
        const DWORD error = GetLastError();
        for (const auto* name : {"ac_line", "battery_flags_raw", "battery_presence", "battery_percent", "battery_life_seconds", "battery_saver"})
            r.snapshot.push_back({name, error_status(error), "", "GetSystemPowerStatus failed.", error});
    }
    r.history.push_back({"sleep_wake_history", Status::unavailable, "", "Event-log acquisition is not implemented. No channels are enabled or queried. No conclusion about past sleep/wake can be drawn.", 0});
    for (auto pair : {std::pair<const char*, const char*>{"last_wake_source", "No reliable public API collector is implemented for the last wake source."}, {"armed_wake_devices", "System wake-state metadata does not enumerate currently armed wake devices; no device collector is implemented."}, {"wake_timers", "No reliable supported public read-only timer inventory is implemented."}, {"active_power_requests", "No reliable supported public read-only power-request inventory is used; no powercfg scraping."}, {"current_standby_state", "Capability metadata does not expose current Modern Standby residency."}, {"standby_network_modes", "No separate connected/disconnected policy collector is implemented; connectivity capability alone cannot establish policy or mode."}})
        r.limitations.push_back({pair.first, Status::unavailable, "", pair.second, 0});
    r.findings.push_back("Unsupported means Windows reports a capability absent. Unavailable means no usable evidence was obtained; it does not mean false.");
    r.findings.push_back("No automatic fixes are proposed. Capabilities, snapshots, and history answer different questions.");
    return r;
}
static void json_evidence(std::ostringstream& out, const std::vector<Evidence>& items) {
    out << '[';
    bool first = true;
    for (const auto& item : items) {
        if (!first) out << ',';
        first = false;
        out << "{\"name\":" << quote(item.name) << ",\"status\":" << quote(status_name(item.status)) << ",\"value\":"
            << (item.value.empty() ? "null" : quote(item.value)) << ",\"explanation\":" << quote(item.explanation) << ",\"win32_error\":" << item.error << '}';
    }
    out << ']';
}
std::string json(const Report& r) {
    std::ostringstream out;
    out << "{\"schema_version\":1,\"application\":\"modern-standby-auditor\",\"version\":\"1.0.0\"";
    for (const auto& pair : {std::pair<const char*, const std::vector<Evidence>*>{"system_context", &r.context}, {"capabilities", &r.capabilities}, {"current_snapshot", &r.snapshot}, {"wake_metadata", &r.wake}, {"historical_evidence", &r.history}, {"limitations", &r.limitations}}) {
        out << ',' << quote(pair.first) << ':';
        json_evidence(out, *pair.second);
    }
    out << ",\"findings\":[";
    bool first = true;
    for (const auto& finding : r.findings) { if (!first) out << ','; first = false; out << quote(finding); }
    out << "]}\n";
    return out.str();
}
std::string human(const Report& r) {
    std::ostringstream out;
    out << "modern-standby-auditor 1.0.0\nRead-only local audit\n";
    for (const auto& pair : {std::pair<const char*, const std::vector<Evidence>*>{"System context", &r.context}, {"Capabilities", &r.capabilities}, {"Current snapshot", &r.snapshot}, {"Wake capability metadata", &r.wake}, {"Historical evidence", &r.history}, {"Limitations", &r.limitations}}) {
        out << '\n' << pair.first << "\n";
        for (const auto& item : *pair.second) {
            out << "  " << item.name << ": " << status_name(item.status);
            if (!item.value.empty()) out << " (" << item.value << ')';
            if (item.error) out << " [Win32 error " << item.error << ']';
            out << "\n    " << item.explanation << '\n';
        }
    }
    out << "\nFindings / interpretation\n";
    for (const auto& finding : r.findings) out << "  " << finding << '\n';
    return out.str();
}
Mode parse(const std::vector<std::wstring>& args) {
    if (args.empty()) return Mode::audit;
    if (args.size() != 1) return Mode::invalid;
    if (args[0] == L"--json") return Mode::json;
    if (args[0] == L"--help") return Mode::help;
    if (args[0] == L"--version") return Mode::version;
    return Mode::invalid;
}
}
