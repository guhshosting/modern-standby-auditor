#include "audit.h"
#include <algorithm>
#include <cstdio>
#include <iostream>
#include <stdexcept>

namespace {
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
const msa::Evidence& find(const std::vector<msa::Evidence>& items, const char* name) {
    const auto found = std::find_if(items.begin(), items.end(), [name](const msa::Evidence& item) { return item.name == name; });
    if (found == items.end()) throw std::runtime_error("Missing evidence field");
    return *found;
}
}
int main() {
    try {
        SYSTEM_POWER_CAPABILITIES c{};
        auto caps = msa::decode_capabilities(c, true);
        check(find(caps, "s0_low_power_idle").status == msa::Status::unsupported, "No Modern Standby platform");
        check(find(caps, "standby_network_connectivity").status == msa::Status::not_applicable, "No standby networking on non-AoAc platform");
        c.AoAc = 1; c.SystemS3 = 1; c.SystemS4 = 1; c.HiberFileType = 200;
        caps = msa::decode_capabilities(c, true);
        check(find(caps, "s0_low_power_idle").status == msa::Status::supported, "Modern Standby platform");
        check(find(caps, "s3").status == msa::Status::supported, "Do not invent mutually exclusive states");
        check(find(caps, "standby_network_connectivity").status == msa::Status::unsupported, "Connectivity capability absent");
        check(find(caps, "hiberfile_type_raw").value == "200", "Future hiberfile types preserved");
        caps = msa::decode_capabilities(c, false);
        check(find(caps, "standby_network_connectivity").status == msa::Status::unavailable, "Version-dependent field unavailable");
        c.AoAcConnectivitySupported = 1;
        check(find(msa::decode_capabilities(c, true), "standby_network_connectivity").status == msa::Status::supported, "Connectivity capability present");
        check(msa::power_state(99) == "unknown(99)", "Unknown power state preservation");
        check(msa::error_status(ERROR_ACCESS_DENIED) == msa::Status::access_denied, "Access denied distinction");
        check(msa::error_status(ERROR_NOT_SUPPORTED) == msa::Status::unavailable, "API failure is not a false capability");
        SYSTEM_POWER_STATUS s{};
        s.ACLineStatus = 1; s.BatteryFlag = 128; s.BatteryLifePercent = 255; s.BatteryLifeTime = MAXDWORD;
        auto battery = msa::decode_battery(s);
        check(find(battery, "battery_presence").value == "absent", "No battery");
        check(find(battery, "battery_percent").status == msa::Status::not_applicable, "No battery charge not applicable");
        check(find(battery, "ac_line").value == "online", "AC online");
        s.BatteryFlag = 255; s.ACLineStatus = 255;
        battery = msa::decode_battery(s);
        check(find(battery, "battery_presence").status == msa::Status::unavailable, "Unknown flags do not imply absent");
        check(find(battery, "ac_line").status == msa::Status::unavailable, "Unknown AC");
        s.BatteryFlag = 72; s.ACLineStatus = 0; s.BatteryLifePercent = 42; s.BatteryLifeTime = 300;
        battery = msa::decode_battery(s);
        check(find(battery, "battery_flags_raw").value == "72", "Unknown/new flags preserved");
        check(find(battery, "battery_percent").value == "42", "Battery percent");
        check(find(battery, "battery_life_seconds").value == "300", "Battery life");
        check(find(battery, "ac_line").value == "offline", "AC offline");
        check(msa::quote(std::string("\"\\\n\t") + char{1}) == "\"\\\"\\\\\\n\\t\\u0001\"", "JSON escaping");
        msa::Report r;
        for (auto state : {msa::Status::supported, msa::Status::unsupported, msa::Status::unavailable, msa::Status::access_denied, msa::Status::not_applicable})
            r.capabilities.push_back({msa::status_name(state), state, "", "test", 0});
        const auto output = msa::json(r);
        check(output == msa::json(r), "Deterministic JSON");
        check(output.find("\"value\":null") != std::string::npos, "Unknown JSON value is null");
        for (const auto& field : r.capabilities) check(output.find(msa::quote(msa::status_name(field.status))) != std::string::npos, "JSON status preservation");
        check(msa::parse({}) == msa::Mode::audit, "Default audit");
        check(msa::parse({L"--json"}) == msa::Mode::json, "JSON option");
        check(msa::parse({L"--json", L"--json"}) == msa::Mode::invalid, "Duplicate arguments");
        check(msa::parse({L"--history"}) == msa::Mode::invalid, "Unknown arguments");
        std::cout << "All unit checks passed\n";
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "%s\n", e.what()); return 1; }
    catch (...) { std::fputs("Unexpected test failure\n", stderr); return 1; }
}
