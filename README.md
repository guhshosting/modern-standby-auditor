# modern-standby-auditor

> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


A Windows command-line sleep capability auditor, version 1.0.0. C++17, MIT licensed, portable, and usable without administrator elevation.

Modern Standby is Windows S0 low-power idle. This tool reports the `AoAc` capability from `GetPwrCapabilities`, rather than guessing from device type. An absent capability is a valid result on desktops, servers, virtual machines, and older hardware. There is no health score or power optimizer.

## Use

```text
modern-standby-auditor
modern-standby-auditor --json
modern-standby-auditor --help
modern-standby-auditor --version
```

Only one option is accepted. Exit status 0 means the audit completed, including partial, unsupported, and unavailable results; 1 indicates runtime/output failure; 2 indicates invalid arguments. Output redirected to a file or pipe is UTF-8 without BOM; interactive Windows consoles receive Unicode through `WriteConsoleW`.

## What the evidence means

The report separates system context, capabilities, current snapshot, wake capability metadata, historical evidence, findings, and limitations.

* **Capability:** Windows reports S0 low-power idle, S1/S2/S3, S4, and S5 flags. S5 is shutdown, not sleep. Hiberfile presence/type is separate from S4 capability. This API does not explain *why* a state is absent or guarantee a future sleep transition will succeed.
* **Current snapshot:** AC status, battery flags, charge, OS remaining-life estimate, and battery-saver status come from `GetSystemPowerStatus`. No battery is normal. Measurements are sequential snapshots, not an atomic or continuous observation.
* **Wake metadata:** AC, lid, RTC, minimum device wake state, default low-latency wake state, and wake-alarm capability describe system-level capabilities. They do not identify armed devices, pending wake timers, or the last wake source.
* **History:** No event-log collector is included in 1.0.0. History is explicitly unavailable. Absence of evidence does not prove that no sleep/wake occurred. A historical wake event would not establish a persistent problem.

`AoAcConnectivitySupported` is decoded only when Windows 10+ version metadata is available. It describes standby networking capability, not observed network traffic, current connectivity, or a separate connected/disconnected policy. No separate disconnected-mode capability or policy is inferred. Windows behavior and policy differ by OS release. The auditor never generates network traffic to test this field.

No reliable public read-only inventory of active power requests is used. Last wake source, armed wake devices, wake timers, current standby residency, and separate standby network modes are explicitly marked unavailable. The program does not scrape `powercfg` or undocumented structures to fill these gaps.

## JSON contract

Schema version 1 has deterministic field ordering and no acquisition timestamps. Live values may change between runs. Evidence arrays contain objects with `name`, `status`, `value`, `explanation`, and `win32_error`. Values are strings or null; a boolean capability uses the strings `"true"` and `"false"`. Raw flag/type fields preserve future values. Consumers should key by `name`, allow additional fields, and use `status` before interpreting values.

```json
{"name":"s0_low_power_idle","status":"unsupported","value":"false","explanation":"GetPwrCapabilities AoAc; capability does not establish current use.","win32_error":0}
```

Statuses are `supported` (affirmative capability or successfully obtained observation), `unsupported` (Windows reports a capability absent), `unavailable` (unknown, collection failure, or no collector), `access_denied`, and `not_applicable`. Missing telemetry is never serialized as false. `win32_error` is numeric; zero can accompany an unavailable result when no API was attempted. Version/build comes from read-only Windows version registry metadata, including build revision; product branding can be stale after upgrades. Build number is more useful than product branding for Windows 10/11 identification.

## Safety and privacy

The application reads Windows power capabilities, power status, system architecture, and OS version registry values. It only writes its report to stdout/stderr. It never sleeps, hibernates, resumes, wakes, shuts down, reboots, keeps the system awake, creates/deletes power requests, or changes power plans, settings, wake devices/timers, registry values, services, tasks, firmware, policy, or diagnostic channels. It does not launch external processes or call shells, PowerShell, cmd, or powercfg. It has no telemetry, sockets, DNS, HTTP, connectivity probes, online lookups, or symbol downloads. No fixes that disable devices/services or alter power settings are proposed.

## Compatibility and build

Target: Windows 10, Windows 11, and supported Windows Server versions using these APIs. Modern Standby absence on Server is expected and graceful. Build with Visual Studio C++ tools, CMake 3.21+, and a Windows 10+ SDK. The runtime is linked statically; there are no third-party runtime dependencies. x64 is the development build; x86/ARM64 builds require their corresponding Visual Studio toolchains and separate qualification.

```text
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 -DMSA_ANALYZE=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cpack --config build/CPackConfig.cmake -C Release
```

Visual Studio 2022 users can select `Visual Studio 17 2022`. Project code uses `/W4 /WX /permissive-`; `MSA_ANALYZE=ON` runs MSVC `/analyze`. CTest includes capability decoding, non-Modern-Standby fixtures, all status distinctions, battery/AC/no-battery scenarios, future flag preservation, JSON escaping/determinism, CLI validation, and a source safety guard. See `VALIDATION.md` for actual host validation and physical qualification still required. Source guards and import inspection complement review; they do not establish a formal proof of safety.

For clang-tidy, use a separate Ninja build with `CMAKE_EXPORT_COMPILE_COMMANDS=ON` and `MSA_ANALYZE=OFF` in an MSVC developer environment, then run clang-tidy against all three project translation units. Cppcheck can run with `--enable=warning,style,performance,portability --error-exitcode=1 --std=c++17 --platform=win64 -Isrc src tests/tests.cpp`. PowerShell 7 can run `scripts/validate-json.ps1` to validate live JSON against the bundled schema. Build/test scripts may use development shells; the shipped application never invokes one. Validation must only invoke the auditor's read-only operations; never force a sleep transition or change configuration to manufacture evidence.
