# Validation and release context: modern-standby-auditor 1.0.0

Development/build validation: Windows Server 2025 x64. The exact executable completed physical Windows 11 Pro 25H2 x64 qualification (build 26200.9550) and Windows 10 Pro 22H2 x64 qualification in a dedicated QEMU VM (build 19045.6466). Physical Windows 10 hardware and ARM64 were not qualified. Windows 11 status: PASS WITH FINDINGS, supported by the preserved physical qualification report dated 2026-10-02 and raw/run ledgers. Historical Windows 10 detailed ledgers are unavailable; completion is user supplied.

The final ZIP was assembled after executable qualification around the unchanged qualified EXE. Execution of this final assembled package on Windows is not claimed. Development validation is distinct from client qualification.

Qualified executable SHA-256: `659e564741a05554e65ae4efdaf00c072e7c141a952f3c92e1fc9a1a9212df90`.

No separately imported MSVC C++ runtime DLLs were found; Windows system libraries remain required.

Physical Windows 11 observations: powercfg /a independently confirms S0 Low Power Idle Network Connected; S1/S2/S3 unavailable and hibernation disabled. /lastwake, /waketimers, /devicequery wake_armed and /requests captured without power transitions. History, armed timers/devices, requests, last wake, current residency and separate networking policy are explicitly unavailable in v1.

Recorded findings: Registry product branding says Windows 10 Pro, although build/release and the explicit stale-brand caveat are correct. Prefer prominent Windows 11 identification. S4 is correctly scoped as capability; hiberfile absence agrees with powercfg showing hibernation unavailable.

Qualification safety limits: no broad filesystem, registry or policy mutation tracing was performed. Parent-PID TCP polling observed no connections; UDP, child traffic and packet-level activity were not monitored. These observations are not a formal proof of absence of all side effects.

See application documentation for query, output and safety limits. Windows may perform internal activity while servicing read-only API calls.
