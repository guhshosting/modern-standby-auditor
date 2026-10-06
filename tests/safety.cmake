# Complementary source guard. Release import review is also required; this is
# not a proof against arbitrary future code changes.
file(GLOB sources "${ROOT}/src/*.cpp" "${ROOT}/src/*.h")
foreach(source IN LISTS sources)
  file(READ "${source}" content)
  if(content MATCHES "(SetSuspendState|SetThreadExecutionState|PowerSet|PowerCreateRequest|PowerClearRequest|PowerWrite|RegSet|RegCreate|CreateProcess|ShellExecute|system[ \t]*\\(|popen|WinHttp|WinInet|WSAStartup|socket[ \t]*\\(|DeviceIoControl|ExitWindows|InitiateSystemShutdown)")
    message(FATAL_ERROR "Forbidden mutation, network, or external-command API in ${source}")
  endif()
endforeach()
