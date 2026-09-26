@echo off
setlocal
set "DFIROSCOPE_VIEWER=%~dp0DFIRoscope.Live.exe"
if not exist "%DFIROSCOPE_VIEWER%" (
  >&2 echo DFIRoscope CLI launcher error: adjacent DFIRoscope.Live.exe was not found.
  exit /b 3
)
"%DFIROSCOPE_VIEWER%" %*
exit /b %ERRORLEVEL%
