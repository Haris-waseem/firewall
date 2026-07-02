@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cmake -B build -S . -G "NMake Makefiles"
if %errorlevel% neq 0 exit /b %errorlevel%
cmake --build build --config Release
