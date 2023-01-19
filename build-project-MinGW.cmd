@ECHO off

IF NOT EXIST "build-project" (
	MKDIR "build-project"
)

CD /d "build-project"

cmake -S .. -B . -G "MinGW Makefiles"

IF EXIST "Makefile" (
	make TDOM-EncryptOrDecryptFile-Reborn
) ELSE (
	ECHO ==============================================================================
	ECHO CMake Failed
)

PAUSE
CD ..
