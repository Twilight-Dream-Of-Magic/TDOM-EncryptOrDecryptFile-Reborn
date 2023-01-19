@ECHO off

IF NOT EXIST "build-project" (
	MKDIR "build-project"
)

CD /d "build-project"

cmake -S .. -B .

IF EXIST "Makefile" (
	make TDOM-EncryptOrDecryptFile-Reborn
) ELSE IF EXIST "TDOM-EncryptOrDecryptFile-Reborn.sln"(
	msbuild TDOM-EncryptOrDecryptFile-Reborn.sln
) ELSE (
	ECHO ==============================================================================
	ECHO CMake Failed
)

PAUSE
CD ..
