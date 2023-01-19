@ECHO off

IF NOT EXIST "build-project" (
	MKDIR "build-project"
)

CD /d "build-project"

cmake -S .. -B .

IF EXIST ".\Makefile" (
	make TDOM-EncryptOrDecryptFile-Reborn
) ELSE IF EXIST "TDOM-EncryptOrDecryptFile-Reborn.sln"(
	msbuild TDOM-EncryptOrDecryptFile-Reborn.sln
) ELSE (
	echo ==============================================================================
	echo CMake Failed
)

PAUSE
CD ..
