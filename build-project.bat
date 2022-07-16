@ECHO off

IF NOT EXIST ".\build-project" (

	MKDIR ".\build-project"
)

CD /d ".\build-project"

cmake -S ..\ -B .

IF EXIST ".\Makefile" (
	make help
	make TDOM-EncryptOrDecryptFile-Reborn
) ELSE (
	msbuild TDOM-EncryptOrDecryptFile-Reborn.sln
)

PAUSE
