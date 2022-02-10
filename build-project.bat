@ECHO off

IF NOT EXIST ".\build-project" (

	MKDIR ".\build-project"
)

CD /d ".\build-project"

cmake ..

IF EXIST ".\Makefile" (
	make .
) ELSE (
	msbuild TDOM-EncryptOrDecryptFile-Reborn.sln
)

PAUSE