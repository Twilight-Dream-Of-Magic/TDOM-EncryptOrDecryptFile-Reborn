#!/usr/bin/env bash

# --parents

if [ -d "./build-project" ];
then
	mkdir --verbose "./build-project"
fi

cd "./build-project"

#cmake -S is SourceCodePath
#cmake -B is BuildScriptPath

cmake -S ..\ -B . -G "Unix Makefiles"

make help
make TDOM-EncryptOrDecryptFile-Reborn
