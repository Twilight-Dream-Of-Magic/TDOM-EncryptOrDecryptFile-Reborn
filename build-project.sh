#!/usr/bin/env bash

# --parents

if [ -d "./build-project" ];
then
	mkdir --verbose "./build-project"
fi

cd "./build-project"

#cmake -S is SourceCodePath
#cmake -B is BuildScriptPath

sudo cmake -S ../ -B .
sudo make help
sudo make TDOM-EncryptOrDecryptFile-Reborn
