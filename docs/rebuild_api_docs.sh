#!/bin/sh

rm -rf source/api/*

sphinx-apidoc -M -T -e -t ./apidoc -d -1 -f -o ./source/api ../pwncat ../pwncat/commands/[!_]* ../pwncat/channel/[!_]* ../pwncat/modules/*[!.][!p][!y]
