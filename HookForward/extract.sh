#!/bin/bash
for i in $(objdump -d HookShellcode.exe | grep "^ " | cut -f2); do echo -e -n "\x$i"; done > hook.bin