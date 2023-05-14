# based on https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
make:
	nasm -f win64 directjump.asm -o directjump.o
	x86_64-w64-mingw32-gcc ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ApiResolve.o -Wl,--no-seh
	x86_64-w64-mingw32-gcc HookShellcode.c -Wall -m64 -masm=intel -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o HookShellcode.o -Wl,--no-seh
	x86_64-w64-mingw32-ld -s directjump.o ApiResolve.o HookShellcode.o -o HookShellcode.exe
