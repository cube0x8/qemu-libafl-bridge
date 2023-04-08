# QEMU LibAFL Bridge

This is a patched QEMU that exposes an interface for LibAFL-based fuzzers.

This raw interface is used in `libafl_qemu` that expose a more Rusty API.

## QEMU gdb_map_layout feature
This new feature allows to load a gdb dump into the guest's memory and emulate it. The dump can be exported from a live instance of gdb, after the breakpoint to the target function hit.

### How does it work?
A new loader has been added to QEMU and can be invoked as follows:

`-device loader,gdb_map_layout=/path/to/gdb_layout_file`.

The `gdb_map_layout` loader device will process the file passed as argument and will proceed with loading the dump files that have been previously extracted from a live instance of gdb.

For more information about how to export a suitable dump, please refer to the tool "gdb_dump" at this [link](https://github.com/cube0x8/fuzzing_helpers/tree/main/gdb_dump).

By using the QEMU `-kernel` command line option, it is possible to boot a custom kernel which can jump to the entry point of the target function. You can download [this](https://github.com/cube0x8/fuzzing_helpers/tree/main/x86_kernel) custom kernel and modify it with the address of your choice.


### How to use it?
To run a simple test, download a sample target [here](https://github.com/cube0x8/fuzzing_helpers/tree/main/x86_fuzzing_target) and compile it:

`# gcc -g -o target main.c`

Run it in gdb:

`# gdb ./target`

Set the breakpoint to the LibFuzzer-like entry point:

`(gdb) b LLVMFuzzerTestOneInput`

Run the target (`r`) and, once the breakpoint hit, export the process's address space by using the `gdb_dump` tool:

`(gdb) source /path/to/gdb_dump.py`

Display the pc and store it for later use:

```
(gdb) p/x $pc
$3 = 0x565561c0
```

Download a custom 32bit (x86) kernel from [here](https://github.com/cube0x8/fuzzing_helpers/tree/main/x86_fuzzing_target) and modify the `mov` instruction in the `kernel32_x86.asm` file to match your pc register:

```
mov eax, 0x565561c0
jmp eax
```

Build the kernel:

`./build.sh`

Build and execute `qemu-system-i386` as follows:

```
# cd build
# ./qemu-system-i386 -monitor null -kernel /path/to/kernel32_x86.elf -serial null -nographic -snapshot -m 4G -S -s -device loader,gdb_map_layout=/tmp/dump/layout_memory
```

Attach to the QEMU process using gdb and the `gdbinit` for real-mode debugging [(link)](https://github.com/cube0x8/fuzzing_helpers/blob/main/x86_kernel/gdbinit):
```
# gdb -x gdbinit
[...]
real-mode-gdb$ display /5i $pc
1: x/5i $pc
<error: No registers.>
real-mode-gdb$ target remote 127.0.0.1:1234
Remote debugging using 127.0.0.1:1234
[...]
---------------------------[ CODE ]----
   0xffff0:	jmp    0x3630:0xf000e05b
   0xffff7:	das    
   0xffff8:	xor    dh,BYTE PTR [ebx]
   0xffffa:	das    
   0xffffb:	cmp    DWORD PTR [ecx],edi
   0xffffd:	add    ah,bh
   0xfffff:	add    BYTE PTR [edx],al
   0x100001:	mov    al,0xad
   0x100003:	sbb    eax,DWORD PTR [eax]
   0x100005:	add    BYTE PTR [eax],al
0x0000fff0 in ?? ()
1: x/5i $pc
=> 0xfff0:	add    BYTE PTR [eax],al
   0xfff2:	add    BYTE PTR [eax],al
   0xfff4:	add    BYTE PTR [eax],al
   0xfff6:	add    BYTE PTR [eax],al
   0xfff8:	add    BYTE PTR [eax],al
real-mode-gdb$ b *0x565561c0
Breakpoint 1 at 0x565561c0
real-mode-gdb$ c
Continuing.
[...]

Breakpoint 1, 0x565561c0 in ?? ()
1: x/5i $pc
=> 0x565561c0:	endbr32 
   0x565561c4:	push   ebp
   0x565561c5:	mov    ebp,esp
   0x565561c7:	sub    esp,0x10
   0x565561ca:	call   0x565562e4

```

#### License

<sup>
This project extends the QEMU emulator, and our contributions to previously existing files adopt those files' respective licenses; the files that we have added are made available under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.
</sup>

<br>
