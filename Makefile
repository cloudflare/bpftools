
.PHONY: all
all: linux_tools/bpf_dbg linux_tools/bpf_asm

linux_tools/bpf_dbg: linux_tools/*.[ch]
	make -C linux_tools bpf_dbg

linux_tools/bpf_asm: linux_tools/*.[ch]
	make -C linux_tools bpf_asm

