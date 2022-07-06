
.PHONY: all
all: linux_tools/bpf_dbg linux_tools/bpf_asm
	python3 -c "import pcappy"


linux_tools/bpf_dbg: linux_tools/*.[ch]
	make -C linux_tools bpf_dbg

linux_tools/bpf_asm: linux_tools/*.[ch]
	make -C linux_tools bpf_asm

test:
	python3 -m unittest discover tests/
