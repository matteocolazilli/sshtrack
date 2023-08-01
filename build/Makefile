TARGET = sshtrack
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ../src/${TARGET:=.c}
USER_SKEL = ../include/${TARGET:=.skel.h}
VMLINUX_H = ../include/vmlinux.h

all: $(TARGET) $(BPF_OBJ) $(VMLINUX_H)
.PHONY: all

$(TARGET): $(USER_C) $(USER_SKEL)
	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz

%.bpf.o: ../src/%.bpf.c ../include/vmlinux.h
	clang \
	    -target bpf \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

install:
	sudo cp ./sshtrack /usr/bin/

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
