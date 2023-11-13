all: cms.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
%.o: %.c 
	clang \
		-D__TARGET_ARCH_x86 \
 		-target bpf \
 		-I/usr/include/$(shell uname -m)-linux-gnu \
		-I/usr/src/linux-headers-6.2.0-36-generic/include/uapi \
		-idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include \
 		-g \
 		-O2 -c $< -o $@
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%,$@)
