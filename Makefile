all: cms.bpf.o pass.bpf.o fexit.bpf.o fentry.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
%.o: %.c 
	clang \
		-D__TARGET_ARCH_x86 \
 		-target bpf \
 		-g \
 		-O2 -c $< -o $@
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	#clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%,$@)
