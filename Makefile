all: cms.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
%.o: %.c
	clang \
 		-target bpf \
 		-I/usr/include/$(shell uname -m)-linux-gnu \
 		-g \
 		-O2 -c $< -o $@
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%,$@)
