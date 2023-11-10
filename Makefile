all: cms.bpf.o
clean: 
	-rm *.o
%.o: %.c
	clang \
 		-target bpf \
 		-I/usr/include/$(shell uname -m)-linux-gnu \
 		-g \
 		-O2 -c $< -o $@
