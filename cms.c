#include <bpf/libbpf.h>
#include "cms.skel.h"


int main() {
	// ah boh
	struct cms_bpf* cms = cms_bpf__open_and_load();
}

