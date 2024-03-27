#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>
#include "cms.skel.h"


int if_index;
struct cms_bpf* cms;

void sig_handler(int sig) {
	bpf_xdp_detach(if_index, 0, NULL);
	cms_bpf__destroy(cms);
	exit(0);
}

void bump_memlock_rlimit(void) {
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}
int main(int argc, char **argv) {

	int err;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return 1;
	}

	bump_memlock_rlimit();

	cms = cms_bpf__open_and_load();
	err = cms_bpf__attach(cms);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		return 1;
	}

	if (!cms) {
		fprintf(stderr, "Failed to open and load BPF object\n");
		return 1;
	}

	if_index = if_nametoindex(argv[1]);
	err = bpf_xdp_attach(if_index, bpf_program__fd(cms->progs.cms), 0, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		return 1;
	}


	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while(1);

	return 0;
}

