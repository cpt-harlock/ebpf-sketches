if [ $# -ne 2 ]; then
	echo "Usage: sudo ./attach.sh <prog_prefix> <dev>"
	exit
fi
sudo bpftool prog load ${1}.bpf.o /sys/fs/bpf/${1}
sudo bpftool net attach xdp name ${1} dev ${2}
