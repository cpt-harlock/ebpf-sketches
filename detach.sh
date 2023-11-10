if [ $# -ne 2 ]; then
	echo "Usage: sudo ./detach.sh <prog_prefix> <dev>"
	exit
fi
sudo bpftool net detach xdp dev ${2}
sudo rm /sys/fs/bpf/${1}
