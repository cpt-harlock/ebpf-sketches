#define CMS_SIZE 32
#define CMS_ROWS 4

#include <linux/types.h>

#pragma pack(1)
struct cms {
	__u16 count[CMS_ROWS][CMS_SIZE];
};

struct event {
	__u64 hash;
};
#pragma pack()
