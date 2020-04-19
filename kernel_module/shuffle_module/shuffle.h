#ifndef __SHUFFLE_IOCTL_H__
#define __SHUFFLE_IOCTL_H__

struct shuffle_args
{
	unsigned long from_addr;
	pid_t to_pid;
	unsigned long to_addr;
	unsigned long nr_pages;
	int res;
};

#define SHUFFLE_MAGIC 's'
#define SHUFFLE_IOCTL_SHUFFLE	_IOWR(SHUFFLE_MAGIC, 0x01, struct shuffle_args)

#endif
