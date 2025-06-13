#ifndef _MODMAP_H_
#define _MODMAP_H_

#include <sys/types.h>
#include <sys/ioccom.h>

typedef struct mmap_req_hook mmap_req_hook_t;

typedef struct mmap_req_user {
	void * __capability addr;    // needs to be null on request. No hints possible for now
	size_t len;
	int prot;
	int flags;
	int fd;
	off_t pos;
	void * __capability extra;
 } mmap_req_user_t;

typedef struct cap_req {
    void* __capability user_cap;
    void* __capability sealed_cap;
} cap_req_t;

#define MODMAPIOC_MAP	_IOWR('a', 1, mmap_req_user_t)
#endif 