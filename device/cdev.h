#ifndef CDEV_H
#define CDEV_H

#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/rman.h>
#include <sys/ioccom.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/rwlock.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include <cheri/cheric.h>
#include <cheri/cheri.h>

#define MAX_USERS 4

// cheri specific setup
MALLOC_DECLARE(M_DEVBUF);
MALLOC_DEFINE(M_DEVBUF, "cdev_cheri", "Cherified Uart Device Driver");

typedef struct cap_req {
    void* __capability user_cap;
    void* __capability sealed_cap;
} cap_req_t;

typedef struct cdev_header_req {
    cap_req_t cap_req;
} cdev_header_req_t;

typedef struct cdev_disc_req {
    cap_req_t cap_req;
    int32_t found_receivers[MAX_USERS];
} cdev_disc_req_t;

typedef struct tx_cdev_req {
    cap_req_t cap_req;
    size_t length;
    uint32_t receiver_id
} tx_cdev_req_t;

typedef struct __attribute__((packed)) cdev_buffers {
    char transmit_buffer[(PAGE_SIZE / 2) - 2];
    char receive_buffer[(PAGE_SIZE / 2) - 4];
    uint32_t rx_offest;
} cdev_buffers_t;

#define CDEV_TX    _IOWR('E', 1, tx_cdev_req_t);
#define CDEV_DISC  _IOWR('E', 2, cdev_disc_req_t);
#define CDEV_GBY   _IOWR('E', 2, cdev_header_req_t);

static d_open_t		cdev_open;
static d_close_t	cdev_close;
static d_ioctl_t	cdev_ioctl;
static d_mmap_single_extra_t cdev_mmap_single_extra;

static int	cdev_pager_ctor(void *handle, vm_ooffset_t size,
    vm_prot_t prot, vm_ooffset_t foff, struct ucred *cred, u_short *color);
static void	cdev_pager_dtor(void *handle);
static int	cdev_pager_fault(vm_object_t obj, vm_ooffset_t offset,
    int prot, vm_page_t *mres);

static struct cdev_pager_ops cdev_cdev_pager_ops = {
	.cdev_pg_ctor = cdev_pager_ctor,
	.cdev_pg_dtor = cdev_pager_dtor,
	.cdev_pg_fault = cdev_pager_fault,
};

static struct cdevsw cdev_cdevsw = {
	.d_name		= "cdev_cheri",
	.d_version	= D_VERSION,
	.d_open		= cdev_open,
	.d_close	= cdev_close,
	.d_ioctl	= cdev_ioctl,
    .d_mmap_single_extra = cdev_mmap_single_extra,
};

typedef struct sealed_cap_state {
    void * __capability original_cap;
    void * __capability sealed_cap;
} sealed_cap_state_t;

typedef struct user_state {
    bool valid;
    vm_object_t obj;
    vm_map_t map;
    void* __capability sealing_key;
    sealed_cap_state_t cap_state;
    cdev_buffers_t* page;
    uint32_t user_id;
} user_state_t;

typedef struct cdev_soft_c {
    bool device_attached;

    struct cdev* cdev;
    struct mtx      sc_mtx;

    // message passing data
    user_state_t user_states[MAX_USERS];

    bool dying;
    bool mapped;
} cdev_softc_t;

#endif