#ifndef CDEV_TYPES
#define CDEV_TYPES
#include <stdint.h>
#include <stddef.h>
#include "modmap.h"

#define MAX_USERS 4
#define PAGE_SIZE 4096

typedef struct cdev_header_req {
    cap_req_t cap_req;
    uint32_t my_id;
} cdev_header_req_t;

typedef struct cdev_disc_req {
    cap_req_t cap_req;
    uint32_t my_id;
    int32_t found_receivers[MAX_USERS];
    uint32_t your_id;
} cdev_disc_req_t;

typedef struct tx_cdev_req {
    cap_req_t cap_req;
    uint32_t my_id;
    size_t length;
    uint32_t receiver_id;
} tx_cdev_req_t;

typedef struct __attribute__((packed)) cdev_buffers {
    char transmit_buffer[(PAGE_SIZE / 2) - 2];
    char receive_buffer[(PAGE_SIZE / 2) - 2];
    uint32_t rx_offest;
} cdev_buffers_t;

#define CDEV_TX    _IOWR('E', 1, tx_cdev_req_t)
#define CDEV_DISC  _IOWR('E', 2, cdev_disc_req_t)
#define CDEV_GBY   _IOWR('E', 3, cdev_header_req_t)

#endif