#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <cheri/cheric.h>

#include "modmap.h"
#include "cdev_types.h"


#define DEVNODE "/dev/cdev_cheri"

static int cdev_cheri_fd = -1;
static int modmap_fd;


int main(void) {
    uint32_t my_id = -1;
  printf("Opening cdev_cheri fd.\n");
  // 1) Open the character device
  cdev_cheri_fd = open(DEVNODE, O_RDWR);
  if (cdev_cheri_fd < 0)
    err(1, "open %s", DEVNODE);

  printf("attempting malloc() of User Cap.\n");
  cap_req_t cap_request;
  cap_request.user_cap = malloc(4096); // placeholder

  printf("User Cap: %p\n", cap_request.user_cap);

  //using mmap_req_user_t to create the pointer
  mmap_req_user_t req;
  req.addr  = NULL;                     // required
  req.len   = PAGE_SIZE;                     // page‐aligned
  req.prot  = PROT_READ | PROT_WRITE | PROT_CAP;
  req.flags = MAP_SHARED;               // or MAP_PRIVATE
  req.fd    = cdev_cheri_fd;                       // anonymous
  req.pos   = 0;
  req.extra = (void * __capability)(&cap_request); 

  printf("Before mmap ioctl:\n");
  modmap_fd = open("/dev/modmap", O_RDWR);
  if (modmap_fd < 0)
    err(1, "open %s", modmap_fd);

  while (true) {
    int code = ioctl(modmap_fd, MODMAPIOC_MAP, &req);
    if (code == 0) {
        break;
    }
    if (code == 16) {
        continue;
    }
    perror("ioctl MODMAPIOC_MAP");
    close(modmap_fd);
    return 1;
  }
 
  cdev_buffers_t* __capability cdev_buffer = (cdev_buffers_t* __capability) req.addr;
  printf("successfully retrived shared memeory address \n");
  fflush(stdout);

  printf("First byte: %02x\n", cdev_buffer->receive_buffer[0]);

  strncpy(cdev_buffer->transmit_buffer, "Hello World!", 12);

  printf("RX Buffer Offset: %d\n", cdev_buffer->rx_offest);

  printf("ioctling discover\n");
  printf("Cap before ioctl: %#p\n", cap_request.sealed_cap);


  cdev_disc_req_t cdev_disc_req;
  while (true) {
    cdev_disc_req.cap_req = cap_request;
    cdev_disc_req.my_id = my_id;

    if (ioctl(cdev_cheri_fd, CDEV_DISC, &cdev_disc_req) < 0) {
        perror("ioctl CDEV_DISC");
        close(cdev_cheri_fd);
            return 1;
    }
    my_id = cdev_disc_req.your_id;
    printf("CDEV_DISC informed identity: %d\n", my_id);
    if (cdev_disc_req.found_receivers[1] != -1) {
        printf("CDEV_DISC found peers\n");
        break;
    } else {
        printf("CDEV_DISC waiting on peers\n");
    }
    sleep(1);
  }

  printf("Cap after ioctl: %#p\n", cap_request.sealed_cap);
  printf("Ioctl CDEV_DISC sucessful\n");

  sleep(1);

  printf("First byte: %02x\n", cdev_buffer->receive_buffer[0]);
  printf("RX Buffer Offset: %d\n", cdev_buffer->rx_offest);
  printf("ioctling CDEV_TX\n");
  printf("Cap before ioctl: %#p\n", cap_request.sealed_cap);
  tx_cdev_req_t tx_cdev_req;
  tx_cdev_req.cap_req = cap_request;
  tx_cdev_req.my_id = my_id;
  strncpy(cdev_buffer->transmit_buffer, "Hello World!", 12);
  tx_cdev_req.length = 13;
  tx_cdev_req.receiver_id = cdev_disc_req.found_receivers[1];
  if (ioctl(cdev_cheri_fd, CDEV_TX, &tx_cdev_req) < 0) {
        perror("ioctl CDEV_TX");
        close(cdev_cheri_fd);
            return 1;
  }
  if (ioctl(cdev_cheri_fd, CDEV_TX, &tx_cdev_req) < 0) {
        perror("ioctl CDEV_TX");
        close(cdev_cheri_fd);
            return 1;
  }
  printf("Cap after ioctl: %#p\n", cap_request.sealed_cap);
  printf("Ioctl CDEV_TX sucessful\n");

  sleep(1);
  printf("First byte: %02x\n", cdev_buffer->receive_buffer[0]);
  printf("RX Buffer Offset: %d\n", cdev_buffer->rx_offest);


  sleep(1);
  printf("Attempting to send as a different user.\n");
  tx_cdev_req_t tx_cdev_req_bad_id;
  tx_cdev_req_bad_id.cap_req = cap_request;
  tx_cdev_req_bad_id.my_id = 1;
  strncpy(cdev_buffer->transmit_buffer, "Hello World!", 12);
  tx_cdev_req_bad_id.length = 13;
  tx_cdev_req_bad_id.receiver_id = my_id;
  if (ioctl(cdev_cheri_fd, CDEV_TX, &tx_cdev_req_bad_id) < 0) {
        printf("Driver rejected forged request.\n");
  }

  printf("Attempting to send without capability token.\n");
  uint32_t victim = cdev_disc_req.found_receivers[1];
  if (victim == my_id) {
    victim = cdev_disc_req.found_receivers[0];
  }
  cap_req_t bad_cap_request;
  tx_cdev_req_t tx_cdev_req_bad_cap;
  bad_cap_request.user_cap = malloc(4096); // placeholder
  tx_cdev_req_bad_cap.cap_req = bad_cap_request;
  tx_cdev_req_bad_cap.my_id = victim;
  strncpy(cdev_buffer->transmit_buffer, "Hello World!", 12);
  tx_cdev_req_bad_cap.length = 13;
  tx_cdev_req_bad_cap.receiver_id = my_id;
  if (ioctl(cdev_cheri_fd, CDEV_TX, &tx_cdev_req_bad_cap) < 0) {
        printf("Driver rejected invalid request.\n");
  } else {
    printf("Driver failed to reject invalid request %d as %d.\n", my_id, victim);
  }


  printf("ioctling CDEV_GBY\n");
  printf("Cap before ioctl: %#p\n", cap_request.sealed_cap);
  cdev_header_req_t cdev_header_req;
  cdev_header_req.cap_req = cap_request;
  cdev_header_req.my_id = my_id;
  if (ioctl(cdev_cheri_fd, CDEV_GBY, &cdev_header_req) < 0) {
        perror("ioctl CDEV_GBY");
        close(cdev_cheri_fd);
            return 1;
  }
  printf("Cap after ioctl: %#p\n", cap_request.sealed_cap);
  printf("Ioctl CDEV_GBY sucessful\n");

  // No way to forge request, but can call goodbye with invalid my_id of another process

  // ADD an use after free call that should fail

  // 

  // Try to read the rec buffer (should crash)
  printf("Should not print %c\n", cdev_buffer->receive_buffer[0]);

  close(modmap_fd);
  close(cdev_cheri_fd);
  return 0;
}
