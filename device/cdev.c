#include "cdev.h"

#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>

#define REFCLOCK 24000000

#define CDEV_LOCK_INIT(sc) mtx_init(&(sc)->sc_mtx, device_get_nameunit((sc)->dev), "cdev softc lock", MTX_DEF)
#define CDEV_LOCK(sc)      mtx_lock(&(sc)->sc_mtx)
#define CDEV_UNLOCK(sc)    mtx_unlock(&(sc)->sc_mtx)
#define CDEV_LOCK_DESTROY(sc) mtx_destroy(&(sc)->sc_mtx)

// Forward declarations for device methods
static int cdev_acpi_probe(device_t dev);
static int cdev_acpi_attach(device_t dev);
static int cdev_acpi_detach(device_t dev);

// ACPI-compatible hardware IDs for the PL011 CDEV
static char *cdev_ids[] = { "ARMH0011", NULL };

static int check_cap_token(cdev_softc_t* sc, void* __capability cap_token){
    if(sc->cap_state.sealed_cap == NULL){
        return EINVAL;
    }

    if(cap_token == NULL){
        return EINVAL;
    }

    void* __capability unsealed_token = cheri_unseal(cap_token, sc->sealing_key);
    if(!cheri_ptr_equal_exact(unsealed_token, sc->cap_state.original_cap)){
        return EPERM;
    }

    return 0;
}

static int check_attach_and_lock(cdev_softc_t *sc){
    if(sc == NULL){
        return EINVAL;
    }

    CDEV_LOCK(sc);
    if(!sc->device_attached){
        CDEV_UNLOCK(sc);
        return EINVAL;
    }

    return 0;
}

static int
cdev_open(struct cdev *dev, int flags, int devtype, struct thread *td)
{
    cdev_softc_t *sc = dev->si_drv1;

    int err = check_attach_and_lock(sc);

    if(err){
        return ENXIO;
    }

    CDEV_UNLOCK(sc);
	uprintf("CDEV: device opened\n");
	return (0);
}

// probably will be expanded in the future to revoke all caps in the vm object and such
static void revoke_cap_token(cdev_softc_t* sc){
    sc->cap_state.original_cap = NULL;
    sc->cap_state.sealed_cap = NULL;
}

static int
cdev_close(struct cdev *dev, int flags, int devtype, struct thread *td)
{
	uprintf("CDEV: device closed\n");

    cdev_softc_t *sc = dev->si_drv1;

    if(sc != NULL){
        CDEV_LOCK(sc);
        revoke_cap_token(sc);
        CDEV_UNLOCK(sc);
    }

	return (0);
}

static int
create_our_cdev(cdev_softc_t* sc){
    sc->cdev = make_dev(&cdev_cdevsw, 0, UID_ROOT, GID_WHEEL,
        0600, "cdev-cheri");
    if(sc->cdev == NULL){
        return EINVAL;
    }

    sc->cdev->si_drv1 = sc;

    // allocate shared mem using VM system instead of contigmalloc
    sc->page = (cdev_buffers_t* __kerncap)malloc(sizeof(cdev_registers), M_DEVBUF, M_WAITOK | M_ZERO);
    if(sc->page == NULL){
        destroy_dev(sc->cdev);
        device_printf(sc->dev, "Failed to create shared mem\n");
        return EINVAL;
    }

    return 0;
}

static int
destroy_our_cdev(cdev_softc_t* sc){
    CDEV_LOCK(sc);
    if(sc->mapped){
        CDEV_UNLOCK(sc);
        return EBUSY;
    }

    sc->dying = true;
    CDEV_UNLOCK(sc);

    destroy_dev(sc->cdev);
    free(sc->page, M_DEVBUF);
    return 0;
}

static int
cdev_pager_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot, vm_ooffset_t foff, struct ucred *cred, u_short *color){
    cdev_softc_t *sc = handle;

	CDEV_LOCK(sc);
	sc->mapped = true;
    CDEV_UNLOCK(sc);

	*color = 0;
	return (0);
}

static void
cdev_pager_dtor(void *handle){
    cdev_softc_t *sc = handle;

	CDEV_LOCK(sc);
	sc->mapped = false;
	CDEV_UNLOCK(sc);
}

static int
cdev_pager_fault(vm_object_t obj, vm_ooffset_t offset, int prot, vm_page_t *mres){
    cdev_softc_t *sc = obj->handle;
	vm_page_t page;
	vm_paddr_t paddr;

	paddr = pmap_kextract(cheri_getaddress(sc->page) + offset);

	/* See the end of old_dev_pager_fault in device_pager.c. */
	if (((*mres)->flags & (PG_FICTITIOUS | PGA_CAPSTORE)) != 0) {
		page = *mres;
		vm_page_updatefake(page, paddr, VM_MEMATTR_DEFAULT);
	} else {
		VM_OBJECT_WUNLOCK(obj);
		page = vm_page_getfake(paddr, VM_MEMATTR_DEFAULT);
        page->a.flags |= PGA_CAPSTORE;
		VM_OBJECT_WLOCK(obj);
		vm_page_replace(page, obj, (*mres)->pindex, *mres);
		*mres = page;
	}

	vm_page_valid(page);
	return (VM_PAGER_OK);
}

static void* __capability
create_sealing_key(size_t id){
    if(id >= cheri_getbase(kernel_root_sealcap)){
        return NULL;
    }

    void * __capability derived = cheri_setaddress(kernel_root_sealcap, cheri_getbase(kernel_root_sealcap) + id);
    derived = cheri_setbounds(derived, 1);

    return derived;
}

static int cdev_mmap_single_extra(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t size, vm_object_t *object, int nprot, void * __kerncap extra){
    cdev_softc_t *sc = cdev->si_drv1;
	vm_object_t obj;
    cap_req_t* __kerncap req = NULL;

    // need to have a user request at all to make this work
    if(extra == NULL){
        return EINVAL;
    }

    req = (cap_req_t* __kerncap)extra;

    // validate that request is properly formed
	CDEV_LOCK(sc);
    if (req->user_cap == NULL ||
        sc == NULL ||
        sc->cap_state.sealed_cap != NULL ||
        (offset != NULL && *offset != 0) ||
        size != PAGE_SIZE){
		CDEV_UNLOCK(sc);
        return EINVAL;
    }

    // only allow mmap if not in teardown
	if (sc->dying) {
		CDEV_UNLOCK(sc);
		return (ENXIO);
	}
	CDEV_UNLOCK(sc);

    // make sure tag provided is valid
    if(!cheri_gettag(req->user_cap)){
        return EINVAL;
    }

    // create vm object for user
	obj = cdev_pager_allocate(sc, OBJT_DEVICE, &cdev_cdev_pager_ops,
	    OFF_TO_IDX(PAGE_SIZE), nprot | VM_PROT_CAP, *offset, curthread->td_ucred);
	if (obj == NULL)
		return (ENXIO);

    obj->flags |= OBJ_HASCAP;

	/*
	 * If an unload started while we were allocating the VM
	 * object, dying will now be set and the unloading thread will
	 * be waiting in destroy_dev().  Just release the VM object
	 * and fail the mapping request.
	 */
	CDEV_LOCK(sc);
	if (sc->dying) {
	    CDEV_UNLOCK(sc);
		vm_object_deallocate(obj);
		return (ENXIO);
	}

	*object = obj;

    // seal the cap the user provided and give it to them
    sc->cap_state.original_cap = req->user_cap;
    sc->cap_state.sealed_cap = cheri_seal(req->user_cap, sc->sealing_key);

    req->sealed_cap = sc->cap_state.sealed_cap;
	CDEV_UNLOCK(sc);

	return (0);
}

static int
cdev_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td){
    int error = 0;

    uprintf("CDEV: Addr check\n");
    if(addr == NULL){
        return EINVAL;
    }

    uprintf("CDEV: Cap cast\n");
    cdev_header_req_t* header_req = (cdev_header_req_t*)addr;
    cdev_softc_t *sc = dev->si_drv1;

    uprintf("CDEV: Null check\n");
    if(sc == NULL){
        return EINVAL;
    }

    uprintf("CDEV: Cap Token Check\n");
    if(check_cap_token(sc, header_req->cap_req.sealed_cap)){
        return EPERM;
    }

    tx_cdev_req_t* user_req_tx = NULL;

    uprintf("CDEV: Switch statement\n");
    switch(cmd){
        case CDEV_GBY:
            if(check_attach_and_lock(sc)){
                return EINVAL;
            }

            revoke_cap_token(sc);
            CDEV_UNLOCK(sc);
            break;
        case CDEV_TX:
            uprintf("CDEV: Lock\n");
            if(check_attach_and_lock(sc)){
                return EINVAL;
            }

            uprintf("CDEV: Read tx\n");
            user_req_tx = (tx_cdev_req_t *)addr;

            uprintf("CDEV: check length\n");
            if(user_req_tx->length > (PAGE_SIZE / 2)){
                device_printf(sc->dev, "User Wants To Send Too Many Bytes\n");
                CDEV_UNLOCK(sc);
                return EINVAL;
            }

            // call cdev transmit function
            cdev_write(sc, user_req_tx);

            CDEV_UNLOCK(sc);
            break;
        default:
            error = ENOTTY;
            break;
    }

    return error;
}