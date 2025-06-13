#include "cdev.h"

#include <sys/param.h>

#define CDEV_LOCK_INIT(sc) mtx_init(&(sc)->sc_mtx, "cdev_cheri", "cdev softc lock", MTX_SPIN)
#define CDEV_LOCK(sc)      mtx_lock_spin(&(sc)->sc_mtx)
#define CDEV_UNLOCK(sc)    mtx_unlock_spin(&(sc)->sc_mtx)
#define CDEV_LOCK_DESTROY(sc) mtx_destroy(&(sc)->sc_mtx)

static size_t current_users = 0;

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

static int check_cap_token(cdev_softc_t* sc, uint32_t id, void* __capability cap_token){
    if(check_attach_and_lock(sc)){
        return EINVAL;
    }

    if(!sc->user_states[id].valid){
        CDEV_UNLOCK(sc);
        return EINVAL;
    }

    if(sc->user_states[id].cap_state.sealed_cap == NULL){
        CDEV_UNLOCK(sc);
        return EINVAL;
    }

    if(cap_token == NULL){
        CDEV_UNLOCK(sc);
        return EINVAL;
    }

    void* __capability unsealed_token = cheri_unseal(cap_token, sc->user_states[id].sealing_key);
    if(!cheri_ptr_equal_exact(unsealed_token, sc->user_states[id].cap_state.original_cap)){
        CDEV_UNLOCK(sc);
        return EPERM;
    }

    CDEV_UNLOCK(sc);
    return 0;
}

static int check_cap_token_loop(cdev_softc_t* sc, void* __capability cap_token){
    if(check_attach_and_lock(sc)){
        return EINVAL;
    }

    bool found = false;
    for(size_t i = 0; i < current_users; i++){
        if(!sc->user_states[i].valid){
           continue;
        }

        if(sc->user_states[i].cap_state.sealed_cap == NULL){
            continue;
        }

        if(cap_token == NULL){
            continue;
        }

        uprintf("CDEV: Chekcing equality\n");
        void* __capability unsealed_token = cheri_unseal(cap_token, sc->user_states[i].sealing_key);
        if(!cheri_ptr_equal_exact(unsealed_token, sc->user_states[i].cap_state.original_cap)){
            CDEV_UNLOCK(sc);
            continue;
        }

        found = true;
    }

    CDEV_UNLOCK(sc);
    return found ? 0 : EPERM;
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
static void revoke_cap_token(cdev_softc_t* sc, uint32_t id_to_revoke){
    sc->user_states[id_to_revoke].cap_state.original_cap = NULL;
    sc->user_states[id_to_revoke].cap_state.sealed_cap = NULL;
}

static int
cdev_close(struct cdev *dev, int flags, int devtype, struct thread *td)
{
	uprintf("CDEV: device closed\n");

    cdev_softc_t *sc = dev->si_drv1;

    if(sc != NULL){
        CDEV_LOCK(sc);

        size_t i;
        for(i = 0; i < MAX_USERS; i++){
            if(!sc->user_states[i].valid){
                continue;
            }
            if(sc->user_states[i].pid == curthread->td_proc->p_pid){
                break;
            }
        }

        if(i == MAX_USERS){
            CDEV_UNLOCK(sc);
            return 0;
        }

        free(sc->user_states[i].page, M_DEVBUF);
        sc->user_states[i].page_freed = true;

        revoke_cap_token(sc, i);

        CDEV_UNLOCK(sc);
    }

	return (0);
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

    cdev_buffers_t* user_page = NULL;
    for(size_t i = 0; i < MAX_USERS; i++){
        if(!sc->user_states[i].valid){
            continue;
        }
        if(sc->user_states[i].pid == curthread->td_proc->p_pid){
            user_page = sc->user_states[i].page;
            break;
        }
    }

    if(user_page == NULL){
        return VM_PAGER_FAIL;
    }

	paddr = pmap_kextract(cheri_getaddress(user_page) + offset);

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

static int cdev_mmap_single_extra(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t size, vm_object_t *object, int nprot, void * __kerncap extra, vm_map_t map){
    cdev_softc_t *sc = cdev->si_drv1;
	vm_object_t obj;
    cap_req_t* __kerncap req = NULL;

    // need to have a user request at all to make this work
    if(extra == NULL){
        return EINVAL;
    }

    req = (cap_req_t* __kerncap)extra;

    // validate that request is properly formed
    if (req->user_cap == NULL ||
        sc == NULL ||
        (current_users == MAX_USERS) ||
        (offset != NULL && *offset != 0) ||
        size != PAGE_SIZE){
        return EINVAL;
    }

	CDEV_LOCK(sc);
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

    sc->user_states[current_users].valid = true;
    sc->user_states[current_users].map = map;
    sc->user_states[current_users].obj = obj;
    sc->user_states[current_users].pid = curthread->td_proc->p_pid;
    sc->user_states[current_users].sealing_key = create_sealing_key(current_users);

    uprintf("CDEV: sealing key %#p\n", sc->user_states[current_users].sealing_key);
    sc->user_states[current_users].page = (cdev_buffers_t*)malloc(sizeof(cdev_buffers_t), M_DEVBUF, M_WAITOK | M_ZERO);

    // seal user cap
    sc->user_states[current_users].cap_state.original_cap = req->user_cap;
    sc->user_states[current_users].cap_state.sealed_cap = cheri_seal(req->user_cap, sc->user_states[current_users].sealing_key);

    req->sealed_cap = sc->user_states[current_users].cap_state.sealed_cap;

    current_users++;
	CDEV_UNLOCK(sc);

	return (0);
}

static void
discover_users(cdev_softc_t* sc, cdev_disc_req_t* req){
    size_t current_pos = 0;
    for(size_t i = 0; i < MAX_USERS; i++){
        if(sc->user_states[i].valid){
            req->found_receivers[current_pos] = sc->user_states[i].user_id;
            current_pos++;
        }
        if(sc->user_states[i].pid == curthread->td_proc->p_pid){
            req->your_id = i;
        }
    }

    for(size_t i = current_pos; i < MAX_USERS; i++){
        req->found_receivers[current_pos] = -1;
    }
}

static int
transmit_to_user(cdev_softc_t* sc, tx_cdev_req_t* req){
    return 0;
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
    if(header_req->my_id >= 0 && header_req->my_id < MAX_USERS){
        if(check_cap_token(sc, header_req->my_id, header_req->cap_req.sealed_cap)){
            return EPERM;
        }
    }
    else{
        uprintf("CDEV: Cap token loop\n");
        if(check_cap_token_loop(sc, header_req->cap_req.sealed_cap)){
            return EPERM;
        }
    }
    

    tx_cdev_req_t* user_req_tx = NULL;
    cdev_disc_req_t* user_req_disc = NULL;

    uprintf("CDEV: Switch statement\n");
    switch(cmd){
        case CDEV_GBY:
            if(check_attach_and_lock(sc)){
                return EINVAL;
            }

            if(header_req->my_id >= MAX_USERS || header_req->my_id < 0){
                return EINVAL;
            }

            revoke_cap_token(sc, header_req->my_id);
            CDEV_UNLOCK(sc);
            break;
        case CDEV_DISC:
            if(check_attach_and_lock(sc)){
                return EINVAL;
            }

            user_req_disc = (cdev_disc_req_t*)addr;

            // function to return cdev discovery
            discover_users(sc, user_req_disc);
            
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
            if(user_req_tx->length > ((PAGE_SIZE / 2) - 2)){
                uprintf("CDEV: User Wants To Send Too Many Bytes\n");
                CDEV_UNLOCK(sc);
                return EINVAL;
            }

            if(user_req_tx->receiver_id >= MAX_USERS || user_req_tx->receiver_id < 0){
                uprintf("CDEV: User Wants To Send non existent receiver\n");
                CDEV_UNLOCK(sc);
                return EINVAL;
            }

            if(!sc->user_states[user_req_tx->receiver_id].valid){
                uprintf("CDEV: User Wants To Send non existent receiver\n");
                CDEV_UNLOCK(sc);
                return EINVAL;
            }

            // call transmmit function
            transmit_to_user(sc, user_req_tx);

            CDEV_UNLOCK(sc);
            break;
        default:
            error = ENOTTY;
            break;
    }

    return error;
}

static struct cdev *cdev_cdev;

static int
create_our_cdev(cdev_softc_t* sc){
    sc->cdev = make_dev(&cdev_cdevsw, 0, UID_ROOT, GID_WHEEL,
        0600, "cdev_cheri");
    cdev_cdev = sc->cdev;

    if(sc->cdev == NULL){
        return EINVAL;
    }

    sc->cdev->si_drv1 = sc;

    sc->device_attached = true;

    return 0;
}

static int
destroy_our_cdev(cdev_softc_t* sc){
    if(sc == NULL){
        return ENXIO;
    }
    CDEV_LOCK(sc);
    if(sc->mapped){
        CDEV_UNLOCK(sc);
        return EBUSY;
    }

    sc->dying = true;
    CDEV_UNLOCK(sc);

    destroy_dev(sc->cdev);
    for(size_t i = 0; i < MAX_USERS; i++){
        if(sc->user_states[i].valid){
            continue;
        }

        if(sc->user_states[i].page_freed){
            continue;
        }

        free(sc->user_states[i].page, M_DEVBUF);
    }

    free(sc, M_DEVBUF);

    cdev_cdev = NULL;
    return 0;
}

static int
handle_load(void){
    cdev_softc_t* sc = (cdev_softc_t*)malloc(sizeof(cdev_softc_t), M_DEVBUF, M_WAITOK | M_ZERO);
    CDEV_LOCK_INIT(sc);

    return create_our_cdev(sc);
}

static int
cdev_modevent(module_t mod, int type, void *arg)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
        error = handle_load();
        if(error){
            printf("Device failed to load\n");
        }
		break;
	case MOD_UNLOAD: /* FALLTHROUGH */
	case MOD_SHUTDOWN:
        if(cdev_cdev == NULL){
            return ENXIO;
        }

        error = destroy_our_cdev(cdev_cdev->si_drv1);
        if(error){
            printf("Couldn't unload device\n");
        }
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

DEV_MODULE(cdev, cdev_modevent, NULL);