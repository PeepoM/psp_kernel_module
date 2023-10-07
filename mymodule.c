#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <net/pfil.h>

static pfil_head_t my_filter_head;

static int my_filter(void *arg, struct mbuf **m, struct ifnet *ifp, int dir, struct inpcb *inp)
{
    // Log to stdout
    printf("Intercepted a packet!\n");

    // Forward the packet down the protocol stack
    return PFIL_PASS;
}

static int load(struct module *module, int cmd, void *arg)
{
    switch (cmd)
    {
        case MOD_LOAD:
            my_filter_head = pfil_head_register(NULL);
            if (my_filter_head == NULL)
            {
                printf("Failed to register pfil head\n");
                return EINVAL;
            }

            pfil_add_hook(&my_filter_head, my_filter, NULL, PFIL_IN, NULL);

            break;

        case MOD_UNLOAD:
            pfil_remove_hook(pfil_remove_hook(NULL, my_filter));
            pfil_head_unregister(my_filter_head);
            break;

        default:
            return EOPNOTSUPP;
    }

    return 0;
}

static moduledata_t my_filter_mod =
{
    "my_filter",
    load,
    NULL
};

DECLARE_MODULE(my_filter, my_filter_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
