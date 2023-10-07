#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/pfil.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "psp.h"

static int transport_encap(struct mbuf **mb)
{
	// TODO: Provide serious implementation
	return 0;
}

static pfil_return_t process_in_pkt(struct mbuf **mb, struct ifnet *ifp, int dir, void *arg, struct inpcb *inp)
{
	printf("Processing packet\n");
	struct ether_header *eh;
	u_short etype;

	eh = mtod(*mb, struct ether_header *);
	etype = ntohs(eh->ether_type);

	if (etype != ETHERTYPE_IP && etype != ETHERTYPE_IPV6)
	{
		printf("Skipping non-IP packet, etype = 0x%x\n", etype);
		return PFIL_PASS; // Return appropriate value (PFIL_PASS, PFIL_DROPPED, etc.)
	}

	// Returns 0 if packet was processed, non-zero otherwise (or EPERM if it should be dropped)
	return transport_encap(mb);
}

static int event_handler(module_t mod, int event, void *arg)
{
	int error = 0;
	static pfil_hook_t pfil_hook = NULL;

	switch (event)
	{
	case MOD_LOAD:
		printf("Greetings World! The kernel module has been loaded!\n");

		struct pfil_hook_args hookargs = {
			.pa_version = PFIL_VERSION,
			.pa_modname = "psp_module",
			.pa_type = PFIL_TYPE_IP4,
			.pa_flags = PFIL_IN | PFIL_OUT,
			.pa_mbuf_chk = process_in_pkt,
		};
		pfil_hook = pfil_add_hook(&hookargs);
		printf("Hook added\n");

		if (pfil_hook == NULL)
		{
			printf("Failed to add hook\n");
			error = EINVAL;
		}

		break;
	case MOD_UNLOAD:
		printf("Farewell! The kernel module has been unloaded!\n");
		if (pfil_hook != NULL)
		{
			printf("Removing hook\n");
			pfil_remove_hook(pfil_hook);
			pfil_hook = NULL;
		}
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return error;
}

static moduledata_t conf = {
	"psp_module",
	event_handler,
	NULL};

DECLARE_MODULE(psp_module, conf, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
