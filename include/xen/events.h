/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2005 - Grzegorz Milos - Intel Reseach Cambridge
 * (C) 2020 - EPAM Systems Inc.
 ****************************************************************************
 *
 *        File: events.h
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: Grzegorz Milos (gm281@cam.ac.uk)
 *
 *        Date: Jul 2003, changes Jun 2005
 *
 * Environment: Xen Minimal OS
 * Description: Deals with events on the event channels
 *
 ****************************************************************************
 */

#ifndef _EVENTS_H_
#define _EVENTS_H_

#include <asm/xen/hypercall.h>
#include <xen/interface/event_channel.h>

typedef void (*evtchn_handler_t)(evtchn_port_t, struct pt_regs *, void *);

void init_events(void);
void fini_events(void);

int do_event(evtchn_port_t port, struct pt_regs *regs);
void unbind_evtchn(evtchn_port_t port);
void unbind_all_ports(void);
int evtchn_alloc_unbound(domid_t pal, evtchn_handler_t handler,
			 void *data, evtchn_port_t *port);

static inline int notify_remote_via_evtchn(evtchn_port_t port)
{
	struct evtchn_send op;
	op.port = port;
	return HYPERVISOR_event_channel_op(EVTCHNOP_send, &op);
}

void eventchn_poll(void);

#endif /* _EVENTS_H_ */
