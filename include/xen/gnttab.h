#ifndef __GNTTAB_H__
#define __GNTTAB_H__

#include <xen/interface/grant_table.h>

void init_gnttab(void);
void fini_gnttab(void);

grant_ref_t gnttab_alloc_and_grant(void **map);
grant_ref_t gnttab_grant_access(domid_t domid, unsigned long frame,
                                int readonly);
grant_ref_t gnttab_grant_transfer(domid_t domid, unsigned long pfn);
int gnttab_end_access(grant_ref_t ref);
const char *gnttabop_error(int16_t status);

#endif /* !__GNTTAB_H__ */
