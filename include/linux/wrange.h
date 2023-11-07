/* SPDX-License-Identifier: GPL-2.0-only */
/* wrange: wrapped range
 */
#ifndef _LINUX_WRANGE_H
#define _LINUX_WRANGE_H

#include <linux/types.h>

struct wrange32 {
	/* Start with a usual u32 min/max.
	 *
	 * Requiring umin/start <= umax/end, and cannot be use to track s32
	 * range.
	 */
	u32 start; /* umin */
	u32 end; /* umax */
};

/* Helper functions that will be required later */
static inline u32 wrange32_umin(struct wrange32 w) {
	return w.start;
}

static inline u32 wrange32_umax(struct wrange32 w) {
	return w.end;
}

#endif /* _LINUX_WRANGE_H */
