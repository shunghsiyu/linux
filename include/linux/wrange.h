/* SPDX-License-Identifier: GPL-2.0-only */
/* wrange: wrapped range
 *
 * A wrange tracks knowledge about a range of possible values using two bound,
 * start and end. The possible value could be any of the values (inclusively)
 * between start and end, and this can work even when end < start. Below is
 * some pseudo code for inferring the possible values within the 32-bit version
 * of wrange:
 *
 *   bool[U32_MAX] possible_values = { false };
 *   for (u32 i = start; i < end; i++)
 *   	possible_values[i] = true;
 *
 * For an intuitive visualization of wrange, one can imagine the 32-bit numeric
 * domain as a circle, where 0 sits at 6 o'clock, and the number increment as
 * we go in clockwise direction. Thus 2^30 sits at 9 o'clock, 2^31 at 12
 * o'clock, 2^31+2^30 at 3 o'clock, so on and so forth. This place 2^32-1 just
 * besides 0, one position away in the counter-clockwise direction. With this
 * visualization wrange can be seen as a line drawn on the circle, starting at
 * start, and goes in clockwise direction until it reaches end, where all the
 * numbers on such line is considered to be a possible value represented by
 * such wrange.
 */
#ifndef _LINUX_WRANGE_H
#define _LINUX_WRANGE_H

#include <linux/types.h>
#include <linux/limits.h>

struct wrange32 {
	/* Allow end < start */
	u32 start;
	u32 end;
};

static inline bool wrange32_uwrapping(struct wrange32 w) {
	return w.end < w.start;
}

static inline u32 wrange32_umin(struct wrange32 w) {
	if (wrange32_uwrapping(w))
		return U32_MIN;
	else
		return w.start;
}

static inline u32 wrange32_umax(struct wrange32 w) {
	if (wrange32_uwrapping(w))
		return U32_MAX;
	else
		return w.end;
}

static inline bool wrange32_swrapping(struct wrange32 w) {
	return (s32)w.end < (s32)w.start;
}

/* Helper functions that will be required later */
static inline s32 wrange32_smin(struct wrange32 w) {
	if (wrange32_swrapping(w))
		return S32_MIN;
	else
		return w.start;
}

static inline s32 wrange32_smax(struct wrange32 w) {
	if (wrange32_swrapping(w))
		return S32_MAX;
	else
		return w.end;
}

#endif /* _LINUX_WRANGE_H */
