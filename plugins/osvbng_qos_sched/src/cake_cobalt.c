/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - COBALT AQM
 * rec_inv_sqrt cache initialization (Newton-Raphson, Q0.32 fixed point).
 *
 * Algorithms derived from the Linux CAKE qdisc (sch_cake.c).
 * Original authors: Dave Taht, Jonathan Morton, Toke Hoiland-Jorgensen,
 * Sebastian Moeller, Kevin Darbyshire-Bryant, Ryan Mounce.
 */

#include <osvbng_qos_sched/osvbng_qos_sched.h>

u32 cobalt_rec_inv_sqrt_cache[CAKE_REC_INV_SQRT_CACHE] = { 0 };

void
cake_cobalt_cache_init (void)
{
  cake_flow_t v;
  clib_memset (&v, 0, sizeof (v));

  v.rec_inv_sqrt = ~0U;
  cobalt_rec_inv_sqrt_cache[0] = v.rec_inv_sqrt;

  for (v.codel_count = 1; v.codel_count < CAKE_REC_INV_SQRT_CACHE;
       v.codel_count++)
    {
      cobalt_newton_step (&v);
      cobalt_newton_step (&v);
      cobalt_newton_step (&v);
      cobalt_newton_step (&v);
      cobalt_rec_inv_sqrt_cache[v.codel_count] = v.rec_inv_sqrt;
    }
}

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
