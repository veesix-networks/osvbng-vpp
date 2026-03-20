/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - COBALT AQM
 * Combined CoDel + BLUE active queue management.
 *
 * CoDel: Controlled Delay (RFC 8289) — drop/mark at increasing frequency
 * when sojourn time exceeds target for longer than interval.
 *
 * BLUE: Probabilistic dropping for unresponsive flows — increment drop
 * probability on persistent queue buildup, decrement on drain.
 *
 * Algorithms derived from the Linux CAKE qdisc (sch_cake.c).
 * Original authors: Dave Taht, Jonathan Morton, Toke Hoiland-Jorgensen,
 * Sebastian Moeller, Kevin Darbyshire-Bryant, Ryan Mounce.
 */

#include <osvbng_qos_sched/osvbng_qos_sched.h>

/*
 * Newton-Raphson rec_inv_sqrt update.
 * Approximates 1/sqrt(count) for CoDel drop interval scheduling.
 *
 * From Linux CoDel: val = (val * (3 - val^2 * count)) / 2
 * Scaled to u16 range (0-65535 represents 0.0-1.0).
 */
void
cake_codel_newton_step (cake_flow_t *flow)
{
  u32 val = (u32) flow->codel_rec_inv_sqrt;
  u32 count = flow->codel_count;

  /* Newton step */
  val = (val * 3) / 2 -
	(((u64) val * val * val) * count) / ((u64) 0xffff * 0xffff * 2);

  if (val > 0xffff)
    val = 0xffff;
  flow->codel_rec_inv_sqrt = (u16) val;
}

/*
 * CoDel control law: compute next drop time.
 * next = now + interval / sqrt(count)
 *       = now + interval * rec_inv_sqrt
 */
static_always_inline u64
cake_codel_control_law (u64 now_us, u32 interval_us, u16 rec_inv_sqrt)
{
  return now_us + ((u64) interval_us * rec_inv_sqrt) / 0xffff;
}

/*
 * COBALT combined drop decision.
 *
 * Returns 1 if packet should be dropped, 0 otherwise.
 * Sets *ecn_mark to 1 if packet was ECN CE marked instead of dropped.
 *
 * TODO: Full implementation with:
 * - CoDel state machine (idle → dropping → recovering)
 * - BLUE probability updates (increase on overflow, decrease on drain)
 * - rec_inv_sqrt cache lookup for small count values
 * - ECN marking integration
 */

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
