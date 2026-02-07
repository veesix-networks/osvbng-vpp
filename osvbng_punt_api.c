/*
 * Copyright (c) 2025 Veesix Networks
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/format_fns.h>
#include <osvbng_punt/osvbng_punt.h>

/* API message includes */
#include <osvbng_punt/osvbng_punt.api_enum.h>
#include <osvbng_punt/osvbng_punt.api_types.h>

#define REPLY_MSG_ID_BASE pm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
  vl_api_osvbng_punt_enable_disable_t_handler
  (vl_api_osvbng_punt_enable_disable_t * mp)
{
  vl_api_osvbng_punt_enable_disable_reply_t *rmp;
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  int rv;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  switch (mp->protocol)
    {
    case OSVBNG_PUNT_PROTO_DHCPV4:
      if (mp->enable)
	rv = osvbng_punt_enable_dhcpv4 (sw_if_index);
      else
	rv = osvbng_punt_disable_dhcpv4 (sw_if_index);
      break;
    case OSVBNG_PUNT_PROTO_DHCPV6:
      if (mp->enable)
	rv = osvbng_punt_enable_dhcpv6 (sw_if_index);
      else
	rv = osvbng_punt_disable_dhcpv6 (sw_if_index);
      break;
    case OSVBNG_PUNT_PROTO_L2TP:
      if (mp->enable)
	rv = osvbng_punt_enable_l2tp (sw_if_index);
      else
	rv = osvbng_punt_disable_l2tp (sw_if_index);
      break;
    case OSVBNG_PUNT_PROTO_IPV6_ND:
      if (mp->enable)
	rv = osvbng_punt_enable_ipv6_nd (sw_if_index);
      else
	rv = osvbng_punt_disable_ipv6_nd (sw_if_index);
      break;
    default:
      rv = osvbng_punt_enable_disable (sw_if_index, mp->protocol, mp->enable);
      break;
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_OSVBNG_PUNT_ENABLE_DISABLE_REPLY);
}

static void
vl_api_osvbng_punt_stats_dump_t_handler (vl_api_osvbng_punt_stats_dump_t * mp)
{
  vl_api_osvbng_punt_stats_details_t *rmp;
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
    {
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
	ntohs (VL_API_OSVBNG_PUNT_STATS_DETAILS + pm->msg_id_base);
      rmp->context = mp->context;
      rmp->protocol = i;
      rmp->packets_punted = clib_host_to_net_u64 (pm->packets_punted[i]);
      rmp->packets_dropped = clib_host_to_net_u64 (pm->packets_dropped[i]);
      rmp->packets_policed = clib_host_to_net_u64 (pm->policers[i].policed);
      rmp->policer_rate = pm->policers[i].rate;
      rmp->policer_burst = htonl (pm->policers[i].burst);

      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
  vl_api_osvbng_punt_policer_configure_t_handler
  (vl_api_osvbng_punt_policer_configure_t * mp)
{
  vl_api_osvbng_punt_policer_configure_reply_t *rmp;
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  int rv = 0;

  if (mp->protocol >= OSVBNG_PUNT_N_PROTO)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
    }
  else
    {
      rv = osvbng_punt_policer_configure (mp->protocol, mp->rate,
					  ntohl (mp->burst));
    }

  REPLY_MACRO (VL_API_OSVBNG_PUNT_POLICER_CONFIGURE_REPLY);
}

static void
vl_api_osvbng_punt_registration_dump_t_handler (vl_api_osvbng_punt_registration_dump_t * mp)
{
  vl_api_osvbng_punt_registration_details_t *rmp;
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  for (int proto = 0; proto < OSVBNG_PUNT_N_PROTO; proto++)
    {
      u32 sw_if_index;
      uword *p;

      hash_foreach (sw_if_index, p, pm->enabled_interfaces[proto],
      ({
        rmp = vl_msg_api_alloc (sizeof (*rmp));
        clib_memset (rmp, 0, sizeof (*rmp));
        rmp->_vl_msg_id =
          ntohs (VL_API_OSVBNG_PUNT_REGISTRATION_DETAILS + pm->msg_id_base);
        rmp->context = mp->context;
        rmp->sw_if_index = htonl (sw_if_index);
        rmp->protocol = proto;

        vl_api_send_msg (reg, (u8 *) rmp);
      }));
    }
}

#include <osvbng_punt/osvbng_punt.api.c>

static clib_error_t *
osvbng_punt_api_init (vlib_main_t * vm)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  /* Ask for a correctly-sized block of API message decode slots */
  pm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_punt_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
