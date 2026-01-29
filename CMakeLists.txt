# Copyright (c) 2025 Veesix Networks
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_vpp_plugin(osvbng_punt
  SOURCES
  osvbng_punt.c
  osvbng_punt_arp.c
  osvbng_punt_dhcp.c
  osvbng_punt_dhcp6.c
  osvbng_punt_pppoe_disc.c
  osvbng_punt_pppoe_sess.c
  osvbng_punt_l2tp.c
  osvbng_punt_ipv6_nd.c
  osvbng_punt_api.c

  API_FILES
  osvbng_punt.api
)
