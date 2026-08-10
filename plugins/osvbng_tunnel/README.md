# osvbng-vpp-plugin-tunnel

Generic tunnel RX dispatch for osvbng.

Overlay tunnel decap paths in VPP bypass the device-input feature arc,
so osvbng features armed on tunnel interfaces (l2gw, ipoe, pppoe, punt)
never see decapsulated frames. This plugin provides a single node,
`osvbng-tunnel-input`, registered as a sibling of `device-input`, that
re-enters the arc for the tunnel `sw_if_index` after decap. Frames then
traverse exactly the same RX path as on a physical port, falling
through to `ethernet-input` when no features are armed.

The node is stateless and lock-free; buffers stay on their RX worker
from decap through feature processing to the egress output node.

Usage: the control plane queries `osvbng_tunnel_decap_next_get` for the
node's next-index slot on `vxlan4-input` / `vxlan6-input` and passes it
as `decap_next_index` when creating a vxlan tunnel. Other encap types
(GRE, MPLS pseudowires) can be added the same way.
