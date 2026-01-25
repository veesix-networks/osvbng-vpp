# OSVBNG Unified Control Plane Punt Plugin

This VPP plugin provides unified punting of control plane packets (DHCP, ARP, PPPoE, L2TP, IPv6 ND) to the OSVBNG control plane via a single unix socket.

## Features

- **Unified Socket**: Single unix socket for all control plane protocols
- **Per-Interface Control**: Enable/disable punt per interface and per protocol
- **Multi-Protocol Support**:
  - DHCPv4 (UDP port 67/68)
  - DHCPv6 (UDP port 546/547)
  - ARP (EtherType 0x0806)
  - PPPoE Discovery (EtherType 0x8863)
  - PPPoE Session (EtherType 0x8864)
  - IPv6 Neighbor Discovery (ICMPv6)
  - L2TP Control (UDP port 1701)
- **Consistent Metadata**: All punted packets include sw_if_index, protocol type, and timestamp
- **Statistics**: Per-protocol counters for punted and dropped packets

## Usage

### CLI Commands

Enable ARP punt on an interface:
```
osvbng punt enable GigabitEthernet0/0/0 protocol arp socket /run/osvbng/punt.sock
```

Enable DHCPv4 punt:
```
osvbng punt enable GigabitEthernet0/0/0 protocol dhcpv4 socket /run/osvbng/punt.sock
```

Disable punt:
```
osvbng punt disable GigabitEthernet0/0/0 protocol arp
```

Show statistics:
```
show osvbng punt stats
```

### Packet Format

Each punted packet is framed with a header followed by the raw packet data:

```c
struct osvbng_punt_packet_header {
    uint32_t sw_if_index;      // Interface index (network byte order)
    uint8_t  protocol;         // Protocol type (0=DHCPv4, 1=DHCPv6, 2=ARP, ...)
    uint8_t  direction;        // 0=RX, 1=TX
    uint16_t data_len;         // Packet length (network byte order)
    uint64_t timestamp_ns;     // Nanosecond timestamp (network byte order)
    // Followed by raw packet data
};
```

## Architecture

The plugin uses two punting mechanisms:

1. **Feature Arcs** (for L2 protocols like ARP, PPPoE):
   - Packets enter the appropriate feature arc (e.g., "arp" for ARP packets)
   - Plugin nodes intercept and punt to socket
   - Provides early interception before protocol processing

2. **VPP Native Punt** (for L4 protocols like DHCP, L2TP):
   - Leverages VPP's existing efficient UDP punt infrastructure
   - Packets registered by UDP port
   - Minimal overhead

## Building

The plugin is built as part of the VPP build system:

```bash
cd vpp
make build-release
```

## Integration with OSVBNG

The OSVBNG control plane daemon reads from the punt socket and dispatches packets to protocol-specific handlers based on the protocol field in the header.

See `../context/refactor/UNIFIED_PUNT_PLUGIN.md` for detailed design documentation.
