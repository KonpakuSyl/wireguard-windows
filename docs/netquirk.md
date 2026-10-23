# Network Configuration Quirks

Bringing a tunnel up also sets the network parameters that belong to that configuration.

### Routing

`wgctl` takes all the allowed IPs from each peer, deduplicates them, and adds them to the routes for the WireGuard interface. It then monitors which interface on the system has a default route (a route with a `/0` CIDR) that is not the WireGuard interface itself, and, if no MTU has been specified in the configuration, it sets the MTU of the WireGuard interface to be 80 less than the MTU of that default route interface. WireGuardNT also monitors the routing table and determines the outgoing route that does not loop back to itself, and then sends each packet using `IP_PKTINFO`/`IPV6_PKTINFO`. It keeps track of the incoming interface and source address for received packets, and always replies to the sender in that way.

### Firewall considerations for `/0` allowed IPs

If an interface has only one peer, and that peer contains an allowed IP in `/0`, then WireGuard enables a so-called "kill-switch", which adds firewall rules to do the following:

- Packets from the tunnel process itself are permitted, so that WireGuard packets can flow successfully.
- If the configuration specifies DNS servers, then packets sent to port `53` are only permitted if they are to one of those DNS servers. This is to prevent Windows' [ordinary multihomed DNS resolution behavior](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552%28v%3Dws.10%29), so that DNS queries only go to the DNS server specified, rather than multiple DNS servers.
- Loopback packets are permitted, and packets actually going through the WireGuard tunnel are permitted.
- DHCP for IPv4 and IPv6 and NDP for IPv6 are permitted.
- All other packets are blocked.

This prevents traffic from leaking outside the tunnel.

To use a default route without these restrictive kill-switch semantics, use the routes `0.0.0.0/1` and `128.0.0.0/1` in place of `0.0.0.0/0`, and `::/1` and `8000::/1` in place of `::/0`. This achieves nearly the same thing, but does not activate the firewalling above. Configurations without a `/0` route fall back to ordinary Windows routing and DNS behavior.

### Considerations for non-`/0` allowed IPs

When the conditions above do not apply, routing and DNS information is handed to Windows in the typical way. This includes its [ordinary multihomed DNS resolution behavior](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552%28v%3Dws.10%29) and its ordinary routing table resolution. One firewall rule is still added, which allows the tunnel process to send and receive WireGuard packets.

### Network List Manager

Windows assigns a unique GUID to each new WireGuard adapter. The application makes this GUID deterministic, so that firewall policy (such as "public" vs "private" network categorization) can be consistently applied to the tunnel's network. The GUID is derived from the tunnel configuration, so changing the configuration changes the GUID. Technical details are described in [a mailing list post](https://lists.zx2c4.com/pipermail/wireguard/2019-June/004259.html).

### Adapter lifetime

The network adapter is created when `wgctl up` starts and destroyed when that process exits. Additional filters, address families, or protocols should be bound to the adapter programmatically, possibly through the configuration's script hooks or by automatic NDIS layer binding.

### Script hooks

`PreUp`, `PostUp`, `PreDown`, and `PostDown` run only when `HKLM\Software\WireGuard\DangerousScriptExecution` is `DWORD(1)`. They run as the elevated user who started `wgctl`, with `WIREGUARD_TUNNEL_NAME` set to the tunnel name. Leave the key unset unless you need the hooks; they are skipped by default.

```text
reg add HKLM\Software\WireGuard /v DangerousScriptExecution /t REG_DWORD /d 1 /f
```
