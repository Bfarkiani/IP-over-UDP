# IP-over-UDP

This project mimics a WireGuard VPN without encryption. You will need to configure the main function for both the clients and the server.

### Configuration

- **output_interface**: The output network interface used for NAT.
- **tunnel_ip**: Ensure that the server and client have unique IPs within the same subnet range.
- **udp_endpoints**: UDP endpoints where the VPN server is listening.
- **routes**: These are used to configure `iptables` to redirect traffic through the tunnel device created by the VPN.

For each route, the VPN needs to know where to send the traffic. Therefore, the keys in `routes` and `udp_endpoints` must match. However, you can specify different UDP endpoints for each route.

### Example

In the client configuration:

```python
routes = {
    '8.8.8.8/32': ('192.168.170.1', 10000)
}
```
This means that traffic destined for `8.8.8.8/32` will be sent to the UDP endpoint at IP `192.168.170.1` on port `10000`. A VPN server must be actively listening on port `10000` at the address `192.168.170.1`.
