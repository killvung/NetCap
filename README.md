# NetCap
Have you ever wonder, what goes in and out of your network.

## netwatch-agent

Finally I have time to work on this.
 - A Go binary on the router.
 - It runs persistently on the router.
 - It starts at router boot through an OpenWrt procd init service.
 - It binds to [port] by default.
 - It collects device inventory and recent traffic samples even when no macOS client is connected.
 - It exposes data through gRPC/protobuf.
 - It retains only a bounded recent sample buffer; it is not the long-term history store.
