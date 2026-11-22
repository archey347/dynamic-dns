## Dynamic DNS API for RFC2136

A Dynamic DNS API for bind servers. Receives requests from remote hosts via HTTP, then issues an update to a DNS server via RFC2136. 

Has a similar kind of interface as the one at [Mythic Beasts](https://www.mythic-beasts.com/support/api/dnsv2/dynamic-dns).

### Testing

```
DYNAMIC_DNS_CONFIG=etc/dynamic-dns/dynamic-dns-server.yaml go run cmd/dynamic-dns-server/main.go
```
### Images

Pushing a `vX.Y.Z` tag publishes `archey347/dynamic-dns:vX.Y.Z`, `:vX.Y` and `:latest`. A weekly
rebuild of the newest release refreshes `:vX.Y` and `:latest` with current base-image fixes;
`:vX.Y.Z` is never rebuilt. Deployments that should pick those up (e.g. via `podman auto-update`)
follow `:vX.Y`.
