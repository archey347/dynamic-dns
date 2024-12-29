## Dynamic DNS API for RFC2136

A Dynamic DNS API for bind servers. Receives requests from remote hosts via HTTP, then issues an update to a DNS server via RFC2136. 

Has a similar kind of interface as the one at [Mythic Beasts](https://www.mythic-beasts.com/support/api/dnsv2/dynamic-dns).

### Testing

```
DYNAMIC_DNS_CONFIG=etc/dynamic-dns-server/dynamic-dns-server.yaml go run cmd/dynamic-dns-server/main.go
```