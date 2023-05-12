# ✨ Falco Plugin - DNS Collector ✨

This project is a falco plugin for the DNS Collector project (https://github.com/dmachard/go-dnscollector).

## Supported Fields
Here is the current set of supported fields:


|             NAME                                    |   TYPE   | ARG  |                                                          DESCRIPTION                                    |
|-----------------------------------------------------|----------|------|---------------------------------------------------------------------------------------------------------|
| `dnscollector.network.family`                       | `string`        | None | IP protocol version INET or INET6.                                                               |
| `dnscollector.network.protocol`                     | `string`        | None | Protocol UDP, TCP.                                                                               |
| `dnscollector.network.query-ip`                     | `string`        | None | DNS query IP address.                                                                            |
| `dnscollector.network.query-port`                   | `string`        | None | DNS query port.                                                                                  |
| `dnscollector.network.response-ip`                  | `string`        | None | DNS response IP address.                                                                         |
| `dnscollector.network.response-port`                | `string`        | None | DNS response port.                                                                               |
| `dnscollector.network.ip-defragmented`              | `string`        | None | IP-Fragmented.                                                                                   |
| `dnscollector.network.tcp-reassembled`              | `string`        | None | TCP-Reassembled.                                                                                 |
| `dnscollector.dns.length`                           | `uint64`        | None | Length of the query or response.                                                                 |
| `dnscollector.dns.opcode`                           | `uint64`        | None | DNS operation code (integer).                                                                    |
| `dnscollector.dns.rcode`                            | `string`        | None | DNS return code.                                                                                 |
| `dnscollector.dns.qname`                            | `string`        | None | DNS query name.                                                                                  |
| `dnscollector.dns.qtype`                            | `string`        | None | DNS query type.                                                                                  |
| `dnscollector.dns.flags.qr`                         | `string`        | None | DNS query type value q/r.                                                                        |
| `dnscollector.dns.flags.tc`                         | `string`        | None | DNS truncated response flag.                                                                     |
| `dnscollector.dns.flags.aa`                         | `string`        | None | DNS authoritive response flag.                                                                   |
| `dnscollector.dns.flags.ra`                         | `string`        | None | DNS recursion available flag.                                                                    |
| `dnscollector.dns.flags.ad`                         | `string`        | None | DNS authenticated data flag.                                                                     |
| `dnscollector.dns.malformed-packet`                 | `string`        | None | Malformed dns packet, integer value 1/0.                                                         |
| `dnscollector.dns.repeated`                         | `uint64`        | None | DNS query repeated.                                                                              |
| `dnscollector.edns.udp-size`                        | `uint64`        | None | EDNS UDP size.                                                                                   |
| `dnscollector.edns.rcode.`                          | `uint64`        | None | EDNS request code.                                                                               |
| `dnscollector.edns.version.`                        | `uint64`        | None | EDNS version.                                                                                    |
| `dnscollector.edns.dnssec-ok.`                      | `uint64`        | None | EDNS DNSSEC_OK.                                                                                  |
| `dnscollector.edns.options.`                        | `string`        | None | EDNS options.                                                                                    |
| `dnscollector.dnstap.operation`                     | `string`        | None | DNStap pperation.                                                                                |
| `dnscollector.dnstap.identity`                      | `string`        | None | DNStap identity.                                                                                 |
| `dnscollector.dnstap.version`                       | `string`        | None | DNStap version.                                                                                  |
| `dnscollector.dnstap.latency`                       | `string`        | None | Computed latency between queries and replies.                                                    |
| `dnscollector.suspicious.score`                     | `string`        | None | DNS calcualted suspicious score.                                                                 |
| `dnscollector.suspicious.malformed-pkt`             | `string`        | None | DNS suspicious malformed packet detected.                                                        |
| `dnscollector.suspicious.large-pkt`                 | `string`        | None | DNS suspicious large packet detected.                                                            |
| `dnscollector.suspicious.long-domain`               | `string`        | None | DNS suspicious long domain detected.                                                             |
| `dnscollector.suspicious.slow-domain`               | `string`        | None | DNS suspicious long domain detected.
| `dnscollector.suspicious.unallowed-chars`           | `string`        | None | DNS suspicious unallowed characters detected.                                                    |
| `dnscollector.suspicious.uncommon-qtypes`           | `string`        | None | DNS suspicious uncommon query type detected.                                                     |
| `dnscollector.suspicious.excessive-number-labels`   | `string`        | None | DNS suspicious excessive number of labels detected.                                              |


## Configuration

### `falco.yaml` Example

```yaml
plugins:
  - name: dnscollector
    library_path: libdnscollector.so
    open_params: "http://:8888/events"
load_plugins: [dnscollector]
```