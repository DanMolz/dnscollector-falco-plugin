/*
Copyright (C) 2022 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dnscollector

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

// Fields returns the list of extractor fields exported for DNS Collector events.
func (f *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "dnscollector.network.family", Desc: "IP protocol version INET or INET6"},
		{Type: "string", Name: "dnscollector.network.protocol", Desc: "Protocol UDP, TCP"},
		{Type: "string", Name: "dnscollector.network.query-ip", Desc: "DNS query IP address"},
		{Type: "string", Name: "dnscollector.network.query-port", Desc: "DNS query port"},
		{Type: "string", Name: "dnscollector.network.response-ip", Desc: "DNS response IP address"},
		{Type: "string", Name: "dnscollector.network.response-port", Desc: "DNS response port"},
		{Type: "string", Name: "dnscollector.network.ip-defragmented", Desc: "IP-Fragmented"},
		{Type: "string", Name: "dnscollector.network.tcp-reassembled", Desc: "TCP-Reassembled"},
		{Type: "uint64", Name: "dnscollector.dns.length", Desc: "Length of the query or response."},
		{Type: "uint64", Name: "dnscollector.dns.opcode", Desc: "DNS operation code (integer)"},
		{Type: "string", Name: "dnscollector.dns.rcode", Desc: "DNS return code"},
		{Type: "string", Name: "dnscollector.dns.qname", Desc: "DNS query name"},
		{Type: "string", Name: "dnscollector.dns.qtype", Desc: "DNS query type"},
		{Type: "string", Name: "dnscollector.dns.flags.qr", Desc: "DNS query type value q/r"},
		{Type: "string", Name: "dnscollector.dns.flags.tc", Desc: "DNS truncated response flag"},
		{Type: "string", Name: "dnscollector.dns.flags.aa", Desc: "DNS authoritive response flag"},
		{Type: "string", Name: "dnscollector.dns.flags.ra", Desc: "DNS recursion available flag"},
		{Type: "string", Name: "dnscollector.dns.flags.ad", Desc: "DNS authenticated data flag"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.an", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.an.name", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.an.rdatatype", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.an.ttl", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.an.rdata", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.ns.name", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.ns.rdatatype", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.ns.ttl", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.ns.rdata", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.ar.name", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.ar.rdatatype", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.ar.ttl", Desc: "resource-records"},
		// {Type: "string", Name: "dnscollector.dns.resource-records.ar.rdata", Desc: "resource-records"},
		{Type: "string", Name: "dnscollector.dns.malformed-packet", Desc: "Malformed dns packet, integer value 1/0"},
		{Type: "uint64", Name: "dnscollector.dns.repeated", Desc: "DNS query repeated"},
		{Type: "uint64", Name: "dnscollector.edns.udp-size", Desc: "EDNS UDP size"},
		{Type: "uint64", Name: "dnscollector.edns.rcode", Desc: "EDNS request code"},
		{Type: "uint64", Name: "dnscollector.edns.version", Desc: "EDNS version"},
		{Type: "uint64", Name: "dnscollector.edns.dnssec-ok", Desc: "EDNS DNSSEC_OK"},
		{Type: "string", Name: "dnscollector.edns.options", Desc: "EDNS options"},
		{Type: "string", Name: "dnscollector.dnstap.operation", Desc: "DNStap pperation"},
		{Type: "string", Name: "dnscollector.dnstap.identity", Desc: "DNStap identity"},
		{Type: "string", Name: "dnscollector.dnstap.version", Desc: "DNStap version"},
		{Type: "string", Name: "dnscollector.dnstap.latency", Desc: "Computed latency between queries and replies"},
		{Type: "uint64", Name: "dnscollector.suspicious.score", Desc: "DNS calcualted suspicious score"},
		{Type: "string", Name: "dnscollector.suspicious.malformed-pkt", Desc: "DNS suspicious malformed packet detected"},
		{Type: "string", Name: "dnscollector.suspicious.large-pkt", Desc: "DNS suspicious large packet detected"},
		{Type: "string", Name: "dnscollector.suspicious.long-domain", Desc: "DNS suspicious long domain detected"},
		{Type: "string", Name: "dnscollector.suspicious.slow-domain", Desc: "DNS suspicious unallowed characters detected"},
		{Type: "string", Name: "dnscollector.suspicious.unallowed-chars", Desc: "DNS suspicious unallowed characters detected"},
		{Type: "string", Name: "dnscollector.suspicious.uncommon-qtypes", Desc: "DNS suspicious uncommon query type detected"},
		{Type: "string", Name: "dnscollector.suspicious.excessive-number-labels", Desc: "DNS suspicious excessive number of labels detected"},
	}
}
