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
	"encoding/json"
	"io"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

type LogEvent struct {
	Network struct {
		Family         string `json:"family"`
		Protocol       string `json:"protocol"`
		QueryIP        string `json:"query-ip"`
		QueryPort      string `json:"query-port"`
		ResponseIP     string `json:"response-ip"`
		ResponsePort   string `json:"response-port"`
		IPDefragmented bool   `json:"ip-defragmented"`
		TCPReassembled bool   `json:"tcp-reassembled"`
	} `json:"network"`
	DNS struct {
		Length int    `json:"length"`
		Opcode int    `json:"opcode"`
		Rcode  string `json:"rcode"`
		Qname  string `json:"qname"`
		Qtype  string `json:"qtype"`
		Flags  struct {
			Qr bool `json:"qr"`
			Tc bool `json:"tc"`
			Aa bool `json:"aa"`
			Ra bool `json:"ra"`
			Ad bool `json:"ad"`
		} `json:"flags"`
		ResourceRecords struct {
			An []struct {
				Name      string `json:"name"`
				Rdatatype string `json:"rdatatype"`
				TTL       int    `json:"ttl"`
				Rdata     string `json:"rdata"`
			} `json:"an"`
			Ns []struct {
				Name      string `json:"name"`
				Rdatatype string `json:"rdatatype"`
				TTL       int    `json:"ttl"`
				Rdata     string `json:"rdata"`
			} `json:"ns"`
			Ar []struct {
				Name      string `json:"name"`
				Rdatatype string `json:"rdatatype"`
				TTL       int    `json:"ttl"`
				Rdata     string `json:"rdata"`
			} `json:"ar"`
		} `json:"resource-records"`
		MalformedPacket bool `json:"malformed-packet"`
		Repeated        int  `json:"repeated"`
	} `json:"dns"`
	Edns struct {
		UDPSize  int           `json:"udp-size"`
		Rcode    int           `json:"rcode"`
		Version  int           `json:"version"`
		DnssecOk int           `json:"dnssec-ok"`
		Options  []interface{} `json:"options"`
	} `json:"edns"`
	Dnstap struct {
		Operation          string    `json:"operation"`
		Identity           string    `json:"identity"`
		Version            string    `json:"version"`
		TimestampRfc3339Ns time.Time `json:"timestamp-rfc3339ns"`
		Latency            string    `json:"latency"`
	} `json:"dnstap"`
	Suspicious struct {
		Score                 int  `json:"score"`
		MalformedPkt          bool `json:"malformed-pkt"`
		LargePkt              bool `json:"large-pkt"`
		LongDomain            bool `json:"long-domain"`
		SlowDomain            bool `json:"slow-domain"`
		UnallowedChars        bool `json:"unallowed-chars"`
		UncommonQtypes        bool `json:"uncommon-qtypes"`
		ExcessiveNumberLabels bool `json:"excessive-number-labels"`
	} `json:"suspicious"`
}

// Extract allows Falco plugin framework to get values for all available fields
func (f *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	data := f.lastLogEvent

	if evt.EventNum() != f.lastEventNum {
		rawData, err := io.ReadAll(evt.Reader())
		if err != nil {
			return err
		}

		err = json.Unmarshal(rawData, &data)
		if err != nil {
			return err
		}

		f.lastLogEvent = data
		f.lastEventNum = evt.EventNum()
	}

	switch req.Field() {
	case "dnscollector.network.family":
		req.SetValue(data.Network.Family)
	case "dnscollector.network.protocol":
		req.SetValue(data.Network.Protocol)
	case "dnscollector.network.query-ip":
		req.SetValue(data.Network.QueryIP)
	case "dnscollector.network.query-port":
		req.SetValue(data.Network.QueryPort)
	case "dnscollector.network.response-ip":
		req.SetValue(data.Network.ResponseIP)
	case "dnscollector.network.response-port":
		req.SetValue(data.Network.ResponsePort)
	case "dnscollector.network.ip-defragmented":
		value := formatBool(data.Network.IPDefragmented)
		req.SetValue(value)
	case "dnscollector.network.tcp-reassembled":
		value := formatBool(data.Network.TCPReassembled)
		req.SetValue(value)
	case "dnscollector.dns.length":
		value := formatInt(data.DNS.Length)
		req.SetValue(value)
	case "dnscollector.dns.opcode":
		value := formatInt(data.DNS.Opcode)
		req.SetValue(value)
	case "dnscollector.dns.rcode":
		req.SetValue(data.DNS.Rcode)
	case "dnscollector.dns.qname":
		req.SetValue(data.DNS.Qname)
	case "dnscollector.dns.qtype":
		req.SetValue(data.DNS.Qtype)
	case "dnscollector.dns.flags.qr":
		value := formatBool(data.DNS.Flags.Qr)
		req.SetValue(value)
	case "dnscollector.dns.flags.tc":
		value := formatBool(data.DNS.Flags.Tc)
		req.SetValue(value)
	case "dnscollector.dns.flags.aa":
		value := formatBool(data.DNS.Flags.Aa)
		req.SetValue(value)
	case "dnscollector.dns.flags.ra":
		value := formatBool(data.DNS.Flags.Ra)
		req.SetValue(value)
	case "dnscollector.dns.flags.ad":
		value := formatBool(data.DNS.Flags.Ad)
		req.SetValue(value)

	// WIP
	// case "dnscollector.dns.resource-records.an.name":
	// 	req.SetValue(data.DNS.ResourceRecords.An[0].Name)
	// case "dnscollector.dns.resource-records.an.rdatatype":
	// 	req.SetValue(data.DNS.ResourceRecords.An[0].Rdatatype)
	// case "dnscollector.dns.resource-records.an.ttl":
	// 	req.SetValue(data.DNS.ResourceRecords.An[0].TTL)
	// case "dnscollector.dns.resource-records.an.rdata":
	// 	req.SetValue(data.DNS.ResourceRecords.An[0].Rdata)
	// case "dnscollector.dns.resource-records.ns.name":
	// 	req.SetValue(data.DNS.ResourceRecords.Ns[0].Name)
	// case "dnscollector.dns.resource-records.ns.rdatatype":
	// 	req.SetValue(data.DNS.ResourceRecords.Ns[0].Rdatatype)
	// case "dnscollector.dns.resource-records.ns.ttl":
	// 	req.SetValue(data.DNS.ResourceRecords.Ns[0].TTL)
	// case "dnscollector.dns.resource-records.ns.rdata":
	// 	req.SetValue(data.DNS.ResourceRecords.Ns[0].Rdata)
	// case "dnscollector.dns.resource-records.ar.name":
	// 	req.SetValue(data.DNS.ResourceRecords.Ar[0].Name)
	// case "dnscollector.dns.resource-records.ar.rdatatype":
	// 	req.SetValue(data.DNS.ResourceRecords.Ar[0].Rdatatype)
	// case "dnscollector.dns.resource-records.ar.ttl":
	// 	req.SetValue(data.DNS.ResourceRecords.Ar[0].TTL)
	// case "dnscollector.dns.resource-records.ar.rdata":
	// 	req.SetValue(data.DNS.ResourceRecords.Ar[0].Rdata)
	
case "dnscollector.dns.malformed-packet":
		value := formatBool(data.DNS.MalformedPacket)
		req.SetValue(value)
	case "dnscollector.dns.repeated":
		value := formatInt(data.DNS.Repeated)
		req.SetValue(value)
	case "dnscollector.edns.udp-size":
		value := formatInt(data.Edns.UDPSize)
		req.SetValue(value)
	case "dnscollector.edns.rcode":
		value := formatInt(data.Edns.Rcode)
		req.SetValue(value)
	case "dnscollector.edns.version":
		value := formatInt(data.Edns.Version)
		req.SetValue(value)
	case "dnscollector.edns.dnssec-ok":
		value := formatInt(data.Edns.DnssecOk)
		req.SetValue(value)
	case "dnscollector.edns.options":
		req.SetValue(data.Edns.Options)
	case "dnscollector.dnstap.operation":
		req.SetValue(data.Dnstap.Operation)
	case "dnscollector.dnstap.identity":
		req.SetValue(data.Dnstap.Identity)
	case "dnscollector.dnstap.version":
		req.SetValue(data.Dnstap.Version)
	case "dnscollector.dnstap.latency":
		req.SetValue(data.Dnstap.Latency)
	case "dnscollector.suspicious.score":
		value := formatInt(data.Suspicious.Score)
		req.SetValue(value)
	case "dnscollector.suspicious.malformed-pkt":
		value := formatBool(data.Suspicious.MalformedPkt)
		req.SetValue(value)
	case "dnscollector.suspicious.large-pkt":
		value := formatBool(data.Suspicious.LargePkt)
		req.SetValue(value)
	case "dnscollector.suspicious.long-domain":
		value := formatBool(data.Suspicious.LongDomain)
		req.SetValue(value)
	case "dnscollector.suspicious.slow-domain":
		value := formatBool(data.Suspicious.SlowDomain)
		req.SetValue(value)
	case "dnscollector.suspicious.unallowed-chars":
		value := formatBool(data.Suspicious.UnallowedChars)
		req.SetValue(value)
	case "dnscollector.suspicious.uncommon-qtypes":
		value := formatBool(data.Suspicious.UncommonQtypes)
		req.SetValue(value)
	case "dnscollector.suspicious.excessive-number-labels":
		value := formatBool(data.Suspicious.ExcessiveNumberLabels)
		req.SetValue(value)
	default:
		return nil
	}

	return nil
}

func formatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func formatInt(i int) uint64 {
	v := uint64(i)
	return v
}