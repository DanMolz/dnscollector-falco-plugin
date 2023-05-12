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

import "github.com/falcosecurity/plugin-sdk-go/pkg/sdk"

type PluginConfig struct {
	SSLCertificate      string `json:"sslCertificate"       jsonschema:"title=SSL certificate,description=The SSL Certificate to be used with the HTTPS Webhook endpoint (Default: /etc/falco/falco.pem),default=/etc/falco/falco.pem"`
	UseAsync            bool   `json:"useAsync"             jsonschema:"title=Use async extraction,description=If true then async extraction optimization is enabled (Default: true),default=true"`
	MaxEventSize        uint64 `json:"maxEventSize"         jsonschema:"title=Maximum event size,description=Maximum size of single event (Default: 262144),default=262144"`
	WebhookMaxBatchSize uint64 `json:"webhookMaxBatchSize"  jsonschema:"title=Maximum webhook request size,description=Maximum size of incoming webhook POST request bodies (Default: 12582912),default=12582912"`
}

// Resets sets the configuration to its default values
func (f *PluginConfig) Reset() {
	f.SSLCertificate = "/etc/falco/falco.pem"
	f.UseAsync = true
	f.MaxEventSize = uint64(sdk.DefaultEvtSize)
	f.WebhookMaxBatchSize = 12 * 1024 * 1024
}