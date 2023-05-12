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
	"log"
	"os"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
)

const pluginName = "dnscollector"

// Plugin implements extractor.Plugin and extracts DNS request fields from
// DNS Collector events.
type Plugin struct {
	plugins.BasePlugin
	logger       *log.Logger
	Config       PluginConfig
	lastLogEvent LogEvent
	lastEventNum uint64
}

func (f *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          999,
		Name:        pluginName,
		Description: "Read DNS Collector Events",
		Contact:     "github.com/falcosecurity/plugins",
		Version:     "0.0.1",
		EventSource: "dnscollector",
	}
}

func (f *Plugin) Init(cfg string) error {
	// read configuration
	f.Config.Reset()
	err := json.Unmarshal([]byte(cfg), &f.Config)
	if err != nil {
		return err
	}

	// setup optional async extraction optimization
	extract.SetAsync(f.Config.UseAsync)

	// setup internal logger
	f.logger = log.New(os.Stderr, "["+pluginName+"] ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	return nil
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}
