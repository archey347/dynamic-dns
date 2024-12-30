package internal

import (
	"errors"

	"github.com/archey347/dynamic-dns/internal/http"
	"github.com/spf13/viper"
)

var AllowedRecordTypes = map[string]bool{
	"A":    true,
	"AAAA": true,
}

type Config struct {
	Http        http.Config            `mapstructure:"http"`
	Keys        map[string]*Key        `mapstructure:"keys"`
	Zones       map[string]*Zone       `mapstructure:"zones"`
	Nameservers map[string]*Nameserver `mapstructure:"nameservers"`
}

type Key struct {
	Secret  string `mapstructure:"secret"`
	Allowed []struct {
		Zone         string   `mapstructure:"zone"`
		HostPatterns []string `mapstructure:"host_patterns"`
		RecordTypes  []string `mapstructure:"record_types"`
	} `mapstructure:"allowed"`
}

type Zone struct {
	Nameservers []string `mapstructure:"nameservers"`
}

type Nameserver struct {
	Address string `mapstructure:"address"`
	Key     struct {
		Name   string `mapstructure:"name"`
		Secret string `mapstructure:"secret"`
	} `mapstructure:"key"`
}

const defaultConfigFile = "/etc/dynamic-dns/dynamic-dns-server.yaml"

func LoadConfig(configFile string) (*Config, error) {
	if configFile == "" {
		configFile = defaultConfigFile
	}

	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigType("yaml")
	v.SetConfigFile(configFile)

	err := v.ReadInConfig()
	if err != nil {
		return nil, err
	}

	config := &Config{}

	err = v.Unmarshal(&config)
	if err != nil {
		return nil, err
	}

	err = validateConfig(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func validateConfig(config *Config) error {
	for zoneName, zone := range config.Zones {
		for _, ns := range zone.Nameservers {
			if _, ok := config.Nameservers[ns]; !ok {
				return errors.New("Unknown nameserver '" + ns + "' configured for zone '" + zoneName + "'")
			}
		}
	}

	return nil
}
