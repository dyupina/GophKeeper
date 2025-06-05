// Package config is used to configure the application settings.
package config

import (
	"flag"
	"os"
	"strings"
)

// Config - application configuration structure.
type Config struct {
	// Addr: server address (e.g., "https://localhost:8085").
	Addr string `json:"server_address"`
	// DBConnection: database connection string.
	DBConnection string `json:"database_dsn"`
	// Timeout: integer value representing the request processing timeout in seconds.
	Timeout int
}

var cfgDefault = Config{
	Addr:         "", //"https://localhost:8085",
	DBConnection: "",
	Timeout:      15,
}

// NewConfig creates and returns a new instance of the Config structure with predefined values.
func NewConfig() *Config {
	return &cfgDefault
}

func parseEnv(c *Config) {
	if val, exist := os.LookupEnv("SERVER_ADDRESS"); exist {
		val = strings.Trim(val, `"`)
		c.Addr = val
	}
	if val, exist := os.LookupEnv("POSTGRES_USER"); exist {
		val = strings.Trim(val, `"`)
		c.DBConnection = "postgresql://" + val + ":"
	}
	if val, exist := os.LookupEnv("POSTGRES_PASSWORD"); exist {
		val = strings.Trim(val, `"`)
		c.DBConnection += val + "@"
	}
	if val, exist := os.LookupEnv("DB_HOST"); exist {
		val = strings.Trim(val, `"`)
		c.DBConnection += val + ":5432/"
	}
	if val, exist := os.LookupEnv("POSTGRES_DB"); exist {
		val = strings.Trim(val, `"`)
		c.DBConnection += val + "?sslmode=disable"
	}
}

// Init initializes the application configuration using environment variables and command-line flags.
func Init(c *Config) error {
	parseEnv(c)

	var flagCgf Config
	flag.StringVar(&flagCgf.Addr, "a", "", "HTTPS-server startup address")
	flag.StringVar(&flagCgf.DBConnection, "d", "", "database connection address")

	flag.Parse()

	// override
	if flagCgf.Addr != "" {
		c.Addr = flagCgf.Addr
	}
	if flagCgf.DBConnection != "" {
		c.DBConnection = flagCgf.DBConnection
	}

	return nil
}
