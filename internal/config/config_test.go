package config

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit_Config(t *testing.T) {
	tests := []struct {
		name         string
		envVars      map[string]string
		cmdArgs      []string
		expectedAddr string
		expectedDB   string
	}{
		{
			name:         "No env or flags",
			envVars:      nil,
			cmdArgs:      []string{},
			expectedAddr: ":8085",
			expectedDB:   "postgresql://gophkeeper_user:gophkeeper_user@localhost:5432/gophkeeper_db?sslmode=disable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Устанавливаем переменные окружения
			for k, v := range tt.envVars {
				require.NoError(t, os.Setenv(k, v))
			}
			defer func() {
				for k := range tt.envVars {
					os.Unsetenv(k)
				}
			}()

			// Перенастраиваем флаги
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
			cfg := &Config{}

			Init(cfg)

			assert.Equal(t, tt.expectedAddr, cfg.Addr)
			assert.Equal(t, tt.expectedDB, cfg.DBConnection)
		})
	}
}

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	assert.Equal(t, "", cfg.Addr)
	assert.Equal(t, "", cfg.DBConnection)
	assert.Equal(t, 15, cfg.Timeout)
}
