package tools

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port           int
	PKCS11Module   string
	BindAddress    string
	AllowedOrigins []string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Port:           9889,
		BindAddress:    "127.0.0.1",
		AllowedOrigins: []string{"http://localhost:8080"},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
	}

	if v := os.Getenv("SIGNER_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("invalid SIGNER_PORT: %w", err)
		}
		cfg.Port = p
	}

	cfg.PKCS11Module = os.Getenv("SIGNER_PKCS11_MODULE")
	if cfg.PKCS11Module == "" {
		return cfg, fmt.Errorf("SIGNER_PKCS11_MODULE is required")
	}

	if _, err := os.Stat(cfg.PKCS11Module); err != nil {
		return cfg, fmt.Errorf("PKCS#11 module not found at %s: %w", cfg.PKCS11Module, err)
	}

	if v := os.Getenv("SIGNER_BIND_ADDRESS"); v != "" {
		cfg.BindAddress = v
	}

	if v := os.Getenv("SIGNER_ALLOWED_ORIGINS"); v != "" {
		cfg.AllowedOrigins = strings.Split(v, ",")
		for i := range cfg.AllowedOrigins {
			cfg.AllowedOrigins[i] = strings.TrimSpace(cfg.AllowedOrigins[i])
		}
	}

	return cfg, nil
}

func (c Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.BindAddress, c.Port)
}
