package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	Environment, HTTPAddress, DatabaseURL, AuthMode, OIDCIssuer, OIDCAudience string
	PartyBaseURL, PartyTokenURL, PartyClientID, PartyClientSecret             string
	S3Endpoint, S3Region, S3AccessKey, S3SecretKey, S3Bucket                  string
	UploadTTL, DownloadTTL                                                    time.Duration
}

func Load() (Config, error) {
	c := Config{
		Environment: value("DOCUMENT_ENVIRONMENT", "local"), HTTPAddress: value("DOCUMENT_HTTP_ADDRESS", ":8080"),
		DatabaseURL: strings.TrimSpace(os.Getenv("DOCUMENT_DATABASE_URL")), AuthMode: value("DOCUMENT_AUTH_MODE", "oidc"),
		OIDCIssuer: strings.TrimRight(strings.TrimSpace(os.Getenv("DOCUMENT_OIDC_ISSUER")), "/"), OIDCAudience: strings.TrimSpace(os.Getenv("DOCUMENT_OIDC_AUDIENCE")),
		PartyBaseURL: strings.TrimRight(strings.TrimSpace(os.Getenv("DOCUMENT_PARTY_BASE_URL")), "/"), PartyTokenURL: strings.TrimSpace(os.Getenv("DOCUMENT_PARTY_TOKEN_URL")),
		PartyClientID: strings.TrimSpace(os.Getenv("DOCUMENT_PARTY_CLIENT_ID")), PartyClientSecret: strings.TrimSpace(os.Getenv("DOCUMENT_PARTY_CLIENT_SECRET")),
		S3Endpoint: strings.TrimRight(strings.TrimSpace(os.Getenv("DOCUMENT_S3_ENDPOINT")), "/"), S3Region: value("DOCUMENT_S3_REGION", "zm-lusaka-1"),
		S3AccessKey: strings.TrimSpace(os.Getenv("DOCUMENT_S3_ACCESS_KEY")), S3SecretKey: strings.TrimSpace(os.Getenv("DOCUMENT_S3_SECRET_KEY")), S3Bucket: strings.TrimSpace(os.Getenv("DOCUMENT_S3_BUCKET")),
		UploadTTL: 15 * time.Minute, DownloadTTL: 5 * time.Minute,
	}
	allowed := map[string]bool{"local": true, "dev": true, "sandbox": true, "staging": true, "production": true}
	if !allowed[c.Environment] || c.DatabaseURL == "" || c.PartyBaseURL == "" || c.S3Endpoint == "" || c.S3AccessKey == "" || c.S3SecretKey == "" || c.S3Bucket == "" {
		return Config{}, fmt.Errorf("environment, database, Party and S3 configuration are required")
	}
	if c.AuthMode == "disabled" {
		if c.Environment != "local" {
			return Config{}, fmt.Errorf("authentication may only be disabled locally")
		}
	} else if c.AuthMode != "oidc" || c.OIDCIssuer == "" || c.OIDCAudience == "" {
		return Config{}, fmt.Errorf("complete OIDC configuration is required")
	}
	return c, nil
}
func value(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
