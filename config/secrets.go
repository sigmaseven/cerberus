package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/vault/api"
)

// SecretManager interface for retrieving secrets
type SecretManager interface {
	GetSecret(key string) (string, error)
	GetJWTSecret() (string, error)
	GetUsername() (string, error)
	GetPassword() (string, error)
}

// EnvSecretManager uses environment variables (default)
type EnvSecretManager struct{}

func (e *EnvSecretManager) GetSecret(key string) (string, error) {
	envKey := "CERBERUS_" + strings.ToUpper(key)
	value := os.Getenv(envKey)
	if value == "" {
		return "", fmt.Errorf("environment variable %s not set", envKey)
	}
	return value, nil
}

func (e *EnvSecretManager) GetJWTSecret() (string, error) {
	return e.GetSecret("AUTH_JWT_SECRET")
}

func (e *EnvSecretManager) GetUsername() (string, error) {
	return e.GetSecret("AUTH_USERNAME")
}

func (e *EnvSecretManager) GetPassword() (string, error) {
	return e.GetSecret("AUTH_PASSWORD")
}

// VaultSecretManager retrieves secrets from HashiCorp Vault
type VaultSecretManager struct {
	config *Config
	client *api.Client
}

func NewVaultSecretManager(config *Config) (*VaultSecretManager, error) {
	client, err := api.NewClient(&api.Config{
		Address: config.Secrets.Vault.Address,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	if config.Secrets.Vault.Token != "" {
		client.SetToken(config.Secrets.Vault.Token)
	} else {
		// Try to get token from environment
		token := os.Getenv("VAULT_TOKEN")
		if token != "" {
			client.SetToken(token)
		}
	}

	return &VaultSecretManager{
		config: config,
		client: client,
	}, nil
}

func (v *VaultSecretManager) GetSecret(key string) (string, error) {
	path := v.config.Secrets.Vault.Path
	if path == "" {
		path = "secret/cerberus"
	}

	secret, err := v.client.Logical().Read(path)
	if err != nil {
		return "", fmt.Errorf("failed to read from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("secret not found at path %s", path)
	}

	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in Vault secret", key)
	}

	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret value for key %s is not a string", key)
	}

	return strValue, nil
}

func (v *VaultSecretManager) GetJWTSecret() (string, error) {
	return v.GetSecret("jwt_secret")
}

func (v *VaultSecretManager) GetUsername() (string, error) {
	return v.GetSecret("username")
}

func (v *VaultSecretManager) GetPassword() (string, error) {
	return v.GetSecret("password")
}

// AWSSecretManager retrieves secrets from AWS Secrets Manager
type AWSSecretManager struct {
	config *Config
	client *secretsmanager.SecretsManager
}

func NewAWSSecretManager(config *Config) (*AWSSecretManager, error) {
	var sess *session.Session
	var err error

	if config.Secrets.AWS.AccessKey != "" && config.Secrets.AWS.SecretKey != "" {
		sess, err = session.NewSession(&aws.Config{
			Region: aws.String(config.Secrets.AWS.Region),
			Credentials: credentials.NewStaticCredentials(
				config.Secrets.AWS.AccessKey,
				config.Secrets.AWS.SecretKey,
				"",
			),
		})
	} else {
		sess, err = session.NewSession(&aws.Config{
			Region: aws.String(config.Secrets.AWS.Region),
		})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	client := secretsmanager.New(sess)
	return &AWSSecretManager{
		config: config,
		client: client,
	}, nil
}

func (a *AWSSecretManager) GetSecret(key string) (string, error) {
	secretID := a.config.Secrets.AWS.SecretID
	if secretID == "" {
		secretID = "cerberus/secrets"
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}

	result, err := a.client.GetSecretValue(input)
	if err != nil {
		return "", fmt.Errorf("failed to get secret from AWS: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal([]byte(*result.SecretString), &secrets); err != nil {
		return "", fmt.Errorf("failed to parse AWS secret JSON: %w", err)
	}

	value, ok := secrets[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in AWS secret", key)
	}

	return value, nil
}

func (a *AWSSecretManager) GetJWTSecret() (string, error) {
	return a.GetSecret("jwt_secret")
}

func (a *AWSSecretManager) GetUsername() (string, error) {
	return a.GetSecret("username")
}

func (a *AWSSecretManager) GetPassword() (string, error) {
	return a.GetSecret("password")
}

// NewSecretManager creates the appropriate secret manager based on configuration
func NewSecretManager(config *Config) (SecretManager, error) {
	provider := config.Secrets.Provider
	if provider == "" {
		provider = "env" // default to environment variables
	}

	switch provider {
	case "env":
		return &EnvSecretManager{}, nil
	case "vault":
		return NewVaultSecretManager(config)
	case "aws":
		return NewAWSSecretManager(config)
	case "gcp":
		// GCP implementation would go here
		return nil, fmt.Errorf("GCP secret manager not yet implemented")
	case "azure":
		// Azure implementation would go here
		return nil, fmt.Errorf("Azure secret manager not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported secret provider: %s", provider)
	}
}

// LoadSecrets loads secrets from the configured provider
func LoadSecrets(config *Config) error {
	manager, err := NewSecretManager(config)
	if err != nil {
		return fmt.Errorf("failed to create secret manager: %w", err)
	}

	// Load JWT secret
	jwtSecret, err := manager.GetJWTSecret()
	if err != nil {
		return fmt.Errorf("failed to load JWT secret: %w", err)
	}
	config.Auth.JWTSecret = jwtSecret

	// Load username and password for authentication
	username, err := manager.GetUsername()
	if err != nil {
		return fmt.Errorf("failed to load username: %w", err)
	}
	config.Auth.Username = username

	password, err := manager.GetPassword()
	if err != nil {
		return fmt.Errorf("failed to load password: %w", err)
	}
	config.Auth.Password = password

	return nil
}
