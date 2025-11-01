package main

import (
	"testing"

	"cerberus/config"

	"github.com/stretchr/testify/assert"
)

func TestInitLogger(t *testing.T) {
	logger, sugar, err := initLogger()

	assert.NoError(t, err)
	assert.NotNil(t, logger)
	assert.NotNil(t, sugar)
}

func TestInitConfig(t *testing.T) {
	// Initialize logger first
	_, sugar, err := initLogger()
	assert.NoError(t, err)

	// Test with default config
	cfg := initConfig(sugar)

	assert.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.MongoDB.URI)
}

func TestInitMongoDB_Disabled(t *testing.T) {
	_, sugar, err := initLogger()
	assert.NoError(t, err)

	cfg := &config.Config{}
	cfg.MongoDB.Enabled = false

	mongoDB := initMongoDB(cfg, sugar)
	assert.Nil(t, mongoDB)
}
