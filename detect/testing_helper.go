package detect

import "cerberus/config"

//lint:ignore U1000 Test helper for SSRF-disabled test scenarios
func testConfig() *config.Config {
	cfg := &config.Config{}
	enableTestSSRF(cfg)
	return cfg
}

//lint:ignore U1000 Test helper for disabling SSRF protection in tests
func enableTestSSRF(cfg *config.Config) {
	cfg.Security.Webhooks.AllowLocalhost = true
	cfg.Security.Webhooks.AllowPrivateIPs = true
	cfg.Security.Actions.AllowLocalhost = true
	cfg.Security.Actions.AllowPrivateIPs = true
}
