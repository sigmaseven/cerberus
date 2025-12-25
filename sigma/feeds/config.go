package feeds

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads feed configuration from a YAML file
func LoadConfig(configPath string) (*FeedConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config FeedConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	// Validate feeds
	for i := range config.Feeds {
		if err := config.Feeds[i].Validate(); err != nil {
			return nil, fmt.Errorf("invalid feed %s: %w", config.Feeds[i].ID, err)
		}
	}

	return &config, nil
}

// LoadTemplates loads feed templates from a YAML file
func LoadTemplates(templatePath string) ([]FeedTemplate, error) {
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	var templates struct {
		Templates []FeedTemplate `yaml:"templates"`
	}

	if err := yaml.Unmarshal(data, &templates); err != nil {
		return nil, fmt.Errorf("failed to parse template YAML: %w", err)
	}

	return templates.Templates, nil
}

// CreateFeedFromTemplate creates a feed from a template
func CreateFeedFromTemplate(template *FeedTemplate, id string, name string, enabled bool) *RuleFeed {
	feed := &RuleFeed{
		ID:           id,
		Name:         name,
		Description:  template.Description,
		Type:         template.Type,
		URL:          template.URL,
		Branch:       template.Branch,
		Enabled:      enabled,
		IncludePaths: template.IncludePaths,
		ExcludePaths: template.ExcludePaths,
		Priority:     template.RecommendedPriority,
		Tags:         template.Tags,
	}

	return feed
}
