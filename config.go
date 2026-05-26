package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	defaultLookbackDays = 90
	// CloudTrail event history supports lookups for the previous 90 days.
	maxLookbackDays          = 90
	defaultAPITimeoutSeconds = 60
	defaultMaxConcurrency    = 4
	// Limit account/region fan-out to avoid excessive AWS API concurrency.
	maxMaxConcurrency       = 32
	defaultTagBatchSize     = 20
	configKeyAccounts       = "accounts"
	configKeyDefaultRegions = "default_regions"
	configKeyLookbackDays   = "lookback_days"
	configKeyPolicyInputs   = "policy_inputs"
	configKeyPolicyInput    = "policy_input"
	configKeyPolicyLabels   = "policy_labels"
	configKeyMaxConcurrency = "max_concurrency"
	configKeyAPITimeout     = "api_timeout_seconds"
	configKeyTagBatchSize   = "tag_batch_size"
)

type PluginConfig struct {
	Accounts       []AccountConfig
	DefaultRegions []string
	LookbackDays   int
	PolicyInputs   map[string]interface{}
	PolicyLabels   map[string]string
	MaxConcurrency int
	// APITimeoutSeconds is the per-target collection budget, not a per-call timeout.
	APITimeoutSeconds int
	TagBatchSize      int
}

type AccountConfig struct {
	AccountID   string            `json:"account_id"`
	Regions     []string          `json:"regions"`
	RoleARN     string            `json:"role_arn"`
	ExternalID  string            `json:"external_id"`
	SessionName string            `json:"session_name"`
	Tags        map[string]string `json:"tags"`
}

func parsePluginConfig(raw map[string]string) (*PluginConfig, error) {
	cfg := &PluginConfig{
		LookbackDays:      defaultLookbackDays,
		PolicyInputs:      map[string]interface{}{},
		PolicyLabels:      map[string]string{},
		MaxConcurrency:    defaultMaxConcurrency,
		APITimeoutSeconds: defaultAPITimeoutSeconds,
		TagBatchSize:      defaultTagBatchSize,
	}

	if v := strings.TrimSpace(raw[configKeyAccounts]); v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.Accounts); err != nil {
			return nil, fmt.Errorf("could not parse accounts: %w", err)
		}
	}

	if v := strings.TrimSpace(raw[configKeyDefaultRegions]); v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.DefaultRegions); err != nil {
			return nil, fmt.Errorf("could not parse default_regions: %w", err)
		}
		cfg.DefaultRegions = cleanStringList(cfg.DefaultRegions)
	}

	if v := strings.TrimSpace(raw[configKeyLookbackDays]); v != "" {
		i, err := strconv.Atoi(v)
		if err != nil || i <= 0 || i > maxLookbackDays {
			return nil, fmt.Errorf("lookback_days must be a positive integer no greater than %d", maxLookbackDays)
		}
		cfg.LookbackDays = i
	}

	policyInputsRaw := strings.TrimSpace(raw[configKeyPolicyInputs])
	policyInputsKey := configKeyPolicyInputs
	if policyInputsRaw == "" {
		policyInputsRaw = strings.TrimSpace(raw[configKeyPolicyInput])
		policyInputsKey = configKeyPolicyInput
	}
	if policyInputsRaw != "" {
		if err := json.Unmarshal([]byte(policyInputsRaw), &cfg.PolicyInputs); err != nil {
			return nil, fmt.Errorf("could not parse %s: %w", policyInputsKey, err)
		}
	}

	if v := strings.TrimSpace(raw[configKeyPolicyLabels]); v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.PolicyLabels); err != nil {
			return nil, fmt.Errorf("could not parse policy_labels: %w", err)
		}
	}

	if v := strings.TrimSpace(raw[configKeyMaxConcurrency]); v != "" {
		i, err := strconv.Atoi(v)
		if err != nil || i <= 0 || i > maxMaxConcurrency {
			return nil, fmt.Errorf("max_concurrency must be a positive integer no greater than %d", maxMaxConcurrency)
		}
		cfg.MaxConcurrency = i
	}

	if v := strings.TrimSpace(raw[configKeyAPITimeout]); v != "" {
		i, err := strconv.Atoi(v)
		if err != nil || i <= 0 {
			return nil, errors.New("api_timeout_seconds must be a positive integer")
		}
		cfg.APITimeoutSeconds = i
	}

	if v := strings.TrimSpace(raw[configKeyTagBatchSize]); v != "" {
		i, err := strconv.Atoi(v)
		if err != nil || i <= 0 || i > defaultTagBatchSize {
			return nil, fmt.Errorf("tag_batch_size must be a positive integer no greater than %d", defaultTagBatchSize)
		}
		cfg.TagBatchSize = i
	}

	for i := range cfg.Accounts {
		cfg.Accounts[i].Regions = cleanStringList(cfg.Accounts[i].Regions)
		if cfg.Accounts[i].Tags == nil {
			cfg.Accounts[i].Tags = map[string]string{}
		}
	}
	return cfg, nil
}

func cleanStringList(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func (c *PluginConfig) lookbackWindow(now time.Time) (time.Time, time.Time) {
	end := now.UTC()
	return end.AddDate(0, 0, -c.LookbackDays), end
}

func (c *PluginConfig) validateResolvedDefaults(defaultRegion string) error {
	if len(c.Accounts) == 0 && len(c.DefaultRegions) == 0 && strings.TrimSpace(defaultRegion) == "" {
		return errors.New("no accounts/default_regions configured and AWS SDK default region is empty")
	}
	return nil
}
