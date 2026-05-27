package main

import "testing"

func TestParsePluginConfigDefaults(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.LookbackDays != 90 {
		t.Fatalf("LookbackDays = %d, want 90", cfg.LookbackDays)
	}
	if cfg.MaxConcurrency != 4 {
		t.Fatalf("MaxConcurrency = %d, want 4", cfg.MaxConcurrency)
	}
	if cfg.APITimeoutSeconds != 60 {
		t.Fatalf("APITimeoutSeconds = %d, want 60", cfg.APITimeoutSeconds)
	}
	if cfg.TagBatchSize != 20 {
		t.Fatalf("TagBatchSize = %d, want 20", cfg.TagBatchSize)
	}
	if len(cfg.Accounts) != 0 || len(cfg.DefaultRegions) != 0 {
		t.Fatalf("unexpected default targets: %#v %#v", cfg.Accounts, cfg.DefaultRegions)
	}
}

func TestParsePluginConfigStructuredValues(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"accounts":            `[{"account_id":"123456789012","regions":[" us-east-1 ","us-east-1","us-west-2"],"role_arn":"arn:aws:iam::123456789012:role/readonly","external_id":"external","session_name":"session","tags":{"environment":"prod"}}]`,
		"default_regions":     `["us-east-1","us-east-1",""]`,
		"lookback_days":       "30",
		"policy_inputs":       `{"minimum_availability_zones":2}`,
		"policy_labels":       `{"team":"security"}`,
		"max_concurrency":     "8",
		"api_timeout_seconds": "15",
		"tag_batch_size":      "10",
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if got := cfg.Accounts[0].Regions; len(got) != 2 || got[0] != "us-east-1" || got[1] != "us-west-2" {
		t.Fatalf("regions = %#v, want cleaned unique list", got)
	}
	if got := cfg.DefaultRegions; len(got) != 1 || got[0] != "us-east-1" {
		t.Fatalf("default regions = %#v, want us-east-1", got)
	}
	if cfg.LookbackDays != 30 || cfg.MaxConcurrency != 8 || cfg.APITimeoutSeconds != 15 || cfg.TagBatchSize != 10 {
		t.Fatalf("numeric values not parsed: %#v", cfg)
	}
	if cfg.PolicyInputs["minimum_availability_zones"].(float64) != 2 {
		t.Fatalf("policy input not parsed: %#v", cfg.PolicyInputs)
	}
	if cfg.PolicyLabels["team"] != "security" {
		t.Fatalf("policy labels not parsed: %#v", cfg.PolicyLabels)
	}
}

func TestParsePluginConfigPolicyInputAlias(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{"policy_input": `{"x":true}`})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.PolicyInputs["x"] != true {
		t.Fatalf("policy_input alias not parsed: %#v", cfg.PolicyInputs)
	}
}

func TestParsePluginConfigValidation(t *testing.T) {
	tests := []map[string]string{
		{"lookback_days": "0"},
		{"lookback_days": "91"},
		{"lookback_days": "abc"},
		{"max_concurrency": "0"},
		{"max_concurrency": "33"},
		{"api_timeout_seconds": "-1"},
		{"tag_batch_size": "0"},
		{"tag_batch_size": "21"},
		{"accounts": `{"not":"array"}`},
		{"policy_inputs": `[]`},
		{"policy_labels": `[]`},
	}
	for _, raw := range tests {
		if _, err := parsePluginConfig(raw); err == nil {
			t.Fatalf("parsePluginConfig(%#v) succeeded, want error", raw)
		}
	}
}

func TestValidateResolvedDefaults(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.validateResolvedDefaults(""); err == nil {
		t.Fatal("validateResolvedDefaults succeeded without accounts, default regions, or SDK region")
	}
	if err := cfg.validateResolvedDefaults("us-east-1"); err != nil {
		t.Fatalf("validateResolvedDefaults with SDK region: %v", err)
	}
}
