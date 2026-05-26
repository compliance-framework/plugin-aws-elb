package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

func TestRegoFixturesEvaluateEachRecordShape(t *testing.T) {
	account := AccountContext{AccountID: "123456789012", Tags: map[string]string{"environment": "prod"}}
	collectedAt := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	window := Window{Start: "2026-02-13T12:00:00Z", End: "2026-05-14T12:00:00Z"}
	records := []*ResourceRecord{
		newLoadBalancerRecord(account, "us-east-1", testLoadBalancer("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc", "app-lb"), map[string]string{"owner": "platform"}, nil, nil, map[string]interface{}{"minimum_availability_zones": 2}, collectedAt, window),
		newListenerRecord(account, "us-east-1", elbv2types.Listener{
			ListenerArn:     aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/app-lb/abc/listener1"),
			LoadBalancerArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc"),
			Protocol:        elbv2types.ProtocolEnumHttps,
			Port:            aws.Int32(443),
			SslPolicy:       aws.String("ELBSecurityPolicy-TLS13-1-2-2021-06"),
			Certificates:    []elbv2types.Certificate{{CertificateArn: aws.String("arn:aws:acm:us-east-1:123456789012:certificate/cert1")}},
		}, nil, nil, collectedAt),
		newTargetGroupRecord(account, "us-east-1", elbv2types.TargetGroup{
			TargetGroupArn:          aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app-tg/ghi"),
			TargetGroupName:         aws.String("app-tg"),
			Protocol:                elbv2types.ProtocolEnumHttp,
			Port:                    aws.Int32(80),
			HealthCheckProtocol:     elbv2types.ProtocolEnumHttp,
			HealthCheckPath:         aws.String("/healthz"),
			HealthyThresholdCount:   aws.Int32(3),
			UnhealthyThresholdCount: aws.Int32(2),
			LoadBalancerArns:        []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc"},
		}, nil, nil, collectedAt),
		newTargetHealthRecord(account, "us-east-1", "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app-tg/ghi", elbv2types.TargetHealthDescription{
			Target:       &elbv2types.TargetDescription{Id: aws.String("i-1234567890abcdef0")},
			TargetHealth: &elbv2types.TargetHealth{State: elbv2types.TargetHealthStateEnumUnhealthy},
		}, nil, nil, collectedAt),
	}

	plugin := &CompliancePlugin{
		logger:       hclog.NewNullLogger(),
		parsedConfig: &PluginConfig{PolicyLabels: map[string]string{}, PolicyInputs: map[string]interface{}{}},
		policyData:   map[string]interface{}{},
	}
	for _, record := range records {
		policyDir := writeFixturePolicy(t, record.Input.Resource.Type)
		evidence, err := plugin.evaluateRecord(context.Background(), []string{policyDir}, record)
		if err != nil {
			t.Fatalf("evaluate %s: %v", record.Input.Resource.Type, err)
		}
		if len(evidence) != 1 {
			t.Fatalf("evidence count for %s = %d, want 1", record.Input.Resource.Type, len(evidence))
		}
		if evidence[0].Status == nil || evidence[0].Status.State != proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_NOT_SATISFIED {
			t.Fatalf("evidence status for %s = %#v, want not satisfied", record.Input.Resource.Type, evidence[0].Status)
		}
		if evidence[0].Labels["resource_type"] != record.Input.Resource.Type {
			t.Fatalf("evidence labels = %#v", evidence[0].Labels)
		}
	}
}

func writeFixturePolicy(t *testing.T, resourceType string) string {
	t.Helper()
	dir := t.TempDir()
	contents := fmt.Sprintf(`package compliance_framework.fixture_%s

title := "ELBv2 fixture"
description := "ELBv2 fixture policy"

violation[{
	"id": "fixture.%s",
	"title": "Fixture violation",
	"description": sprintf("resource %%s matched", [input.resource.type]),
	"remarks": "matched fixture resource",
}] if {
	input.schema_version == "v1"
	input.source == "aws-elbv2"
	input.resource.type == "%s"
}
`, sanitizedPackageSuffix(resourceType), resourceType, resourceType)
	if err := os.WriteFile(filepath.Join(dir, "fixture.rego"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func sanitizedPackageSuffix(value string) string {
	out := []byte(value)
	for i, b := range out {
		if b == '-' {
			out[i] = '_'
		}
	}
	return string(out)
}
