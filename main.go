package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-elbv2/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

const (
	behaviorLoadBalancer = "loadbalancer"
	behaviorListener     = "listener"
	behaviorTargetGroup  = "target-group"
	behaviorTargetHealth = "target-health"
)

var defaultPolicyBehaviors = map[string][]string{
	"plugin-aws-elbv2-loadbalancer-policies":  {behaviorLoadBalancer},
	"plugin-aws-elbv2-listener-policies":      {behaviorListener},
	"plugin-aws-elbv2-target-group-policies":  {behaviorTargetGroup},
	"plugin-aws-elbv2-target-health-policies": {behaviorTargetHealth},
}

func requestWithDefaultPolicyBehavior(req *proto.EvalRequest) *proto.EvalRequest {
	if req == nil {
		return nil
	}
	return req.
		WithDefaultPolicyBehavior(defaultPolicyBehaviors).
		WithUndefinedMappedTo([]string{behaviorLoadBalancer})
}

type CompliancePlugin struct {
	logger       hclog.Logger
	mu           sync.RWMutex
	rawConfig    map[string]string
	parsedConfig *PluginConfig
	factory      AWSClientFactory
	policyData   map[string]interface{}
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	parsed, err := parsePluginConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rawConfig = cloneStringMap(req.GetConfig())
	l.parsedConfig = parsed
	if req.GetPolicyData() != nil {
		l.policyData = clonePolicyInputs(req.GetPolicyData().AsMap())
	} else {
		l.policyData = clonePolicyInputs(parsed.PolicyInputs)
	}
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.logger, req, apiHelper, buildSubjectTemplates())
}

func (l *CompliancePlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()
	if req == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("eval request is nil")
	}

	l.mu.Lock()
	if l.parsedConfig == nil {
		parsed, err := parsePluginConfig(l.rawConfig)
		if err != nil {
			l.mu.Unlock()
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
		}
		l.parsedConfig = parsed
	}
	if l.policyData == nil {
		l.policyData = clonePolicyInputs(l.parsedConfig.PolicyInputs)
	}
	parsedConfig := l.parsedConfig
	policyData := clonePolicyInputs(l.policyData)
	policyLabels := cloneStringMap(parsedConfig.PolicyLabels)
	l.mu.Unlock()

	policyRequest := requestWithDefaultPolicyBehavior(req)
	pathsByType := map[string][]string{
		resourceTypeLoadBalancer: policyRequest.PolicyPathsForBehavior(behaviorLoadBalancer),
		resourceTypeListener:     policyRequest.PolicyPathsForBehavior(behaviorListener),
		resourceTypeTargetGroup:  policyRequest.PolicyPathsForBehavior(behaviorTargetGroup),
		resourceTypeTargetHealth: policyRequest.PolicyPathsForBehavior(behaviorTargetHealth),
	}

	collector := &Collector{Logger: l.logger.Named("collector"), Config: parsedConfig, Factory: l.factory}
	result := collector.Collect(ctx)

	evidences := make([]*proto.Evidence, 0)
	var accumulated error
	accumulated = errors.Join(accumulated, result.Err)
	for _, record := range result.Records {
		recordEvidence, err := l.evaluateRecord(ctx, pathsByType[record.Input.Resource.Type], record, policyLabels, policyData)
		evidences = append(evidences, recordEvidence...)
		accumulated = errors.Join(accumulated, err)
	}

	if len(evidences) > 0 {
		if createErr := apiHelper.CreateEvidence(ctx, evidences); createErr != nil {
			accumulated = errors.Join(accumulated, createErr)
		}
	}
	if accumulated != nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, accumulated
	}
	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func (l *CompliancePlugin) evaluateRecord(ctx context.Context, policyPaths []string, record *ResourceRecord, policyLabels map[string]string, policyData map[string]interface{}) ([]*proto.Evidence, error) {
	var accumulated error
	evidences := make([]*proto.Evidence, 0)
	labels := internal.MergeMaps(policyLabels, record.Labels)
	activities := []*proto.Activity{{
		Title:       "Collect AWS ELBv2 evidence",
		Description: "Collected read-only Elastic Load Balancing v2 configuration and CloudTrail data for policy evaluation.",
		Steps: []*proto.Step{
			{Title: "Fetch read-only AWS data", Description: "Used AWS SDK read-only ELBv2 and CloudTrail APIs."},
			{Title: "Normalize Rego input", Description: "Converted SDK payloads into the documented aws-elbv2 Rego input schema."},
		},
	}}
	input, err := regoInputMap(record.Input)
	if err != nil {
		return nil, err
	}
	for _, policyPath := range policyPaths {
		processor := policyManager.NewPolicyProcessor(
			l.logger, labels, subjectsForRecord(*record), defaultComponents(),
			inventoryForRecord(*record), defaultActors(), activities, policyData,
		)
		evidence, perr := processor.GenerateResults(ctx, policyPath, input)
		evidences = append(evidences, evidence...)
		if perr != nil {
			accumulated = errors.Join(accumulated, perr)
		}
	}
	return evidences, accumulated
}

func cloneStringMap(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func buildSubjectTemplates() []*proto.SubjectTemplate {
	return []*proto.SubjectTemplate{
		subjectTemplate("aws-elbv2-loadbalancer", "ELBv2 load balancer {{ .resource_id }} in {{ .account_id }}/{{ .region }}", "Elastic Load Balancing v2 load balancer {{ .resource_id }}.", "Represents an ELBv2 load balancer evaluated for compliance posture.", "Load balancer ID"),
		subjectTemplate("aws-elbv2-listener", "ELBv2 listener {{ .resource_id }} in {{ .account_id }}/{{ .region }}", "Elastic Load Balancing v2 listener {{ .resource_id }}.", "Represents an ELBv2 listener evaluated for TLS endpoint posture.", "Listener resource ID"),
		subjectTemplate("aws-elbv2-target-group", "ELBv2 target group {{ .resource_id }} in {{ .account_id }}/{{ .region }}", "Elastic Load Balancing v2 target group {{ .resource_id }}.", "Represents an ELBv2 target group evaluated for health-check posture.", "Target group ID"),
		subjectTemplate("aws-elbv2-target-health", "ELBv2 target health {{ .resource_id }} in {{ .account_id }}/{{ .region }}", "Elastic Load Balancing v2 target health {{ .resource_id }}.", "Represents an ELBv2 target health description evaluated for availability posture.", "Target health ID"),
	}
}

func subjectTemplate(name string, title string, description string, purpose string, resourceDescription string) *proto.SubjectTemplate {
	return &proto.SubjectTemplate{
		Name:                name,
		Type:                proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
		TitleTemplate:       title,
		DescriptionTemplate: description,
		PurposeTemplate:     purpose,
		IdentityLabelKeys:   []string{"account_id", "region", "resource_id"},
		LabelSchema: []*proto.SubjectLabelSchema{
			{Key: "account_id", Description: "AWS account ID"},
			{Key: "region", Description: "AWS region"},
			{Key: "resource_id", Description: resourceDescription},
			{Key: "resource_arn", Description: "AWS resource ARN"},
			{Key: "resource_type", Description: "ELBv2 normalized resource type"},
		},
	}
}

func regoInputMap(input NormalizedInput) (map[string]interface{}, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal Rego input: %w", err)
	}
	out := map[string]interface{}{}
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, fmt.Errorf("unmarshal Rego input: %w", err)
	}
	return out, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{Level: hclog.Debug, JSONFormat: true})
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins:         map[string]goplugin.Plugin{"runner": &runner.RunnerV2GRPCPlugin{Impl: &CompliancePlugin{logger: logger}}},
		GRPCServer:      goplugin.DefaultGRPCServer,
	})
}
