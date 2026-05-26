package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-elbv2/internal"
)

const (
	sourceName      = "aws-elbv2"
	schemaVersionV1 = "v1"

	resourceTypeLoadBalancer = "loadbalancer"
	resourceTypeListener     = "listener"
	resourceTypeTargetGroup  = "target-group"
	resourceTypeTargetHealth = "target-health"
)

type AccountContext struct {
	AccountID string            `json:"account_id"`
	RoleARN   string            `json:"role_arn,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

type RegionContext struct {
	Name string `json:"name"`
}

type ResourceIdentity struct {
	ID   string `json:"id"`
	ARN  string `json:"arn"`
	Type string `json:"type"`
}

type Window struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type CollectionError struct {
	Scope   string `json:"scope"`
	Message string `json:"message"`
}

type CollectionMetadata struct {
	CollectedAt      string            `json:"collected_at"`
	CollectorVersion string            `json:"collector_version"`
	CollectionType   string            `json:"collection_type"`
	Errors           []CollectionError `json:"errors"`
	RawPayloadHashes map[string]string `json:"raw_payload_hashes,omitempty"`
	LookbackWindow   *Window           `json:"lookback_window,omitempty"`
}

type NormalizedInput struct {
	SchemaVersion string                 `json:"schema_version"`
	Source        string                 `json:"source"`
	Account       AccountContext         `json:"account"`
	Region        RegionContext          `json:"region"`
	Resource      ResourceIdentity       `json:"resource"`
	Config        map[string]interface{} `json:"config"`
	Dynamic       map[string]interface{} `json:"dynamic"`
	Tags          map[string]string      `json:"tags"`
	Collection    CollectionMetadata     `json:"collection"`
	PolicyInputs  map[string]interface{} `json:"policy_inputs"`
}

type ResourceRecord struct {
	Input       NormalizedInput
	Labels      map[string]string
	SubjectID   string
	SubjectType proto.SubjectType
	Title       string
	Raw         interface{}
}

type CloudTrailEvent struct {
	EventName       string   `json:"event_name"`
	EventTime       string   `json:"event_time"`
	UserIdentityARN string   `json:"user_identity_arn"`
	Raw             string   `json:"-"`
	Resources       []string `json:"-"`
}

func newLoadBalancerRecord(account AccountContext, region string, lb elbv2types.LoadBalancer, tags map[string]string, cloudTrailEvents []CloudTrailEvent, errors []CollectionError, policyInputs map[string]interface{}, collectedAt time.Time, window Window) *ResourceRecord {
	arn := aws.ToString(lb.LoadBalancerArn)
	id := loadBalancerID(arn)
	if id == "" {
		id = aws.ToString(lb.LoadBalancerName)
	}
	availabilityZones := make([]string, 0, len(lb.AvailabilityZones))
	for _, zone := range lb.AvailabilityZones {
		if name := aws.ToString(zone.ZoneName); name != "" {
			availabilityZones = append(availabilityZones, name)
		}
	}
	state := ""
	if lb.State != nil {
		state = string(lb.State.Code)
	}
	config := map[string]interface{}{
		"load_balancer_arn":  arn,
		"dns_name":           aws.ToString(lb.DNSName),
		"scheme":             string(lb.Scheme),
		"type":               string(lb.Type),
		"state":              state,
		"availability_zones": availabilityZones,
	}
	dynamic := map[string]interface{}{"cloudtrail_events": cloudTrailEventsToMaps(cloudTrailEvents)}
	record := newResourceRecord(account, region, ResourceIdentity{ID: id, ARN: arn, Type: resourceTypeLoadBalancer}, config, dynamic, tags, errors, policyInputs, collectedAt, &window, lb, "aws-elbv2-loadbalancer", fmt.Sprintf("aws-elbv2-loadbalancer/%s/%s/%s", account.AccountID, region, id), "AWS ELBv2 Load Balancer ["+id+"]")
	return &record
}

func newListenerRecord(account AccountContext, region string, listener elbv2types.Listener, tags map[string]string, errors []CollectionError, policyInputs map[string]interface{}, collectedAt time.Time) *ResourceRecord {
	arn := aws.ToString(listener.ListenerArn)
	id := arnResourcePart(arn)
	config := map[string]interface{}{
		"listener_arn":      arn,
		"load_balancer_arn": aws.ToString(listener.LoadBalancerArn),
		"protocol":          string(listener.Protocol),
		"port":              aws.ToInt32(listener.Port),
		"ssl_policy":        aws.ToString(listener.SslPolicy),
		"certificate_arn":   firstCertificateARN(listener.Certificates),
	}
	record := newResourceRecord(account, region, ResourceIdentity{ID: id, ARN: arn, Type: resourceTypeListener}, config, nil, tags, errors, policyInputs, collectedAt, nil, listener, "aws-elbv2-listener", fmt.Sprintf("aws-elbv2-listener/%s/%s/%s", account.AccountID, region, id), "AWS ELBv2 Listener ["+id+"]")
	return &record
}

func newTargetGroupRecord(account AccountContext, region string, targetGroup elbv2types.TargetGroup, tags map[string]string, errors []CollectionError, policyInputs map[string]interface{}, collectedAt time.Time) *ResourceRecord {
	arn := aws.ToString(targetGroup.TargetGroupArn)
	id := targetGroupID(arn)
	if id == "" {
		id = aws.ToString(targetGroup.TargetGroupName)
	}
	config := map[string]interface{}{
		"target_group_arn":          arn,
		"load_balancer_arn":         firstString(targetGroup.LoadBalancerArns),
		"protocol":                  string(targetGroup.Protocol),
		"port":                      aws.ToInt32(targetGroup.Port),
		"health_check_protocol":     string(targetGroup.HealthCheckProtocol),
		"health_check_path":         aws.ToString(targetGroup.HealthCheckPath),
		"healthy_threshold_count":   aws.ToInt32(targetGroup.HealthyThresholdCount),
		"unhealthy_threshold_count": aws.ToInt32(targetGroup.UnhealthyThresholdCount),
	}
	record := newResourceRecord(account, region, ResourceIdentity{ID: id, ARN: arn, Type: resourceTypeTargetGroup}, config, nil, tags, errors, policyInputs, collectedAt, nil, targetGroup, "aws-elbv2-target-group", fmt.Sprintf("aws-elbv2-target-group/%s/%s/%s", account.AccountID, region, id), "AWS ELBv2 Target Group ["+id+"]")
	return &record
}

func newTargetHealthRecord(account AccountContext, region string, targetGroupARN string, targetHealth elbv2types.TargetHealthDescription, errors []CollectionError, policyInputs map[string]interface{}, collectedAt time.Time) *ResourceRecord {
	targetID := ""
	if targetHealth.Target != nil {
		targetID = aws.ToString(targetHealth.Target.Id)
	}
	id := targetGroupID(targetGroupARN) + "/" + targetID
	state := ""
	if targetHealth.TargetHealth != nil {
		state = string(targetHealth.TargetHealth.State)
	}
	config := map[string]interface{}{
		"target_group_arn":    targetGroupARN,
		"target_id":           targetID,
		"target_health_state": state,
	}
	record := newResourceRecord(account, region, ResourceIdentity{ID: id, ARN: targetGroupARN, Type: resourceTypeTargetHealth}, config, nil, nil, errors, policyInputs, collectedAt, nil, targetHealth, "aws-elbv2-target-health", fmt.Sprintf("aws-elbv2-target-health/%s/%s/%s", account.AccountID, region, id), "AWS ELBv2 Target Health ["+id+"]")
	return &record
}

func newResourceRecord(account AccountContext, region string, resource ResourceIdentity, config map[string]interface{}, dynamic map[string]interface{}, tags map[string]string, errors []CollectionError, policyInputs map[string]interface{}, collectedAt time.Time, window *Window, raw interface{}, subjectName string, subjectID string, title string) ResourceRecord {
	if dynamic == nil {
		dynamic = map[string]interface{}{}
	}
	if tags == nil {
		tags = map[string]string{}
	}
	if errors == nil {
		errors = []CollectionError{}
	}
	hashes := map[string]string{}
	if raw != nil {
		hashes["primary"] = hashPayload(raw)
	}
	collection := CollectionMetadata{
		CollectedAt:      collectedAt.UTC().Format(time.RFC3339),
		CollectorVersion: sourceName,
		CollectionType:   "config",
		Errors:           errors,
		RawPayloadHashes: hashes,
	}
	if window != nil && (window.Start != "" || window.End != "") {
		collection.CollectionType = "config_dynamic"
		collection.LookbackWindow = window
	}
	input := NormalizedInput{
		SchemaVersion: schemaVersionV1,
		Source:        sourceName,
		Account:       account,
		Region:        RegionContext{Name: region},
		Resource:      resource,
		Config:        config,
		Dynamic:       dynamic,
		Tags:          tags,
		Collection:    collection,
		PolicyInputs:  clonePolicyInputs(policyInputs),
	}
	labels := map[string]string{
		"provider":      "aws",
		"type":          "elbv2",
		"subject":       subjectName,
		"account_id":    account.AccountID,
		"region":        region,
		"resource_id":   resource.ID,
		"resource_arn":  resource.ARN,
		"resource_type": resource.Type,
	}
	for key, value := range account.Tags {
		labels["account_tag_"+key] = value
	}
	return ResourceRecord{
		Input:       input,
		Labels:      labels,
		SubjectID:   subjectID,
		SubjectType: proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
		Title:       title,
		Raw:         raw,
	}
}

func clonePolicyInputs(input map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func firstCertificateARN(certificates []elbv2types.Certificate) string {
	if len(certificates) == 0 {
		return ""
	}
	return aws.ToString(certificates[0].CertificateArn)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func loadBalancerID(arn string) string {
	return strings.TrimPrefix(arnResourcePart(arn), "loadbalancer/")
}

func targetGroupID(arn string) string {
	return strings.TrimPrefix(arnResourcePart(arn), "targetgroup/")
}

func arnResourcePart(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 {
		return parts[5]
	}
	return arn
}

func formatTime(t *time.Time) string {
	return internal.FormatTime(t)
}

func hashPayload(payload interface{}) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cloudTrailEventsToMaps(events []CloudTrailEvent) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		result = append(result, map[string]interface{}{
			"event_name":        event.EventName,
			"event_time":        event.EventTime,
			"user_identity_arn": event.UserIdentityARN,
		})
	}
	return result
}

func defaultActors() []*proto.OriginActor {
	return []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  internal.StringAddressed("reference"),
					Text: internal.StringAddressed("The Continuous Compliance Framework"),
				},
			},
		},
		{
			Title: "Continuous Compliance Framework - AWS ELBv2 Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-aws-elbv2",
					Rel:  internal.StringAddressed("reference"),
					Text: internal.StringAddressed("AWS ELBv2 Plugin"),
				},
			},
		},
	}
}

func defaultComponents() []*proto.Component {
	return []*proto.Component{
		{
			Identifier:  "common-components/aws-elbv2",
			Type:        "service",
			Title:       "AWS Elastic Load Balancing v2",
			Description: "AWS Elastic Load Balancing v2 distributes traffic across targets using application, network, or gateway load balancers.",
			Purpose:     "Provides load balancing infrastructure evaluated for target health, TLS endpoint, and edge endpoint inventory evidence.",
		},
	}
}

func inventoryForRecord(record ResourceRecord) []*proto.InventoryItem {
	return []*proto.InventoryItem{
		{
			Identifier:  record.SubjectID,
			Type:        "aws-elbv2-" + record.Input.Resource.Type,
			Title:       record.Title,
			Description: "AWS ELBv2 resource evaluated by the AWS ELBv2 plugin.",
			Props: []*proto.Property{
				{Name: "account_id", Value: record.Input.Account.AccountID},
				{Name: "region", Value: record.Input.Region.Name},
				{Name: "resource_id", Value: record.Input.Resource.ID},
				{Name: "resource_arn", Value: record.Input.Resource.ARN},
				{Name: "resource_type", Value: record.Input.Resource.Type},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{Identifier: "common-components/aws-elbv2"},
			},
		},
	}
}

func subjectsForRecord(record ResourceRecord) []*proto.Subject {
	return []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/aws-elbv2",
		},
		{
			Type:       record.SubjectType,
			Identifier: record.SubjectID,
		},
	}
}
