package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
)

type ELBV2API interface {
	DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
	DescribeListeners(context.Context, *elbv2.DescribeListenersInput, ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error)
	DescribeTargetGroups(context.Context, *elbv2.DescribeTargetGroupsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(context.Context, *elbv2.DescribeTargetHealthInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error)
	DescribeTags(context.Context, *elbv2.DescribeTagsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTagsOutput, error)
}

type CloudTrailAPI interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type AWSClientSet struct {
	ELBV2      ELBV2API
	CloudTrail CloudTrailAPI
	STS        STSAPI
}

type AWSClientFactory interface {
	ResolveTargets(context.Context, *PluginConfig) ([]ResolvedTarget, error)
	ClientsForTarget(context.Context, ResolvedTarget) (AWSClientSet, error)
}

type SDKClientFactory struct{}

type ResolvedTarget struct {
	Account AccountContext
	Region  string
	Config  aws.Config
}

type Collector struct {
	Logger  hclog.Logger
	Config  *PluginConfig
	Factory AWSClientFactory
	Now     func() time.Time
}

type CollectionResult struct {
	Records []*ResourceRecord
	Err     error
}

type targetCollection struct {
	loadBalancers []elbv2types.LoadBalancer
	listeners     map[string][]elbv2types.Listener
	targetGroups  []elbv2types.TargetGroup
	targetHealth  map[string][]elbv2types.TargetHealthDescription
	tags          map[string]map[string]string
	errors        map[string][]CollectionError
}

var cloudTrailEventNames = map[string]struct{}{
	"CreateListener": {},
	"ModifyListener": {},
	"DeleteListener": {},
	"CreateRule":     {},
	"ModifyRule":     {},
	"DeleteRule":     {},
}

func (f *SDKClientFactory) ResolveTargets(ctx context.Context, cfg *PluginConfig) ([]ResolvedTarget, error) {
	baseCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS SDK config: %w", err)
	}
	return resolveTargetsWithBaseConfig(ctx, cfg, baseCfg, cfg.APITimeoutSeconds, func(ctx context.Context, cfg aws.Config) (string, error) {
		identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return "", err
		}
		return aws.ToString(identity.Account), nil
	})
}

func resolveTargetsWithBaseConfig(ctx context.Context, cfg *PluginConfig, baseCfg aws.Config, timeoutSeconds int, resolveAccountID func(context.Context, aws.Config) (string, error)) ([]ResolvedTarget, error) {
	if err := cfg.validateResolvedDefaults(baseCfg.Region); err != nil {
		return nil, err
	}

	accounts := effectiveAccounts(cfg)
	var targets []ResolvedTarget
	var accumulated error
	for _, account := range accounts {
		regions := effectiveRegions(account, cfg, baseCfg.Region)
		if len(regions) == 0 {
			accumulated = errors.Join(accumulated, fmt.Errorf("account %q has no configured regions and AWS SDK default region is empty", account.AccountID))
			continue
		}
		for _, region := range regions {
			targetCfg := baseCfg.Copy()
			targetCfg.Region = region
			if account.RoleARN != "" {
				stsClient := sts.NewFromConfig(assumeRoleSourceConfig(baseCfg, region))
				provider := stscreds.NewAssumeRoleProvider(stsClient, account.RoleARN, func(options *stscreds.AssumeRoleOptions) {
					if account.ExternalID != "" {
						options.ExternalID = aws.String(account.ExternalID)
					}
					if account.SessionName != "" {
						options.RoleSessionName = account.SessionName
					}
				})
				targetCfg.Credentials = aws.NewCredentialsCache(provider)
			}

			targetCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			resolvedAccountID, err := resolveAccountID(targetCtx, targetCfg)
			cancel()
			actualAccountID := account.AccountID
			if err != nil {
				accumulated = errors.Join(accumulated, fmt.Errorf("resolve caller identity for account %q region %q: %w", account.AccountID, region, err))
				continue
			}
			if actualAccountID == "" {
				actualAccountID = resolvedAccountID
			} else if resolvedAccountID != "" && actualAccountID != resolvedAccountID {
				accumulated = errors.Join(accumulated, fmt.Errorf("configured account_id %q does not match resolved AWS account %q for region %q", actualAccountID, resolvedAccountID, region))
				continue
			}
			targets = append(targets, ResolvedTarget{
				Account: AccountContext{AccountID: actualAccountID, RoleARN: account.RoleARN, Tags: account.Tags},
				Region:  region,
				Config:  targetCfg,
			})
		}
	}
	return targets, accumulated
}

func assumeRoleSourceConfig(baseCfg aws.Config, region string) aws.Config {
	sourceCfg := baseCfg.Copy()
	sourceCfg.Region = region
	return sourceCfg
}

func effectiveAccounts(cfg *PluginConfig) []AccountConfig {
	if len(cfg.Accounts) == 0 {
		return []AccountConfig{{}}
	}
	return cfg.Accounts
}

func effectiveRegions(account AccountConfig, cfg *PluginConfig, sdkDefaultRegion string) []string {
	regions := account.Regions
	if len(regions) == 0 {
		regions = cfg.DefaultRegions
	}
	if len(regions) == 0 && strings.TrimSpace(sdkDefaultRegion) != "" {
		regions = []string{strings.TrimSpace(sdkDefaultRegion)}
	}
	return cleanStringList(regions)
}

func (f *SDKClientFactory) ClientsForTarget(ctx context.Context, target ResolvedTarget) (AWSClientSet, error) {
	return AWSClientSet{
		ELBV2:      elbv2.NewFromConfig(target.Config),
		CloudTrail: cloudtrail.NewFromConfig(target.Config),
		STS:        sts.NewFromConfig(target.Config),
	}, nil
}

func (c *Collector) Collect(ctx context.Context) CollectionResult {
	if c.Config == nil {
		return CollectionResult{Err: errors.New("collector config is nil")}
	}
	if c.Factory == nil {
		c.Factory = &SDKClientFactory{}
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	collectedAt := now()
	windowStart, windowEnd := c.Config.lookbackWindow(collectedAt)
	window := Window{Start: windowStart.UTC().Format(time.RFC3339), End: windowEnd.UTC().Format(time.RFC3339)}

	targets, err := c.Factory.ResolveTargets(ctx, c.Config)
	var accumulated error
	accumulated = errors.Join(accumulated, err)
	if len(targets) == 0 {
		return CollectionResult{Err: errors.Join(accumulated, errors.New("no AWS account/region targets resolved"))}
	}

	workerCount := c.Config.MaxConcurrency
	if workerCount > len(targets) {
		workerCount = len(targets)
	}
	jobs := make(chan ResolvedTarget)
	results := make(chan CollectionResult, len(targets))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				targetCtx, cancel := context.WithTimeout(ctx, time.Duration(c.Config.APITimeoutSeconds)*time.Second)
				results <- c.collectTarget(targetCtx, c.Factory, target, collectedAt, window, windowStart, windowEnd)
				cancel()
			}
		}()
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wg.Wait()
	close(results)

	records := make([]*ResourceRecord, 0)
	for result := range results {
		records = append(records, result.Records...)
		accumulated = errors.Join(accumulated, result.Err)
	}
	return CollectionResult{Records: records, Err: accumulated}
}

func (c *Collector) collectTarget(ctx context.Context, factory AWSClientFactory, target ResolvedTarget, collectedAt time.Time, window Window, windowStart time.Time, windowEnd time.Time) CollectionResult {
	clients, err := factory.ClientsForTarget(ctx, target)
	if err != nil {
		return CollectionResult{Err: fmt.Errorf("create AWS clients for account %q region %q: %w", target.Account.AccountID, target.Region, err)}
	}
	if target.Account.AccountID == "" && clients.STS != nil {
		if identity, idErr := clients.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); idErr == nil {
			target.Account.AccountID = aws.ToString(identity.Account)
		}
	}

	collected := c.collectELBV2(ctx, clients.ELBV2)
	var accumulated error
	accumulated = joinCollectionErrors(accumulated, allCollectionErrors(collected.errors))

	events, cloudTrailErr := c.collectCloudTrailEvents(ctx, clients.CloudTrail, windowStart, windowEnd)
	accumulated = errors.Join(accumulated, cloudTrailErr)
	if cloudTrailErr != nil {
		for _, lb := range collected.loadBalancers {
			arn := aws.ToString(lb.LoadBalancerArn)
			collected.errors[arn] = append(collected.errors[arn], CollectionError{Scope: "cloudtrail_events", Message: cloudTrailErr.Error()})
		}
	}

	eventsByLoadBalancer := matchEventsToLoadBalancers(events, collected.loadBalancers, collected.listeners)
	records := make([]*ResourceRecord, 0)
	for _, lb := range collected.loadBalancers {
		lbARN := aws.ToString(lb.LoadBalancerArn)
		lbErrors := collected.errors[lbARN]
		records = append(records, newLoadBalancerRecord(target.Account, target.Region, lb, collected.tags[lbARN], eventsByLoadBalancer[lbARN], lbErrors, c.Config.PolicyInputs, collectedAt, window))

		for _, listener := range collected.listeners[lbARN] {
			listenerARN := aws.ToString(listener.ListenerArn)
			records = append(records, newListenerRecord(target.Account, target.Region, listener, collected.errors[listenerARN], c.Config.PolicyInputs, collectedAt))
		}
	}

	for _, targetGroup := range collected.targetGroups {
		tgARN := aws.ToString(targetGroup.TargetGroupArn)
		records = append(records, newTargetGroupRecord(target.Account, target.Region, targetGroup, collected.errors[tgARN], c.Config.PolicyInputs, collectedAt))
		for _, health := range collected.targetHealth[tgARN] {
			records = append(records, newTargetHealthRecord(target.Account, target.Region, tgARN, health, collected.errors[tgARN], c.Config.PolicyInputs, collectedAt))
		}
	}
	return CollectionResult{Records: records, Err: accumulated}
}

func (c *Collector) collectELBV2(ctx context.Context, client ELBV2API) targetCollection {
	result := targetCollection{
		listeners:    map[string][]elbv2types.Listener{},
		targetHealth: map[string][]elbv2types.TargetHealthDescription{},
		tags:         map[string]map[string]string{},
		errors:       map[string][]CollectionError{},
	}
	if client == nil {
		result.errors["target"] = []CollectionError{{Scope: "elbv2_client", Message: "ELBV2 client is nil"}}
		return result
	}

	loadBalancers, lbErrors := c.collectLoadBalancers(ctx, client)
	result.loadBalancers = loadBalancers
	result.errors["target"] = append(result.errors["target"], lbErrors...)
	for _, lb := range loadBalancers {
		lbARN := aws.ToString(lb.LoadBalancerArn)
		result.errors[lbARN] = append(result.errors[lbARN], lbErrors...)
		tags, tagErr := c.collectTags(ctx, client, lbARN)
		if tagErr != nil {
			result.errors[lbARN] = append(result.errors[lbARN], CollectionError{Scope: "tags", Message: tagErr.Error()})
		}
		result.tags[lbARN] = tags
		listeners, listenerErrors := c.collectListeners(ctx, client, lbARN)
		result.listeners[lbARN] = listeners
		result.errors[lbARN] = append(result.errors[lbARN], listenerErrors...)
		for _, listener := range listeners {
			result.errors[aws.ToString(listener.ListenerArn)] = append(result.errors[aws.ToString(listener.ListenerArn)], listenerErrors...)
		}
	}

	targetGroups, tgErrors := c.collectTargetGroups(ctx, client)
	result.targetGroups = targetGroups
	result.errors["target"] = append(result.errors["target"], tgErrors...)
	for _, targetGroup := range targetGroups {
		tgARN := aws.ToString(targetGroup.TargetGroupArn)
		result.errors[tgARN] = append(result.errors[tgARN], tgErrors...)
		health, healthErrors := c.collectTargetHealth(ctx, client, tgARN)
		result.targetHealth[tgARN] = health
		result.errors[tgARN] = append(result.errors[tgARN], healthErrors...)
	}
	return result
}

func (c *Collector) collectLoadBalancers(ctx context.Context, client ELBV2API) ([]elbv2types.LoadBalancer, []CollectionError) {
	var marker *string
	var lbs []elbv2types.LoadBalancer
	var errs []CollectionError
	for {
		out, err := client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			errs = append(errs, CollectionError{Scope: "describe_load_balancers", Message: err.Error()})
			return lbs, errs
		}
		lbs = append(lbs, out.LoadBalancers...)
		if out.NextMarker == nil || aws.ToString(out.NextMarker) == "" {
			return lbs, errs
		}
		marker = out.NextMarker
	}
}

func (c *Collector) collectListeners(ctx context.Context, client ELBV2API, loadBalancerARN string) ([]elbv2types.Listener, []CollectionError) {
	var marker *string
	var listeners []elbv2types.Listener
	var errs []CollectionError
	for {
		out, err := client.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
			LoadBalancerArn: aws.String(loadBalancerARN),
			Marker:          marker,
		})
		if err != nil {
			errs = append(errs, CollectionError{Scope: "describe_listeners", Message: err.Error()})
			return listeners, errs
		}
		listeners = append(listeners, out.Listeners...)
		if out.NextMarker == nil || aws.ToString(out.NextMarker) == "" {
			return listeners, errs
		}
		marker = out.NextMarker
	}
}

func (c *Collector) collectTargetGroups(ctx context.Context, client ELBV2API) ([]elbv2types.TargetGroup, []CollectionError) {
	var marker *string
	var groups []elbv2types.TargetGroup
	var errs []CollectionError
	for {
		out, err := client.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{Marker: marker})
		if err != nil {
			errs = append(errs, CollectionError{Scope: "describe_target_groups", Message: err.Error()})
			return groups, errs
		}
		groups = append(groups, out.TargetGroups...)
		if out.NextMarker == nil || aws.ToString(out.NextMarker) == "" {
			return groups, errs
		}
		marker = out.NextMarker
	}
}

func (c *Collector) collectTargetHealth(ctx context.Context, client ELBV2API, targetGroupARN string) ([]elbv2types.TargetHealthDescription, []CollectionError) {
	out, err := client.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{TargetGroupArn: aws.String(targetGroupARN)})
	if err != nil {
		return nil, []CollectionError{{Scope: "describe_target_health", Message: err.Error()}}
	}
	return out.TargetHealthDescriptions, nil
}

func (c *Collector) collectTags(ctx context.Context, client ELBV2API, arn string) (map[string]string, error) {
	if arn == "" {
		return map[string]string{}, nil
	}
	out, err := client.DescribeTags(ctx, &elbv2.DescribeTagsInput{ResourceArns: []string{arn}})
	if err != nil {
		return map[string]string{}, fmt.Errorf("describe_tags %q: %w", arn, err)
	}
	tags := map[string]string{}
	for _, description := range out.TagDescriptions {
		for _, tag := range description.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
	}
	return tags, nil
}

func (c *Collector) collectCloudTrailEvents(ctx context.Context, client CloudTrailAPI, start time.Time, end time.Time) ([]CloudTrailEvent, error) {
	if client == nil {
		return nil, nil
	}
	var token *string
	var accumulated error
	events := make([]CloudTrailEvent, 0)
	for {
		out, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(start),
			EndTime:   aws.Time(end),
			LookupAttributes: []cloudtrailtypes.LookupAttribute{
				{
					AttributeKey:   cloudtrailtypes.LookupAttributeKeyEventSource,
					AttributeValue: aws.String("elasticloadbalancing.amazonaws.com"),
				},
			},
			NextToken:  token,
			MaxResults: aws.Int32(50),
		})
		if err != nil {
			accumulated = errors.Join(accumulated, fmt.Errorf("cloudtrail lookup elasticloadbalancing.amazonaws.com: %w", err))
			break
		}
		for _, event := range out.Events {
			name := aws.ToString(event.EventName)
			if _, ok := cloudTrailEventNames[name]; !ok {
				continue
			}
			raw := aws.ToString(event.CloudTrailEvent)
			events = append(events, CloudTrailEvent{
				EventName:       name,
				EventTime:       formatTime(event.EventTime),
				UserIdentityARN: userIdentityARN(raw),
				Raw:             raw,
				Resources:       cloudTrailResourceNames(event.Resources),
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		token = out.NextToken
	}
	return events, accumulated
}

func userIdentityARN(raw string) string {
	if raw == "" {
		return ""
	}
	var payload struct {
		UserIdentity struct {
			ARN string `json:"arn"`
		} `json:"userIdentity"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return ""
	}
	return payload.UserIdentity.ARN
}

func cloudTrailResourceNames(resources []cloudtrailtypes.Resource) []string {
	names := make([]string, 0, len(resources))
	for _, resource := range resources {
		if name := aws.ToString(resource.ResourceName); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func matchEventsToLoadBalancers(events []CloudTrailEvent, lbs []elbv2types.LoadBalancer, listeners map[string][]elbv2types.Listener) map[string][]CloudTrailEvent {
	result := map[string][]CloudTrailEvent{}
	listenerToLB := map[string]string{}
	lbIDs := map[string]string{}
	for _, lb := range lbs {
		lbARN := aws.ToString(lb.LoadBalancerArn)
		lbIDs[lbARN] = loadBalancerID(lbARN)
		for _, listener := range listeners[lbARN] {
			listenerToLB[aws.ToString(listener.ListenerArn)] = lbARN
		}
	}

	for _, event := range events {
		for lbARN, lbID := range lbIDs {
			if eventMentions(event, lbARN) || (lbID != "" && eventMentions(event, lbID)) {
				result[lbARN] = append(result[lbARN], event)
				continue
			}
			for listenerARN, listenerLBARN := range listenerToLB {
				if listenerLBARN == lbARN && eventMentions(event, listenerARN) {
					result[lbARN] = append(result[lbARN], event)
					break
				}
			}
		}
	}
	return result
}

func eventMentions(event CloudTrailEvent, value string) bool {
	if value == "" {
		return false
	}
	if strings.Contains(event.Raw, value) {
		return true
	}
	for _, resource := range event.Resources {
		if resource == value || strings.Contains(resource, value) {
			return true
		}
	}
	return false
}

func allCollectionErrors(errorMap map[string][]CollectionError) []CollectionError {
	var result []CollectionError
	for _, errs := range errorMap {
		result = append(result, errs...)
	}
	return result
}

func joinCollectionErrors(accumulated error, errs []CollectionError) error {
	for _, collectionErr := range errs {
		accumulated = errors.Join(accumulated, fmt.Errorf("%s: %s", collectionErr.Scope, collectionErr.Message))
	}
	return accumulated
}
