package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
)

type fakeFactory struct {
	targets []ResolvedTarget
	clients AWSClientSet
}

func (f fakeFactory) ResolveTargets(context.Context, *PluginConfig) ([]ResolvedTarget, error) {
	return f.targets, nil
}

func (f fakeFactory) ClientsForTarget(context.Context, ResolvedTarget) (AWSClientSet, error) {
	return f.clients, nil
}

type fakeELBV2 struct {
	tagErr error

	loadBalancerMarkers []string
	listenerMarkers     []string
	targetGroupMarkers  []string
}

func (f *fakeELBV2) DescribeLoadBalancers(ctx context.Context, in *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	marker := aws.ToString(in.Marker)
	f.loadBalancerMarkers = append(f.loadBalancerMarkers, marker)
	if marker == "" {
		return &elbv2.DescribeLoadBalancersOutput{
			LoadBalancers: []elbv2types.LoadBalancer{testLoadBalancer("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc", "app-lb")},
			NextMarker:    aws.String("page-2"),
		}, nil
	}
	return &elbv2.DescribeLoadBalancersOutput{
		LoadBalancers: []elbv2types.LoadBalancer{testLoadBalancer("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/net-lb/def", "net-lb")},
	}, nil
}

func (f *fakeELBV2) DescribeListeners(ctx context.Context, in *elbv2.DescribeListenersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error) {
	f.listenerMarkers = append(f.listenerMarkers, aws.ToString(in.Marker))
	if aws.ToString(in.LoadBalancerArn) != "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc" {
		return &elbv2.DescribeListenersOutput{}, nil
	}
	return &elbv2.DescribeListenersOutput{
		Listeners: []elbv2types.Listener{
			{
				ListenerArn:     aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/app-lb/abc/listener1"),
				LoadBalancerArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc"),
				Protocol:        elbv2types.ProtocolEnumHttps,
				Port:            aws.Int32(443),
				SslPolicy:       aws.String("ELBSecurityPolicy-TLS13-1-2-2021-06"),
				Certificates: []elbv2types.Certificate{
					{CertificateArn: aws.String("arn:aws:acm:us-east-1:123456789012:certificate/cert1")},
				},
			},
		},
	}, nil
}

func (f *fakeELBV2) DescribeTargetGroups(ctx context.Context, in *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	marker := aws.ToString(in.Marker)
	f.targetGroupMarkers = append(f.targetGroupMarkers, marker)
	if marker == "" {
		return &elbv2.DescribeTargetGroupsOutput{
			TargetGroups: []elbv2types.TargetGroup{
				{
					TargetGroupArn:          aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app-tg/ghi"),
					TargetGroupName:         aws.String("app-tg"),
					Protocol:                elbv2types.ProtocolEnumHttp,
					Port:                    aws.Int32(80),
					HealthCheckProtocol:     elbv2types.ProtocolEnumHttp,
					HealthCheckPath:         aws.String("/healthz"),
					HealthyThresholdCount:   aws.Int32(3),
					UnhealthyThresholdCount: aws.Int32(2),
					LoadBalancerArns:        []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc"},
				},
			},
			NextMarker: aws.String("page-2"),
		}, nil
	}
	return &elbv2.DescribeTargetGroupsOutput{
		TargetGroups: []elbv2types.TargetGroup{
			{
				TargetGroupArn:  aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/error-tg/jkl"),
				TargetGroupName: aws.String("error-tg"),
				Protocol:        elbv2types.ProtocolEnumHttp,
				Port:            aws.Int32(8080),
			},
		},
	}, nil
}

func (f *fakeELBV2) DescribeTargetHealth(ctx context.Context, in *elbv2.DescribeTargetHealthInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error) {
	if aws.ToString(in.TargetGroupArn) == "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/error-tg/jkl" {
		return nil, errors.New("target health unavailable")
	}
	return &elbv2.DescribeTargetHealthOutput{
		TargetHealthDescriptions: []elbv2types.TargetHealthDescription{
			{
				Target:       &elbv2types.TargetDescription{Id: aws.String("i-1234567890abcdef0")},
				TargetHealth: &elbv2types.TargetHealth{State: elbv2types.TargetHealthStateEnumHealthy},
			},
		},
	}, nil
}

func (f *fakeELBV2) DescribeTags(ctx context.Context, in *elbv2.DescribeTagsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTagsOutput, error) {
	if f.tagErr != nil && len(in.ResourceArns) > 0 && in.ResourceArns[0] == "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/net-lb/def" {
		return nil, f.tagErr
	}
	return &elbv2.DescribeTagsOutput{
		TagDescriptions: []elbv2types.TagDescription{
			{
				ResourceArn: aws.String(in.ResourceArns[0]),
				Tags: []elbv2types.Tag{
					{Key: aws.String("owner"), Value: aws.String("platform-team")},
				},
			},
		},
	}, nil
}

type fakeCloudTrail struct {
	calls int
}

func (f *fakeCloudTrail) LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.calls++
	eventTime := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	return &cloudtrail.LookupEventsOutput{
		Events: []cloudtrailtypes.Event{
			{
				EventName:       aws.String("ModifyListener"),
				EventTime:       aws.Time(eventTime),
				CloudTrailEvent: aws.String(`{"userIdentity":{"arn":"arn:aws:iam::123456789012:role/admin"},"requestParameters":{"loadBalancerArn":"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc"}}`),
			},
			{EventName: aws.String("DescribeLoadBalancers")},
		},
	}, nil
}

type fakeSTS struct{}

func (fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
}

func TestCollectorCollectsAllRecordTypesAndAccumulatesErrors(t *testing.T) {
	elb := &fakeELBV2{tagErr: errors.New("access denied")}
	ct := &fakeCloudTrail{}
	cfg, err := parsePluginConfig(map[string]string{
		"accounts":            `[{"account_id":"123456789012","regions":["us-east-1"],"tags":{"environment":"prod"}}]`,
		"lookback_days":       "30",
		"policy_inputs":       `{"minimum_availability_zones":2}`,
		"max_concurrency":     "1",
		"api_timeout_seconds": "5",
	})
	if err != nil {
		t.Fatal(err)
	}
	collector := &Collector{
		Logger: hclog.NewNullLogger(),
		Config: cfg,
		Factory: fakeFactory{
			targets: []ResolvedTarget{{Account: AccountContext{AccountID: "123456789012", Tags: map[string]string{"environment": "prod"}}, Region: "us-east-1"}},
			clients: AWSClientSet{ELBV2: elb, CloudTrail: ct, STS: fakeSTS{}},
		},
		Now: func() time.Time { return time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC) },
	}

	result := collector.Collect(context.Background())
	if result.Err == nil {
		t.Fatal("Collect returned nil error, want accumulated tag/target-health errors")
	}
	if got, want := len(result.Records), 6; got != want {
		t.Fatalf("records = %d, want %d", got, want)
	}
	if got := elb.loadBalancerMarkers; len(got) != 2 || got[0] != "" || got[1] != "page-2" {
		t.Fatalf("load balancer pagination markers = %#v", got)
	}
	if got := elb.targetGroupMarkers; len(got) != 2 || got[0] != "" || got[1] != "page-2" {
		t.Fatalf("target group pagination markers = %#v", got)
	}

	byType := map[string][]*ResourceRecord{}
	for _, record := range result.Records {
		byType[record.Input.Resource.Type] = append(byType[record.Input.Resource.Type], record)
	}
	for _, typ := range []string{resourceTypeLoadBalancer, resourceTypeListener, resourceTypeTargetGroup, resourceTypeTargetHealth} {
		if len(byType[typ]) == 0 {
			t.Fatalf("no records of type %s", typ)
		}
	}

	lb := byType[resourceTypeLoadBalancer][0]
	if lb.Input.Config["load_balancer_arn"] == "" || lb.Input.Config["dns_name"] == "" || lb.Input.Config["state"] != "active" {
		t.Fatalf("load balancer config missing expected fields: %#v", lb.Input.Config)
	}
	if lb.Input.Tags["owner"] != "platform-team" {
		t.Fatalf("load balancer tags = %#v", lb.Input.Tags)
	}
	events := lb.Input.Dynamic["cloudtrail_events"].([]map[string]interface{})
	if len(events) != 1 || events[0]["event_name"] != "ModifyListener" || events[0]["user_identity_arn"] == "" {
		t.Fatalf("cloudtrail events = %#v", events)
	}
	if lb.Input.Collection.CollectionType != "config_dynamic" || lb.Input.Collection.LookbackWindow == nil {
		t.Fatalf("load balancer collection metadata = %#v", lb.Input.Collection)
	}

	listener := byType[resourceTypeListener][0]
	if listener.Input.Config["protocol"] != "HTTPS" || listener.Input.Config["port"] != float64(443) && listener.Input.Config["port"] != int32(443) {
		t.Fatalf("listener config = %#v", listener.Input.Config)
	}
	if listener.Input.Config["certificate_arn"] == "" || listener.Input.Config["ssl_policy"] == "" {
		t.Fatalf("listener TLS fields missing: %#v", listener.Input.Config)
	}
	if listener.Input.Tags["owner"] != "platform-team" {
		t.Fatalf("listener tags = %#v", listener.Input.Tags)
	}

	tg := byType[resourceTypeTargetGroup][0]
	if tg.Input.Config["health_check_path"] != "/healthz" || tg.Input.Config["healthy_threshold_count"] != int32(3) {
		t.Fatalf("target group config = %#v", tg.Input.Config)
	}
	if tg.Input.Tags["owner"] != "platform-team" {
		t.Fatalf("target group tags = %#v", tg.Input.Tags)
	}

	th := byType[resourceTypeTargetHealth][0]
	if th.Input.Config["target_id"] != "i-1234567890abcdef0" || th.Input.Config["target_health_state"] != "healthy" {
		t.Fatalf("target health config = %#v", th.Input.Config)
	}

	var sawTagError, sawHealthError bool
	for _, record := range result.Records {
		for _, collectionErr := range record.Input.Collection.Errors {
			if collectionErr.Scope == "tags" {
				sawTagError = true
			}
			if collectionErr.Scope == "describe_target_health" {
				sawHealthError = true
			}
		}
	}
	if !sawTagError || !sawHealthError {
		t.Fatalf("expected tag and target health errors in records, saw tag=%v health=%v", sawTagError, sawHealthError)
	}
}

func TestCollectorCollectsWithNonPositiveMaxConcurrency(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"accounts":            `[{"account_id":"123456789012","regions":["us-east-1"]}]`,
		"api_timeout_seconds": "5",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConcurrency = 0
	collector := &Collector{
		Logger: hclog.NewNullLogger(),
		Config: cfg,
		Factory: fakeFactory{
			targets: []ResolvedTarget{{Account: AccountContext{AccountID: "123456789012"}, Region: "us-east-1"}},
			clients: AWSClientSet{ELBV2: &fakeELBV2{}, CloudTrail: &fakeCloudTrail{}, STS: fakeSTS{}},
		},
		Now: func() time.Time { return time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC) },
	}

	done := make(chan CollectionResult, 1)
	go func() {
		done <- collector.Collect(context.Background())
	}()

	select {
	case result := <-done:
		if len(result.Records) == 0 {
			t.Fatalf("records = 0, want records")
		}
	case <-time.After(time.Second):
		t.Fatal("Collect hung with MaxConcurrency 0")
	}
}

func testLoadBalancer(arn string, name string) elbv2types.LoadBalancer {
	return elbv2types.LoadBalancer{
		LoadBalancerArn:  aws.String(arn),
		LoadBalancerName: aws.String(name),
		DNSName:          aws.String(name + "-123.us-east-1.elb.amazonaws.com"),
		Scheme:           elbv2types.LoadBalancerSchemeEnumInternetFacing,
		Type:             elbv2types.LoadBalancerTypeEnumApplication,
		State:            &elbv2types.LoadBalancerState{Code: elbv2types.LoadBalancerStateEnumActive},
		AvailabilityZones: []elbv2types.AvailabilityZone{
			{ZoneName: aws.String("us-east-1a")},
			{ZoneName: aws.String("us-east-1b")},
		},
	}
}
