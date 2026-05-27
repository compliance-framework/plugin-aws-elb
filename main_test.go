package main

import (
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
)

func TestBuildSubjectTemplatesRegistersResourceComponents(t *testing.T) {
	templates := buildSubjectTemplates()
	if len(templates) != 4 {
		t.Fatalf("template count = %d, want 4", len(templates))
	}
	for _, template := range templates {
		if template.Type != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
			t.Fatalf("template %s type = %s, want %s", template.Name, template.Type, proto.SubjectType_SUBJECT_TYPE_COMPONENT)
		}
	}
}

func TestResourceRecordsUseComponentSubjectType(t *testing.T) {
	record := newResourceRecord(
		AccountContext{AccountID: "123456789012"},
		"us-east-1",
		ResourceIdentity{ID: "app/test/abc", ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/abc", Type: resourceTypeLoadBalancer},
		map[string]interface{}{"load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/abc"},
		nil,
		nil,
		nil,
		nil,
		time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC),
		nil,
		nil,
		"aws-elbv2-loadbalancer",
		"aws-elbv2-loadbalancer/123456789012/us-east-1/app/test/abc",
		"AWS ELBv2 Load Balancer [app/test/abc]",
	)
	if record.SubjectType != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
		t.Fatalf("record subject type = %s, want %s", record.SubjectType, proto.SubjectType_SUBJECT_TYPE_COMPONENT)
	}

	subjects := subjectsForRecord(record)
	if len(subjects) != 2 {
		t.Fatalf("subject count = %d, want 2", len(subjects))
	}
	if subjects[1].Type != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
		t.Fatalf("resource subject type = %s, want %s", subjects[1].Type, proto.SubjectType_SUBJECT_TYPE_COMPONENT)
	}
}
