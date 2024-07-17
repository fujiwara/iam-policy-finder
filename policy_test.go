package finder_test

import (
	"encoding/json"
	"log"
	"testing"

	finder "github.com/fujiwara/iam-policy-finder"
	"github.com/google/go-cmp/cmp"
)

var fuzzyPolicyJSON = `{
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "1",
		"Effect": "Allow",
		"Action": "s3:ListBucket",
		"Principal": "*",
		"Resource": "arn:aws:s3:::example_bucket"
	}, {
		"Sid": "2",
		"Effect": "Deny",
		"Action": ["s3:DeleteObject", "s3:PutObject"],
		"Resource": ["arn:aws:s3:::example_bucket/*"],
		"Principal": {
			"AWS": "123456789012"
		},
		"Condition": {
			"ArnNotEquals": {
				"aws:PrincipalArn": "arn:aws:iam::444455556666:user/user-name"
			}
		}
	}]
}`

var normalizedPolicy = finder.Policy{
	Version: "2012-10-17",
	Statement: []finder.Statement{
		{
			"Sid":          "1",
			"Effect":       "Allow",
			"Action":       []string{"s3:ListBucket"},
			"Resource":     []string{"arn:aws:s3:::example_bucket"},
			"Principal":    "*",
			"Condition":    map[string]map[string][]string{},
			"NotAction":    []string{},
			"NotPrincipal": map[string][]string{},
		},
		{
			"Sid":      "2",
			"Effect":   "Deny",
			"Action":   []string{"s3:DeleteObject", "s3:PutObject"},
			"Resource": []string{"arn:aws:s3:::example_bucket/*"},
			"Principal": map[string][]string{
				"AWS": {"123456789012"},
			},
			"Condition": map[string]map[string][]string{
				"ArnNotEquals": {
					"aws:PrincipalArn": {"arn:aws:iam::444455556666:user/user-name"},
				},
			},
			"NotAction":    []string{},
			"NotPrincipal": map[string][]string{},
		},
	},
}

func TestParsePolicy(t *testing.T) {
	policy, err := finder.ParsePolicy([]byte(fuzzyPolicyJSON))
	if err != nil {
		log.Fatal(err)
	}
	if diff := cmp.Diff(normalizedPolicy, policy); diff != "" {
		t.Errorf("policy mismatch (-want +got):\n%s", diff)
	}
	b, _ := json.MarshalIndent(policy, "", "  ")
	t.Log(string(b))
}

var celExpressions = []struct {
	name     string
	expr     string
	expected bool
}{
	{
		name:     "Effect is Allow",
		expr:     `Statement.exists(s, s.Effect == "Allow")`,
		expected: true,
	},
	{
		name:     "Effect is Deny",
		expr:     `Statement.exists(s, s.Effect == "Deny")`,
		expected: true,
	},
	{
		name:     "Effect is XXX",
		expr:     `Statement.exists(s, s.Effect == "XXX")`,
		expected: false,
	},
	{
		name:     "All Effect is Allow",
		expr:     `Statement.all(s, s.Effect == "Allow")`,
		expected: false,
	},
	{
		name:     "Action is s3:ListBucket and Effect is Allow",
		expr:     `Statement.exists(s, s.Action.exists(a, a == "s3:ListBucket")) && Statement.exists(s, s.Effect == "Allow")`,
		expected: true,
	},
	{
		name:     "Resource is arn:aws:s3:::example_bucket",
		expr:     `Statement.exists(s, s.Resource.exists(r, r == "arn:aws:s3:::example_bucket"))`,
		expected: true,
	},
	{
		name:     "Action contains *Delete*",
		expr:     `Statement.exists(s, s.Action.exists(a, a.contains("Delete")))`,
		expected: true,
	},
	{
		name:     "Action matches *GetObject*",
		expr:     `Statement.exists(s, s.Action.exists(a, a.contains("GetObject")))`,
		expected: false,
	},
	{
		name:     "Principal is 123456789012",
		expr:     `Statement.exists(s, s.Principal != "*" && s.Principal["AWS"].exists(p, p == "123456789012"))`,
		expected: true,
	},
	{
		name:     "Principal is *",
		expr:     `Statement.exists(s, s.Principal == "*")`,
		expected: true,
	},
	{
		name:     "Resource is arn:aws:s3:::example_bucket/*",
		expr:     `Statement.exists(s, s.Resource.exists(r, r == "arn:aws:s3:::example_bucket/*"))`,
		expected: true,
	},
	{
		name:     `Resource is ["*"]`,
		expr:     `Statement.exists(s, s.Resource == ["*"])`,
		expected: false,
	},
}

func TestCelExpr(t *testing.T) {
	for _, tt := range celExpressions {
		t.Run(tt.name, func(t *testing.T) {
			prg, err := finder.ParseCel(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			out, _, err := prg.Eval(map[string]interface{}{"Statement": normalizedPolicy.Statement})
			if err != nil {
				t.Fatal(err)
			}
			if out.Value().(bool) != tt.expected {
				t.Errorf("unexpected result: got %v, want %v", out.Value(), tt.expected)
			}
		})
	}
}