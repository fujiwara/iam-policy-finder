package finder

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"

	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/cel-go/cel"
	"github.com/samber/lo"
)

type CLI struct {
	Dump                bool     `name:"dump" help:"dump found policy document"`
	Filter              []string `name:"filter" enum:"User,Group,Role,LocalManagedPolicy,AWSManagedPolicy" short:"f" help:"filter policy document(User, Group, Role, LocalManagedPolicy, AWSManagedPolicy)"`
	Expr                string   `arg:"" help:"CEL expression string or file name" required:"true"`
	Debug               bool     `name:"debug" help:"debug logging"`
	SkipEvaluationError bool     `name:"skip-evaluation-error" help:"skip evaluation error"`
	Progress            bool     `name:"progress" help:"show progress dots" negatable:"" default:"false"`

	prg     cel.Program
	scanned int
	found   int
}

func (c *CLI) prepare() error {
	if c.Expr == "" {
		return fmt.Errorf("expr is required")
	}
	if _, err := os.Stat(c.Expr); err == nil {
		b, err := os.ReadFile(c.Expr)
		if err != nil {
			return err
		}
		c.Expr = string(b)
		slog.Debug("expr", "expr", c.Expr)
	} else if !os.IsNotExist(err) {
		return err
	}

	prg, err := parseCel(c.Expr)
	if err != nil {
		return fmt.Errorf("failed to CEL program error: %w", err)
	}
	c.prg = prg
	return nil
}

func (c *CLI) detect(d *PolicyDetail) (bool, error) {
	c.showProgress()
	out, _, err := c.prg.Eval(d.Data())
	if err != nil {
		if c.SkipEvaluationError {
			slog.Warn("failed to CEL evaluation error", "name", d.Name, "error", err)
			return false, nil
		}
		return false, fmt.Errorf("failed to CEL evaluation error: %w, name: %s", err, d.Name)
	}
	switch out.Value().(type) {
	case bool:
		b := out.Value().(bool)
		if b {
			c.found++
		}
		return b, nil
	default:
		if c.SkipEvaluationError {
			slog.Warn("unexpected CEL evaluation result", "value", out.Value(), "name", d.Name)
			return false, nil
		}
		return false, fmt.Errorf("unexpected CEL evaluation result: %v, name: %s", out.Value(), d.Name)
	}
}

func (c *CLI) dump(d *PolicyDetail) {
	if c.Dump {
		fmt.Println(d.Document)
		// b, _ := json.MarshalIndent(d.Policy, "", "  ")
		// fmt.Println(string(b))
	}
}

var logLevel *slog.LevelVar

func init() {
	logLevel = new(slog.LevelVar)
	ops := slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &ops))
	slog.SetDefault(logger)
}

func Run(ctx context.Context) error {
	var c CLI
	kong.Parse(&c)

	defer func() {
		slog.Info("finished", "found", c.found, "scanned", c.scanned)
	}()

	if c.Debug {
		logLevel.Set(slog.LevelDebug)
	}
	if err := c.prepare(); err != nil {
		return err
	}
	filter := lo.Map(c.Filter, func(s string, _ int) types.EntityType {
		return types.EntityType(s)
	})

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	svc := iam.NewFromConfig(cfg)
	var marker *string
	slog.Info("starting scan", "expr", c.Expr, "filter", filter)
	for {
		out, err := svc.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{
			Marker:   marker,
			Filter:   filter,
			MaxItems: aws.Int32(100),
		})
		if err != nil {
			return err
		}
		for _, role := range out.RoleDetailList {
			for _, v := range role.RolePolicyList {
				slog.Debug("scanning", "role", *role.RoleName, "policy", *v.PolicyName)
				d := NewPolicyDetail(*v.PolicyName, *v.PolicyDocument)
				found, err := c.detect(d)
				if err != nil {
					return err
				}
				if found {
					slog.Info("found", "role", *role.RoleName, "policy", *v.PolicyName)
					c.dump(d)
				}
			}
		}
		for _, user := range out.UserDetailList {
			for _, v := range user.UserPolicyList {
				slog.Debug("scanning", "user", *user.UserName, "policy", *v.PolicyName)
				d := NewPolicyDetail(*v.PolicyName, *v.PolicyDocument)
				found, err := c.detect(d)
				if err != nil {
					return err
				}
				if found {
					slog.Info("found", "user", *user.UserName, "policy", *v.PolicyName)
					c.dump(d)
				}
			}
		}
		for _, group := range out.GroupDetailList {
			for _, v := range group.GroupPolicyList {
				slog.Debug("scanning", "group", *group.GroupName, "policy", *v.PolicyName)
				d := NewPolicyDetail(*v.PolicyName, *v.PolicyDocument)
				found, err := c.detect(d)
				if err != nil {
					return err
				}
				if found {
					slog.Info("found", "group", *group.GroupName, "policy", *v.PolicyName)
					c.dump(d)
				}
			}
		}
		for _, policy := range out.Policies {
			versions := []string{}
			var forDump *PolicyDetail
			for _, v := range policy.PolicyVersionList {
				slog.Debug("scanning", "policy", *policy.PolicyName, "version", *v.VersionId)
				d := NewPolicyDetail(*policy.PolicyName, *v.Document)
				found, err := c.detect(d)
				if err != nil {
					return err
				}
				if found {
					versions = append(versions, aws.ToString(v.VersionId))
					forDump = d
				}
			}
			if len(versions) > 0 {
				slog.Info("found", "policy", *policy.PolicyName, "versions", versions, "attached", aws.ToInt32(policy.AttachmentCount))
				c.dump(forDump)
			}
		}
		if out.Marker == nil {
			break
		}
		marker = out.Marker
	}
	return nil
}

func (c *CLI) showProgress() {
	c.scanned++
	if c.Progress {
		fmt.Fprint(os.Stderr, ".")
	}
}

func NewPolicyDetail(name, document string) *PolicyDetail {
	doc, _ := url.QueryUnescape(document)
	policy, err := ParsePolicy([]byte(doc))
	if err != nil {
		slog.Warn("failed to parse policy document", "name", name, "error", err)
	}
	return &PolicyDetail{
		Name:     name,
		Document: doc,
		Policy:   policy,
	}
}

type PolicyDetail struct {
	Name     string
	Document string
	Policy   Policy
}

func (d *PolicyDetail) Data() any {
	return map[string]any{
		"Name":      d.Name,
		"Document":  d.Document,
		"Statement": d.Policy.Statement,
		"Version":   d.Policy.Version,
	}
}
