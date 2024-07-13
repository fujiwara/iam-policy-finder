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
	Dump   bool     `name:"dump" help:"dump found policy document"`
	Filter []string `name:"filter" enum:"User,Group,Role,LocalManagedPolicy,AWSManagedPolicy" short:"f" help:"filter policy document(User, Group, Role, LocalManagedPolicy, AWSManagedPolicy)"`
	Expr   string   `arg:"" help:"CEL expression string or file name" required:"true"`
	Debug  bool     `name:"debug" help:"debug logging"`

	prg cel.Program
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

	env, err := cel.NewEnv(
		cel.Variable("name", cel.StringType),
		cel.Variable("document", cel.StringType),
	)
	if err != nil {
		return err
	}
	ast, issues := env.Compile(c.Expr)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("failed to CEL compile error: %w", issues.Err())
	}
	c.prg, err = env.Program(ast)
	if err != nil {
		return fmt.Errorf("failed to CEL program error: %w", err)
	}
	return nil
}

func (c *CLI) detect(d *PolicyDetail) (bool, error) {
	out, _, err := c.prg.Eval(map[string]any{
		"name":     d.Name,
		"document": d.Document,
	})
	if err != nil {
		return false, err
	}
	switch out.Value().(type) {
	case bool:
		return out.Value().(bool), nil
	default:
		return false, fmt.Errorf("unexpected CEL evaluation result: %v", out.Value())
	}
}

func (c *CLI) dump(d *PolicyDetail) {
	if c.Dump {
		fmt.Println(d.Document)
	}
}

var logLevel *slog.LevelVar

func init() {
	logLevel = new(slog.LevelVar)
	ops := slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &ops))
	slog.SetDefault(logger)
}

func Run(ctx context.Context) error {
	var c CLI
	kong.Parse(&c)

	if c.Debug {
		logLevel.Set(slog.LevelDebug)
	}
	if err := c.prepare(); err != nil {
		return err
	}
	filter := lo.Map(c.Filter, func(s string, _ int) types.EntityType {
		return types.EntityType(s)
	})
	slog.Debug("filter", "filter", filter)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	svc := iam.NewFromConfig(cfg)
	var marker *string
	slog.Debug("starting scan")
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

func NewPolicyDetail(name, document string) *PolicyDetail {
	doc, _ := url.QueryUnescape(document)
	return &PolicyDetail{
		Name:     name,
		Document: doc,
	}
}

type PolicyDetail struct {
	Name     string
	Document string
}
