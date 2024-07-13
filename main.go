package finder

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func main() {
	if err := _main(); err != nil {
		panic(err)
	}
}

func _main() error {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	svc := iam.NewFromConfig(cfg)
	var marker *string
	for {
		out, err := svc.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{
			Marker: marker,
			Filter: []types.EntityType{
				types.EntityTypeUser,
				types.EntityTypeGroup,
				types.EntityTypeRole,
				types.EntityTypeLocalManagedPolicy,
				types.EntityTypeAWSManagedPolicy,
			},
		})
		if err != nil {
			return err
		}
		for _, role := range out.RoleDetailList {
			for _, v := range role.RolePolicyList {
				if detect(aws.ToString(v.PolicyDocument)) {
					slog.Info("found", "role", *role.RoleName, "policy", *v.PolicyName)
				}
			}
		}
		for _, user := range out.UserDetailList {
			for _, v := range user.UserPolicyList {
				if detect(aws.ToString(v.PolicyDocument)) {
					slog.Info("found", "user", *user.UserName, "policy", *v.PolicyName)
				}
			}
		}
		for _, group := range out.GroupDetailList {
			for _, v := range group.GroupPolicyList {
				if detect(aws.ToString(v.PolicyDocument)) {
					slog.Info("found", "group", *group.GroupName, "policy", *v.PolicyName)
				}
			}
		}
		for _, policy := range out.Policies {
			versions := []string{}
			for _, v := range policy.PolicyVersionList {
				if detect(aws.ToString(v.Document)) {
					versions = append(versions, aws.ToString(v.VersionId))
				}
			}
			if len(versions) > 0 {
				slog.Info("found", "policy", *policy.PolicyName, "versions", versions, "attached", aws.ToInt32(policy.AttachmentCount))
			}
		}
		if out.Marker == nil {
			break
		}
		marker = out.Marker
	}
	return nil
}

func detect(s string) bool {
	d, _ := url.QueryUnescape(s)
	l := strings.ToLower(d)
	return strings.Contains(l, `"lambda:getfunction"`) && !strings.Contains(l, `"lambda:listtags"`)
}
