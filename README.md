# iam-policy-finder

iam-policy-finder is a tool to find AWS IAM policies that matches the given condition.

This is useful when you want to find policies that have specific permissions.

## Usage

```
Usage: iam-policy-finder <expr> [flags]

Arguments:
  <expr>    CEL expression string or file name

Flags:
  -h, --help                     Show context-sensitive help.
      --dump                     dump found policy document
  -f, --filter=FILTER,...        filter policy document(User, Group, Role, LocalManagedPolicy, AWSManagedPolicy)
      --debug                    debug logging
      --skip-evaluation-error    skip evaluation error
      --[no-]progress            show progress dots
```

### Examples

iam-policy-finder finds policies that matches the given condition. The condition is written in [CEL](https://cel.dev/) expression.

The first argument is a CEL expression string or file name.

- `Name` is the name of the policy.
- `Document` is the policy document JSON string.
- `Version` is the policy version. (e.g. `"2012-10-17"`)
- `Statement` is the list of normalized statements.
  - `Statement[].Sid` is the statement ID. (e.g. `"Sid-1"`)
  - `Statement[].Effect` is the effect of the statement. (e.g. `"Allow"`, `"Deny"`)
  - `Statement[].Action` is the list of actions in the statement. (e.g. `["s3:GetObject", "s3:PutObject"]`) If the action is `"s3:*"`, it is normalized to `["s3:*"]`.
  - `Statement[].Resource` is the list of resources in the statement. (e.g. `["arn:aws:s3:::my-bucket/*"]`, Not a string) If the resource is `"*"`, it is normalized to `["*"]`.
  - `Statement[].Condition` is the condition object in the statement. (e.g. `{"StringEquals": {"s3:x-amz-acl": "public-read"}}`)
  - `Statement[].Principal` is the principal object or a string in the statement. (e.g. `{"AWS": "arn:aws:iam::123456789012:root"}` or `"*"`)

#### Example of Name is "AmazonEC2FullAccess".

```console
$ iam-policy-finder 'Name == "AmazonEC2FullAccess"'
time=2024-07-14T01:27:14.568+09:00 level=INFO msg=found policy=AmazonEC2FullAccess versions="[v5 v4 v3 v2 v1]" attached=2
```

#### Example of Document matches `"lambda:GetFunction"` and does not match `"lambda:ListTags"`.

```cel
// expr.cel
Document.matches('"lambda:[Gg]et[Ff]unction"') && !Document.matches('"lambda:[Ll]ist[Tt]ags"')
```

```console
$ iam-policy-finder expr.cel
time=2024-07-14T01:25:33.029+09:00 level=INFO msg=found policy=SecretsManagerReadWrite versions="[v5 v4 v3 v2 v1]" attached=2
```

#### Example of finding by normalized policy.

`Statement` is a list of normalized statement objects. So, you can use `Statement.exists` to find any statement that matches the condition.

Statement.Action contains `"s3:*"` and Statement.Effect is `"Allow"`.

```cel
Statement.exists(s, s.Action.exists(a, a == "s3:*") && s.Effect == "Allow")
```

Principal contains AWS account `"123456789012"`.

```cel
Statement.exists(s, s.Principal != "*" && s.Principal["AWS"].exists(p, p == "123456789012"))
```

#### Example of Normalized Policy JSON

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:ListBucket"
      ],
      "Condition": {},
      "Effect": "Allow",
      "NotAction": [],
      "NotPrincipal": {},
      "Principal": "*",
      "Resource": [
        "arn:aws:s3:::example_bucket"
      ],
      "Sid": "1"
    },
    {
      "Action": [
        "s3:DeleteObject",
        "s3:PutObject"
      ],
      "Condition": {
        "ArnNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::444455556666:user/user-name"
          ]
        }
      },
      "Effect": "Deny",
      "NotAction": [],
      "NotPrincipal": {},
      "Principal": {
        "AWS": [
          "123456789012"
        ]
      },
      "Resource": [
        "arn:aws:s3:::example_bucket/*"
      ],
      "Sid": "2"
    }
  ]
}
```

### Options

#### `--filter` (`-f`)

Filters the account authorization type. The default is to search all types.

"User", "Group", "Role", "LocalManagedPolicy" and "AWSManagedPolicy" are allowed.

#### `--dump`

Dumps the found policy document JSON to STDOUT.

#### `--skip-evaluation-error`

Skips the evaluation error. If the evaluation error occurs, the policy is not matched.

#### `--debug`

Enables debug logging.

#### `--[no-]progress`

Shows progress dots to stderr. The default is disabled.

## LICENSE

MIT

## Author

Fujiwara Shunichiro
