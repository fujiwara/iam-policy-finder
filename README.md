# iam-policy-finder

iam-policy-finder is a tool to find AWS IAM policies that matches the given condition.

This is useful when you want to find policies that have specific permissions.

## Usage

```
Usage: iam-policy-finder <expr> [flags]

Arguments:
  <expr>    CEL expression string or file name

Flags:
  -h, --help                 Show context-sensitive help.
      --dump                 dump found policy document
  -f, --filter=FILTER,...    filter policy document(User, Group, Role, LocalManagedPolicy, AWSManagedPolicy)
      --debug                debug logging
```

### Example

iam-policy-finder finds policies that matches the given condition. The condition is written in CEL expression.
The first argument is a CEL expression string or file name.

- `name` is the name of the policy.
- `document` is the policy document JSON string.

```console
$ iam-policy-finder 'name == "AmazonEC2FullAccess"'
{"time":"2024-07-14T01:11:34.762352337+09:00","level":"INFO","msg":"found","policy":"AmazonEC2FullAccess","versions":["v5","v4","v3","v2","v1"],"attached":2}
```

```
// expr.cel
document.matches('"lambda:[Gg]et[Ff]unction"') && !document.matches('"lambda:[Ll]ist[Tt]ags"')
```
```console
$ iam-policy-finder expr.cel
{"time":"2024-07-14T01:14:22.219906882+09:00","level":"INFO","msg":"found","policy":"AWSSupportServiceRolePolicy","versions":["v36","v35","v34","v33","v32","v31","v30","v29","v28","v27","v26","v25","v24","v23","v22","v21","v20","v19","v18","v17","v16","v15","v14","v13","v12","v11","v10","v9","v8","v7","v6","v5","v4","v3"],"attached":1}
```

## LICENSE

MIT

## Author

Fujiwara Shunichiro
