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

iam-policy-finder finds policies that matches the given condition. The condition is written in [CEL](https://cel.dev/) expression.

The first argument is a CEL expression string or file name.

- `name` is the name of the policy.
- `document` is the policy document JSON string.

```console
$ iam-policy-finder 'name == "AmazonEC2FullAccess"'
time=2024-07-14T01:27:14.568+09:00 level=INFO msg=found policy=AmazonEC2FullAccess versions="[v5 v4 v3 v2 v1]" attached=2
```

```
// expr.cel
document.matches('"lambda:[Gg]et[Ff]unction"') && !document.matches('"lambda:[Ll]ist[Tt]ags"')
```
```console
$ iam-policy-finder expr.cel
time=2024-07-14T01:25:33.029+09:00 level=INFO msg=found policy=SecretsManagerReadWrite versions="[v5 v4 v3 v2 v1]" attached=2
```

### Options

#### `--filter` (`-f`)

Filters the account authorization type. The default is to search all types.

"User", "Group", "Role", "LocalManagedPolicy" and "AWSManagedPolicy" are allowed.

#### `--dump`

Dumps the found policy document JSON to STDOUT.

#### `--debug`

Enables debug logging.

### LIMITATIONS

The policy document is not parsed and not normalized. The search is done by string matching.

## LICENSE

MIT

## Author

Fujiwara Shunichiro
