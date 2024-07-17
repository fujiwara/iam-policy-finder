package finder

import (
	"fmt"

	"github.com/google/cel-go/cel"
)

func parseCel(expr string) (cel.Program, error) {
	env, err := cel.NewEnv(
		cel.Variable("Name", cel.StringType),
		cel.Variable("Document", cel.StringType),
		cel.Variable("Version", cel.StringType),
		cel.Variable("Statement", cel.ListType(
			cel.MapType(cel.StringType, cel.DynType),
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to CEL new env error: %w", err)
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to CEL compile error: %w", issues.Err())
	}
	return env.Program(ast)
}
