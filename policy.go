package finder

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement map[string]any

type fuzzyPolicy struct {
	Version   string           `json:"Version"`
	Statement []fuzzyStatement `json:"Statement"`
}

type fuzzyStatement struct {
	Sid          string                                `json:"Sid"`
	Effect       string                                `json:"Effect"`
	Action       json.RawMessage                       `json:"Action"`
	NotAction    json.RawMessage                       `json:"NotAction"`
	Resource     json.RawMessage                       `json:"Resource"`
	Principal    json.RawMessage                       `json:"Principal"`
	NotPrincipal json.RawMessage                       `json:"NotPrincipal"`
	Condition    map[string]map[string]json.RawMessage `json:"Condition"`
}

// normalizeRawMessage normalizes a json.RawMessage to a slice of strings
func normalizeRawMessage(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	switch raw[0] {
	case '"':
		var single string
		if err := json.Unmarshal(raw, &single); err == nil {
			return []string{single}, nil
		}
	case '[':
		slice := []string{}
		if err := json.Unmarshal(raw, &slice); err == nil {
			return slice, nil
		}
	}
	return nil, fmt.Errorf("cannot unmarshal raw message %s", string(raw))
}

type Principal interface {
	map[string][]string | string
}

// normalizePrincipal normalizes a json.RawMessage to a map of slices of strings or a string
func normalizePrincipal(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		return map[string][]string{}, nil
	}
	principal := make(map[string]json.RawMessage)
	switch raw[0] {
	case '{':
		if err := json.Unmarshal(raw, &principal); err != nil {
			return nil, err
		}
		normalized := make(map[string][]string)
		for k, v := range principal {
			n, err := normalizeRawMessage(v)
			if err != nil {
				return nil, err
			}
			normalized[k] = n
		}
		return normalized, nil
	case '"': // "*"
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, err
		}
		return single, nil
	}
	return nil, fmt.Errorf("cannot unmarshal raw Principal: %s", string(raw))
}

// normalizeCondition normalizes a condition map
func normalizeCondition(raw map[string]map[string]json.RawMessage) (map[string]map[string][]string, error) {
	normalized := make(map[string]map[string][]string)
	for k, v := range raw {
		normalized[k] = make(map[string][]string)
		for kk, vv := range v {
			n, err := normalizeRawMessage(vv)
			if err != nil {
				return nil, err
			}
			normalized[k][kk] = n
		}
	}
	return normalized, nil
}

// normalizeStatement normalizes a FuzzyStatement to a Statement
func normalizeStatement(f fuzzyStatement, opt *ParsePolicyOptions) (Statement, error) {
	action, err := normalizeRawMessage(f.Action)
	if err != nil {
		return Statement{}, err
	}
	notAction, err := normalizeRawMessage(f.NotAction)
	if err != nil {
		return Statement{}, err
	}
	if opt.ActionToLowerCase {
		action = toLower(action)
		notAction = toLower(notAction)
	}

	resource, err := normalizeRawMessage(f.Resource)
	if err != nil {
		return Statement{}, err
	}
	principal, err := normalizePrincipal(f.Principal)
	if err != nil {
		return Statement{}, err
	}
	notPrincipal, err := normalizePrincipal(f.NotPrincipal)
	if err != nil {
		return Statement{}, err
	}
	condition, err := normalizeCondition(f.Condition)
	if err != nil {
		return Statement{}, err
	}
	return Statement{
		"Sid":          f.Sid,
		"Effect":       f.Effect,
		"Action":       action,
		"NotAction":    notAction,
		"Resource":     resource,
		"Principal":    principal,
		"NotPrincipal": notPrincipal,
		"Condition":    condition,
	}, nil
}

// normalizePolicy normalizes a policy with fuzzy statements
func normalizePolicy(fPolicy fuzzyPolicy, opt *ParsePolicyOptions) (Policy, error) {
	var statements []Statement
	for _, fStatement := range fPolicy.Statement {
		normalized, err := normalizeStatement(fStatement, opt)
		if err != nil {
			return Policy{}, err
		}
		statements = append(statements, normalized)
	}
	return Policy{
		Version:   fPolicy.Version,
		Statement: statements,
	}, nil
}

func toLower(s []string) []string {
	r := make([]string, len(s))
	for i, v := range s {
		r[i] = strings.ToLower(v)
	}
	return r
}

type ParsePolicyOptions struct {
	ActionToLowerCase bool
}

func ParsePolicy(src []byte, opt *ParsePolicyOptions) (Policy, error) {
	var fPolicy fuzzyPolicy
	if err := json.Unmarshal(src, &fPolicy); err != nil {
		return Policy{}, err
	}
	return normalizePolicy(fPolicy, opt)
}
