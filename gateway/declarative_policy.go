package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode"
)

// PolicyEffect represents permit or deny.
type PolicyEffect string

const (
	EffectPermit PolicyEffect = "permit"
	EffectDeny   PolicyEffect = "deny"
)

// EvalContext contains the runtime transaction parameters presented for authorization.
type EvalContext struct {
	Principal          string
	Action             string
	TenantID           string
	Amount             float64
	Currency           string
	Tainted            bool
	IntentMandateValid bool
	Attributes         map[string]interface{}
}

// Expr is an AST node for policy conditions.
type Expr interface {
	Eval(ctx *EvalContext) (interface{}, error)
}

// BinaryExpr represents binary operations like ==, !=, <, <=, >, >=, &&, ||.
type BinaryExpr struct {
	Op    string
	Left  Expr
	Right Expr
}

func (b *BinaryExpr) Eval(ctx *EvalContext) (interface{}, error) {
	if b.Op == "&&" {
		lVal, err := b.Left.Eval(ctx)
		if err != nil {
			return nil, err
		}
		lBool, ok := lVal.(bool)
		if !ok {
			return nil, fmt.Errorf("left operand of && is not boolean")
		}
		if !lBool {
			return false, nil // Short-circuit
		}
		rVal, err := b.Right.Eval(ctx)
		if err != nil {
			return nil, err
		}
		rBool, ok := rVal.(bool)
		if !ok {
			return nil, fmt.Errorf("right operand of && is not boolean")
		}
		return rBool, nil
	}

	if b.Op == "||" {
		lVal, err := b.Left.Eval(ctx)
		if err != nil {
			return nil, err
		}
		lBool, ok := lVal.(bool)
		if !ok {
			return nil, fmt.Errorf("left operand of || is not boolean")
		}
		if lBool {
			return true, nil // Short-circuit
		}
		rVal, err := b.Right.Eval(ctx)
		if err != nil {
			return nil, err
		}
		rBool, ok := rVal.(bool)
		if !ok {
			return nil, fmt.Errorf("right operand of || is not boolean")
		}
		return rBool, nil
	}

	lVal, err := b.Left.Eval(ctx)
	if err != nil {
		return nil, err
	}
	rVal, err := b.Right.Eval(ctx)
	if err != nil {
		return nil, err
	}

	switch b.Op {
	case "==":
		return compareEqual(lVal, rVal), nil
	case "!=":
		return !compareEqual(lVal, rVal), nil
	case "<":
		lNum, rNum, err := toFloats(lVal, rVal)
		if err != nil {
			return nil, err
		}
		return lNum < rNum, nil
	case "<=":
		lNum, rNum, err := toFloats(lVal, rVal)
		if err != nil {
			return nil, err
		}
		return lNum <= rNum, nil
	case ">":
		lNum, rNum, err := toFloats(lVal, rVal)
		if err != nil {
			return nil, err
		}
		return lNum > rNum, nil
	case ">=":
		lNum, rNum, err := toFloats(lVal, rVal)
		if err != nil {
			return nil, err
		}
		return lNum >= rNum, nil
	case "in":
		return checkInCollection(lVal, rVal)
	default:
		return nil, fmt.Errorf("unsupported operator: %s", b.Op)
	}
}

// UnaryExpr represents unary operations like !.
type UnaryExpr struct {
	Op      string
	Operand Expr
}

func (u *UnaryExpr) Eval(ctx *EvalContext) (interface{}, error) {
	val, err := u.Operand.Eval(ctx)
	if err != nil {
		return nil, err
	}
	if u.Op == "!" {
		b, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("operand of ! is not boolean")
		}
		return !b, nil
	}
	return nil, fmt.Errorf("unsupported unary operator: %s", u.Op)
}

// LiteralExpr represents constant values.
type LiteralExpr struct {
	Value interface{}
}

func (l *LiteralExpr) Eval(ctx *EvalContext) (interface{}, error) {
	return l.Value, nil
}

// VariableExpr resolves runtime attributes.
type VariableExpr struct {
	Name string
}

func (v *VariableExpr) Eval(ctx *EvalContext) (interface{}, error) {
	switch strings.ToLower(v.Name) {
	case "principal", "agent_id", "agent":
		return ctx.Principal, nil
	case "action":
		return ctx.Action, nil
	case "tenant_id", "tenant":
		return ctx.TenantID, nil
	case "amount":
		return ctx.Amount, nil
	case "currency":
		return ctx.Currency, nil
	case "tainted":
		return ctx.Tainted, nil
	case "intent_mandate_valid":
		return ctx.IntentMandateValid, nil
	default:
		if ctx.Attributes != nil {
			if val, ok := ctx.Attributes[v.Name]; ok {
				return val, nil
			}
		}
		return nil, nil
	}
}

// ListExpr represents a collection literal, e.g. ["USD", "EUR"].
type ListExpr struct {
	Elements []Expr
}

func (l *ListExpr) Eval(ctx *EvalContext) (interface{}, error) {
	res := make([]interface{}, len(l.Elements))
	for i, elem := range l.Elements {
		v, err := elem.Eval(ctx)
		if err != nil {
			return nil, err
		}
		res[i] = v
	}
	return res, nil
}

func compareEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	// Try float comparison
	fA, errA := toFloat(a)
	fB, errB := toFloat(b)
	if errA == nil && errB == nil {
		return fA == fB
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func toFloat(v interface{}) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case float32:
		return float64(val), nil
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case string:
		return strconv.ParseFloat(val, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float", v)
	}
}

func toFloats(a, b interface{}) (float64, float64, error) {
	fA, err := toFloat(a)
	if err != nil {
		return 0, 0, err
	}
	fB, err := toFloat(b)
	if err != nil {
		return 0, 0, err
	}
	return fA, fB, nil
}

func checkInCollection(item, col interface{}) (bool, error) {
	items, ok := col.([]interface{})
	if !ok {
		return false, fmt.Errorf("right operand of 'in' must be a list, got %T", col)
	}
	for _, el := range items {
		if compareEqual(item, el) {
			return true, nil
		}
	}
	return false, nil
}

// PolicyRule is a single compiled SPL statement.
type PolicyRule struct {
	Effect     PolicyEffect
	Principals []string // empty or ["*"] for wildcard
	Actions    []string // empty or ["*"] for wildcard
	Condition  Expr     // nil if unconditional
	RawRule    string
}

func matchTarget(targets []string, actual string) bool {
	if len(targets) == 0 {
		return true
	}
	for _, t := range targets {
		if t == "*" || t == actual {
			return true
		}
	}
	return false
}

// CompiledPolicySet represents an immutable set of validated rules.
type CompiledPolicySet struct {
	Rules     []PolicyRule
	RawSource string
}

// Evaluate runs the rule set against the evaluation context.
// Strategy: First-match Deny overrides all. If any Deny matches -> DENY.
// At least one Permit must match -> ALLOW. Otherwise -> DENY (default-deny).
func (cps *CompiledPolicySet) Evaluate(ctx *EvalContext) (decision string, reason string) {
	if cps == nil || len(cps.Rules) == 0 {
		return "DENY", "No declarative policies loaded (default-deny)"
	}

	permitMatched := false
	permitReason := ""

	for _, rule := range cps.Rules {
		// Header match (Principal & Action)
		if !matchTarget(rule.Principals, ctx.Principal) {
			continue
		}
		if !matchTarget(rule.Actions, ctx.Action) {
			continue
		}

		// Condition match
		condPass := true
		if rule.Condition != nil {
			res, err := rule.Condition.Eval(ctx)
			if err != nil {
				// Evaluation error in condition fails safe
				condPass = false
			} else {
				b, ok := res.(bool)
				condPass = ok && b
			}
		}

		if condPass {
			if rule.Effect == EffectDeny {
				return "DENY", fmt.Sprintf("Explicit deny rule matched: %s", rule.RawRule)
			}
			if rule.Effect == EffectPermit {
				permitMatched = true
				permitReason = fmt.Sprintf("Permit rule matched: %s", rule.RawRule)
			}
		}
	}

	if permitMatched {
		return "ALLOW", permitReason
	}

	return "DENY", "No permit rule satisfied condition (default-deny)"
}

// DeclarativePolicyEngine manages live policies with atomic hot-reloading.
type DeclarativePolicyEngine struct {
	activeSet atomic.Pointer[CompiledPolicySet]
}

var globalDeclarativePolicyEngine = NewDeclarativePolicyEngine()

func NewDeclarativePolicyEngine() *DeclarativePolicyEngine {
	engine := &DeclarativePolicyEngine{}
	// Initialize with default standard baseline policy
	defaultPolicy := `
		deny(action == "TRANSFER") when {
			amount > 25000.00 || tainted == true
		};
		permit(principal in ["ag_Finance_Bot", "ag_Admin"], action == "Issue_Refund") when {
			amount <= 5000.00 && currency in ["USD", "EUR", "GBP"]
		};
		permit(action == "Check_Balance") when {
			amount == 0
		};
		permit(principal == "ag_Admin", action == "*") when {
			tainted == false
		};
	`
	_ = engine.LoadPolicy(defaultPolicy)
	return engine
}

func (dpe *DeclarativePolicyEngine) LoadPolicy(raw string) error {
	compiled, err := ParsePolicy(raw)
	if err != nil {
		return fmt.Errorf("policy compilation failed: %w", err)
	}
	dpe.activeSet.Store(compiled)
	return nil
}

func (dpe *DeclarativePolicyEngine) Evaluate(ctx *EvalContext) (string, string) {
	set := dpe.activeSet.Load()
	if set == nil {
		return "DENY", "Policy engine uninitialized"
	}
	return set.Evaluate(ctx)
}

func (dpe *DeclarativePolicyEngine) GetSource() string {
	set := dpe.activeSet.Load()
	if set == nil {
		return ""
	}
	return set.RawSource
}

// --- Sentinel Policy Language (SPL) Parser ---

type tokenType int

const (
	tokEOF tokenType = iota
	tokIdent
	tokString
	tokNumber
	tokBool
	tokPermit
	tokDeny
	tokWhen
	tokLParen
	tokRParen
	tokLBrace
	tokRBrace
	tokLBracket
	tokRBracket
	tokComma
	tokOp
)

type token struct {
	typ tokenType
	val string
}

func tokenize(input string) ([]token, error) {
	var tokens []token
	runes := []rune(input)
	n := len(runes)
	i := 0

	for i < n {
		r := runes[i]
		if unicode.IsSpace(r) {
			i++
			continue
		}
		// Comment skipping: // or #
		if (r == '/' && i+1 < n && runes[i+1] == '/') || r == '#' {
			for i < n && runes[i] != '\n' {
				i++
			}
			continue
		}

		switch r {
		case '(':
			tokens = append(tokens, token{tokLParen, "("})
			i++
		case ')':
			tokens = append(tokens, token{tokRParen, ")"})
			i++
		case '{':
			tokens = append(tokens, token{tokLBrace, "{"})
			i++
		case '}':
			tokens = append(tokens, token{tokRBrace, "}"})
			i++
		case '[':
			tokens = append(tokens, token{tokLBracket, "["})
			i++
		case ']':
			tokens = append(tokens, token{tokRBracket, "]"})
			i++
		case ',':
			tokens = append(tokens, token{tokComma, ","})
			i++
		case ';':
			// Semicolons are statement separators (ignored)
			i++
		case '"', '\'':
			quote := r
			i++
			start := i
			for i < n && runes[i] != quote {
				i++
			}
			if i >= n {
				return nil, errors.New("unclosed string literal")
			}
			tokens = append(tokens, token{tokString, string(runes[start:i])})
			i++
		default:
			// Operators: ==, !=, <=, >=, <, >, &&, ||, !
			if r == '=' && i+1 < n && runes[i+1] == '=' {
				tokens = append(tokens, token{tokOp, "=="})
				i += 2
			} else if r == '!' && i+1 < n && runes[i+1] == '=' {
				tokens = append(tokens, token{tokOp, "!="})
				i += 2
			} else if r == '<' && i+1 < n && runes[i+1] == '=' {
				tokens = append(tokens, token{tokOp, "<="})
				i += 2
			} else if r == '>' && i+1 < n && runes[i+1] == '=' {
				tokens = append(tokens, token{tokOp, ">="})
				i += 2
			} else if r == '&' && i+1 < n && runes[i+1] == '&' {
				tokens = append(tokens, token{tokOp, "&&"})
				i += 2
			} else if r == '|' && i+1 < n && runes[i+1] == '|' {
				tokens = append(tokens, token{tokOp, "||"})
				i += 2
			} else if r == '<' || r == '>' || r == '!' {
				tokens = append(tokens, token{tokOp, string(r)})
				i++
			} else if unicode.IsDigit(r) || (r == '-' && i+1 < n && unicode.IsDigit(runes[i+1])) {
				start := i
				if r == '-' {
					i++
				}
				hasDot := false
				for i < n && (unicode.IsDigit(runes[i]) || runes[i] == '.') {
					if runes[i] == '.' {
						if hasDot {
							break
						}
						hasDot = true
					}
					i++
				}
				tokens = append(tokens, token{tokNumber, string(runes[start:i])})
			} else if unicode.IsLetter(r) || r == '_' || r == '*' {
				start := i
				for i < n && (unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) || runes[i] == '_' || runes[i] == '*' || runes[i] == ':') {
					i++
				}
				val := string(runes[start:i])
				switch strings.ToLower(val) {
				case "permit":
					tokens = append(tokens, token{tokPermit, val})
				case "deny":
					tokens = append(tokens, token{tokDeny, val})
				case "when":
					tokens = append(tokens, token{tokWhen, val})
				case "true", "false":
					tokens = append(tokens, token{tokBool, val})
				case "in":
					tokens = append(tokens, token{tokOp, "in"})
				default:
					tokens = append(tokens, token{tokIdent, val})
				}
			} else {
				return nil, fmt.Errorf("unexpected character: %c", r)
			}
		}
	}
	tokens = append(tokens, token{tokEOF, ""})
	return tokens, nil
}

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() token {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return token{tokEOF, ""}
}

func (p *parser) next() token {
	tok := p.peek()
	p.pos++
	return tok
}

func (p *parser) match(typ tokenType) bool {
	if p.peek().typ == typ {
		p.next()
		return true
	}
	return false
}

func (p *parser) expect(typ tokenType, errMsg string) (token, error) {
	if p.peek().typ != typ {
		return token{}, fmt.Errorf("%s, got %v (%s)", errMsg, p.peek().typ, p.peek().val)
	}
	return p.next(), nil
}

// ParsePolicy parses multiple SPL statements into a CompiledPolicySet.
func ParsePolicy(source string) (*CompiledPolicySet, error) {
	tokens, err := tokenize(source)
	if err != nil {
		return nil, err
	}

	p := &parser{tokens: tokens}
	var rules []PolicyRule

	for p.peek().typ != tokEOF {
		rule, err := p.parseRule()
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return &CompiledPolicySet{
		Rules:     rules,
		RawSource: source,
	}, nil
}

func (p *parser) parseRule() (PolicyRule, error) {
	tok := p.next()
	var effect PolicyEffect
	if tok.typ == tokPermit {
		effect = EffectPermit
	} else if tok.typ == tokDeny {
		effect = EffectDeny
	} else {
		return PolicyRule{}, fmt.Errorf("expected 'permit' or 'deny', got '%s'", tok.val)
	}

	var principals, actions []string
	// Parse mandatory target selector: (principal in ["..."], action == "...")
	_, err := p.expect(tokLParen, "expected '(' after permit/deny")
	if err != nil {
		return PolicyRule{}, err
	}
	for p.peek().typ != tokRParen && p.peek().typ != tokEOF {
		identTok, err := p.expect(tokIdent, "expected target attribute name")
		if err != nil {
			return PolicyRule{}, err
		}
		opTok, err := p.expect(tokOp, "expected '==' or 'in' in target selector")
		if err != nil {
			return PolicyRule{}, err
		}

		var vals []string
		if opTok.val == "in" {
			_, err = p.expect(tokLBracket, "expected '[' after in")
			if err != nil {
				return PolicyRule{}, err
			}
			for p.peek().typ != tokRBracket && p.peek().typ != tokEOF {
				valTok := p.next()
				vals = append(vals, valTok.val)
				if p.peek().typ == tokComma {
					p.next()
				}
			}
			_, err = p.expect(tokRBracket, "expected ']' after list")
			if err != nil {
				return PolicyRule{}, err
			}
		} else if opTok.val == "==" {
			valTok := p.next()
			vals = append(vals, valTok.val)
		} else {
			return PolicyRule{}, fmt.Errorf("unsupported operator '%s' in target selector", opTok.val)
		}

		attrName := strings.ToLower(identTok.val)
		if attrName == "principal" || attrName == "agent" || attrName == "agent_id" {
			principals = append(principals, vals...)
		} else if attrName == "action" {
			actions = append(actions, vals...)
		}

		if p.peek().typ == tokComma {
			p.next()
		}
	}
	_, err = p.expect(tokRParen, "expected ')' after target selector")
	if err != nil {
		return PolicyRule{}, err
	}

	var condition Expr
	if p.match(tokWhen) {
		_, err := p.expect(tokLBrace, "expected '{' after when")
		if err != nil {
			return PolicyRule{}, err
		}
		cond, err := p.parseOr()
		if err != nil {
			return PolicyRule{}, err
		}
		condition = cond
		_, err = p.expect(tokRBrace, "expected '}' closing when block")
		if err != nil {
			return PolicyRule{}, err
		}
	}

	return PolicyRule{
		Effect:     effect,
		Principals: principals,
		Actions:    actions,
		Condition:  condition,
		RawRule:    fmt.Sprintf("%s(%v, %v)", effect, principals, actions),
	}, nil
}

func (p *parser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokOp && p.peek().val == "||" {
		opTok := p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Op: opTok.val, Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Expr, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokOp && p.peek().val == "&&" {
		opTok := p.next()
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Op: opTok.val, Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseComparison() (Expr, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	if p.peek().typ == tokOp && (p.peek().val == "==" || p.peek().val == "!=" ||
		p.peek().val == "<" || p.peek().val == "<=" ||
		p.peek().val == ">" || p.peek().val == ">=" || p.peek().val == "in") {
		opTok := p.next()
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		if opTok.val == "in" {
			if _, ok := right.(*ListExpr); !ok {
				return nil, fmt.Errorf("right operand of 'in' must be a collection literal, got %T", right)
			}
		}
		return &BinaryExpr{Op: opTok.val, Left: left, Right: right}, nil
	}

	return left, nil
}

func (p *parser) parsePrimary() (Expr, error) {
	tok := p.peek()
	switch tok.typ {
	case tokLParen:
		p.next()
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		_, err = p.expect(tokRParen, "expected ')'")
		if err != nil {
			return nil, err
		}
		return expr, nil
	case tokLBracket:
		p.next()
		var elements []Expr
		for p.peek().typ != tokRBracket && p.peek().typ != tokEOF {
			elem, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			elements = append(elements, elem)
			if p.peek().typ == tokComma {
				p.next()
			}
		}
		_, err := p.expect(tokRBracket, "expected ']' closing list")
		if err != nil {
			return nil, err
		}
		return &ListExpr{Elements: elements}, nil
	case tokOp:
		if tok.val == "!" {
			p.next()
			operand, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			return &UnaryExpr{Op: "!", Operand: operand}, nil
		}
		return nil, fmt.Errorf("unexpected operator '%s'", tok.val)
	case tokNumber:
		p.next()
		val, err := strconv.ParseFloat(tok.val, 64)
		if err != nil {
			return nil, err
		}
		return &LiteralExpr{Value: val}, nil
	case tokString:
		p.next()
		return &LiteralExpr{Value: tok.val}, nil
	case tokBool:
		p.next()
		return &LiteralExpr{Value: strings.ToLower(tok.val) == "true"}, nil
	case tokIdent:
		p.next()
		return &VariableExpr{Name: tok.val}, nil
	default:
		return nil, fmt.Errorf("unexpected token in expression: %s (%v)", tok.val, tok.typ)
	}
}
