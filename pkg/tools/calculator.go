// Package tools provides the calculator tool implementation.
package tools

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"strconv"
	"strings"

	"github.com/astrica1/GoLEM/pkg/golem"
)

type CalculatorTool struct {
	*BaseTool
}

// NewCalculatorTool creates a new calculator tool
func NewCalculatorTool() *CalculatorTool {
	schema := golem.ToolSchema{
		Type:        "object",
		Description: "Performs mathematical calculations and expressions",
		Properties: map[string]golem.ToolSchemaProperty{
			"expression": {
				Type:        "string",
				Description: "Mathematical expression to evaluate (e.g., '2 + 3 * 4', 'sqrt(16)', 'sin(3.14159/2)')",
			},
			"precision": {
				Type:        "integer",
				Description: "Number of decimal places for the result (default: 6)",
				Default:     6,
			},
		},
		Required: []string{"expression"},
	}

	return &CalculatorTool{
		BaseTool: NewBaseTool(
			"calculator",
			"Evaluates mathematical expressions including basic arithmetic, functions like sqrt, sin, cos, tan, log, etc.",
			schema,
		),
	}
}

// Execute performs the calculation
func (ct *CalculatorTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if err := ct.ValidateParams(params); err != nil {
		return nil, err
	}

	expression := params["expression"].(string)
	precision := 6

	if p, exists := params["precision"]; exists {
		if pInt, ok := p.(int); ok {
			precision = pInt
		} else if pFloat, ok := p.(float64); ok {
			precision = int(pFloat)
		}
	}

	result, err := ct.evaluateExpression(expression)
	if err != nil {
		return nil, fmt.Errorf("calculation error: %w", err)
	}

	formatted := fmt.Sprintf("%.*f", precision, result)

	formatted = strings.TrimRight(formatted, "0")
	formatted = strings.TrimRight(formatted, ".")

	return map[string]interface{}{
		"expression": expression,
		"result":     formatted,
		"numeric":    result,
		"precision":  precision,
	}, nil
}

// ValidateParams validates the calculator parameters
func (ct *CalculatorTool) ValidateParams(params map[string]interface{}) error {
	if err := ct.BaseTool.ValidateParams(params); err != nil {
		return err
	}

	expression := params["expression"].(string)
	if strings.TrimSpace(expression) == "" {
		return fmt.Errorf("expression cannot be empty")
	}

	dangerous := []string{"import", "package", "func", "exec", "system", "eval"}
	lowerExpr := strings.ToLower(expression)
	for _, danger := range dangerous {
		if strings.Contains(lowerExpr, danger) {
			return fmt.Errorf("expression contains potentially dangerous keywords")
		}
	}

	return nil
}

// evaluateExpression evaluates a mathematical expression
func (ct *CalculatorTool) evaluateExpression(expression string) (float64, error) {
	expression = ct.preprocessExpression(expression)
	expr, err := parser.ParseExpr(expression)
	if err != nil {
		return 0, fmt.Errorf("invalid expression syntax: %w", err)
	}

	result, err := ct.evalNode(expr)
	if err != nil {
		return 0, fmt.Errorf("evaluation error: %w", err)
	}

	return result, nil
}

// preprocessExpression replaces mathematical functions with Go equivalents
func (ct *CalculatorTool) preprocessExpression(expr string) string {
	replacements := map[string]string{
		"sqrt":  "math.Sqrt",
		"sin":   "math.Sin",
		"cos":   "math.Cos",
		"tan":   "math.Tan",
		"asin":  "math.Asin",
		"acos":  "math.Acos",
		"atan":  "math.Atan",
		"log":   "math.Log",
		"log10": "math.Log10",
		"exp":   "math.Exp",
		"abs":   "math.Abs",
		"ceil":  "math.Ceil",
		"floor": "math.Floor",
		"round": "math.Round",
		"pow":   "math.Pow",
		"pi":    "math.Pi",
		"e":     "math.E",
	}

	result := expr
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}

	if !strings.Contains(result, "math.") {
		result = strings.ReplaceAll(result, "Pi", "math.Pi")
		result = strings.ReplaceAll(result, "E", "math.E")
	}

	return result
}

// evalNode evaluates an AST node
func (ct *CalculatorTool) evalNode(node ast.Node) (float64, error) {
	switch n := node.(type) {
	case *ast.BasicLit:
		return ct.evalBasicLit(n)
	case *ast.BinaryExpr:
		return ct.evalBinaryExpr(n)
	case *ast.UnaryExpr:
		return ct.evalUnaryExpr(n)
	case *ast.CallExpr:
		return ct.evalCallExpr(n)
	case *ast.SelectorExpr:
		return ct.evalSelectorExpr(n)
	case *ast.Ident:
		return ct.evalIdent(n)
	case *ast.ParenExpr:
		return ct.evalNode(n.X)
	default:
		return 0, fmt.Errorf("unsupported expression type: %T", n)
	}
}

// evalBasicLit evaluates basic literals (numbers)
func (ct *CalculatorTool) evalBasicLit(lit *ast.BasicLit) (float64, error) {
	if lit.Kind == token.INT || lit.Kind == token.FLOAT {
		return strconv.ParseFloat(lit.Value, 64)
	}
	return 0, fmt.Errorf("unsupported literal type: %s", lit.Kind)
}

// evalBinaryExpr evaluates binary expressions (+, -, *, /, etc.)
func (ct *CalculatorTool) evalBinaryExpr(expr *ast.BinaryExpr) (float64, error) {
	left, err := ct.evalNode(expr.X)
	if err != nil {
		return 0, err
	}

	right, err := ct.evalNode(expr.Y)
	if err != nil {
		return 0, err
	}

	switch expr.Op {
	case token.ADD:
		return left + right, nil
	case token.SUB:
		return left - right, nil
	case token.MUL:
		return left * right, nil
	case token.QUO:
		if right == 0 {
			return 0, fmt.Errorf("division by zero")
		}
		return left / right, nil
	case token.REM:
		if right == 0 {
			return 0, fmt.Errorf("modulo by zero")
		}
		return math.Mod(left, right), nil
	case token.XOR:
		return math.Pow(left, right), nil
	default:
		return 0, fmt.Errorf("unsupported binary operator: %s", expr.Op)
	}
}

// evalUnaryExpr evaluates unary expressions (-, +)
func (ct *CalculatorTool) evalUnaryExpr(expr *ast.UnaryExpr) (float64, error) {
	operand, err := ct.evalNode(expr.X)
	if err != nil {
		return 0, err
	}

	switch expr.Op {
	case token.SUB:
		return -operand, nil
	case token.ADD:
		return operand, nil
	default:
		return 0, fmt.Errorf("unsupported unary operator: %s", expr.Op)
	}
}

// evalCallExpr evaluates function calls
func (ct *CalculatorTool) evalCallExpr(call *ast.CallExpr) (float64, error) {
	// Get function name
	var funcName string
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok && ident.Name == "math" {
			funcName = "math." + fn.Sel.Name
		} else {
			return 0, fmt.Errorf("unsupported selector expression")
		}
	case *ast.Ident:
		funcName = fn.Name
	default:
		return 0, fmt.Errorf("unsupported function call type")
	}

	var args []float64
	for _, arg := range call.Args {
		val, err := ct.evalNode(arg)
		if err != nil {
			return 0, err
		}
		args = append(args, val)
	}

	return ct.callMathFunction(funcName, args)
}

// evalSelectorExpr evaluates selector expressions (math.Pi, etc.)
func (ct *CalculatorTool) evalSelectorExpr(sel *ast.SelectorExpr) (float64, error) {
	if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "math" {
		switch sel.Sel.Name {
		case "Pi":
			return math.Pi, nil
		case "E":
			return math.E, nil
		default:
			return 0, fmt.Errorf("unsupported math constant: %s", sel.Sel.Name)
		}
	}
	return 0, fmt.Errorf("unsupported selector expression")
}

// evalIdent evaluates identifiers (constants)
func (ct *CalculatorTool) evalIdent(ident *ast.Ident) (float64, error) {
	switch ident.Name {
	case "Pi", "pi":
		return math.Pi, nil
	case "E", "e":
		return math.E, nil
	default:
		return 0, fmt.Errorf("unknown identifier: %s", ident.Name)
	}
}

// callMathFunction calls mathematical functions
func (ct *CalculatorTool) callMathFunction(name string, args []float64) (float64, error) {
	switch name {
	case "math.Sqrt", "sqrt":
		if len(args) != 1 {
			return 0, fmt.Errorf("sqrt requires exactly 1 argument")
		}
		if args[0] < 0 {
			return 0, fmt.Errorf("sqrt of negative number")
		}
		return math.Sqrt(args[0]), nil

	case "math.Sin", "sin":
		if len(args) != 1 {
			return 0, fmt.Errorf("sin requires exactly 1 argument")
		}
		return math.Sin(args[0]), nil

	case "math.Cos", "cos":
		if len(args) != 1 {
			return 0, fmt.Errorf("cos requires exactly 1 argument")
		}
		return math.Cos(args[0]), nil

	case "math.Tan", "tan":
		if len(args) != 1 {
			return 0, fmt.Errorf("tan requires exactly 1 argument")
		}
		return math.Tan(args[0]), nil

	case "math.Asin", "asin":
		if len(args) != 1 {
			return 0, fmt.Errorf("asin requires exactly 1 argument")
		}
		if args[0] < -1 || args[0] > 1 {
			return 0, fmt.Errorf("asin argument must be between -1 and 1")
		}
		return math.Asin(args[0]), nil

	case "math.Acos", "acos":
		if len(args) != 1 {
			return 0, fmt.Errorf("acos requires exactly 1 argument")
		}
		if args[0] < -1 || args[0] > 1 {
			return 0, fmt.Errorf("acos argument must be between -1 and 1")
		}
		return math.Acos(args[0]), nil

	case "math.Atan", "atan":
		if len(args) != 1 {
			return 0, fmt.Errorf("atan requires exactly 1 argument")
		}
		return math.Atan(args[0]), nil

	case "math.Log", "log":
		if len(args) != 1 {
			return 0, fmt.Errorf("log requires exactly 1 argument")
		}
		if args[0] <= 0 {
			return 0, fmt.Errorf("log of non-positive number")
		}
		return math.Log(args[0]), nil

	case "math.Log10", "log10":
		if len(args) != 1 {
			return 0, fmt.Errorf("log10 requires exactly 1 argument")
		}
		if args[0] <= 0 {
			return 0, fmt.Errorf("log10 of non-positive number")
		}
		return math.Log10(args[0]), nil

	case "math.Exp", "exp":
		if len(args) != 1 {
			return 0, fmt.Errorf("exp requires exactly 1 argument")
		}
		return math.Exp(args[0]), nil

	case "math.Abs", "abs":
		if len(args) != 1 {
			return 0, fmt.Errorf("abs requires exactly 1 argument")
		}
		return math.Abs(args[0]), nil

	case "math.Ceil", "ceil":
		if len(args) != 1 {
			return 0, fmt.Errorf("ceil requires exactly 1 argument")
		}
		return math.Ceil(args[0]), nil

	case "math.Floor", "floor":
		if len(args) != 1 {
			return 0, fmt.Errorf("floor requires exactly 1 argument")
		}
		return math.Floor(args[0]), nil

	case "math.Round", "round":
		if len(args) != 1 {
			return 0, fmt.Errorf("round requires exactly 1 argument")
		}
		return math.Round(args[0]), nil

	case "math.Pow", "pow":
		if len(args) != 2 {
			return 0, fmt.Errorf("pow requires exactly 2 arguments")
		}
		return math.Pow(args[0], args[1]), nil

	case "max":
		if len(args) < 2 {
			return 0, fmt.Errorf("max requires at least 2 arguments")
		}
		result := args[0]
		for _, arg := range args[1:] {
			if arg > result {
				result = arg
			}
		}
		return result, nil

	case "min":
		if len(args) < 2 {
			return 0, fmt.Errorf("min requires at least 2 arguments")
		}
		result := args[0]
		for _, arg := range args[1:] {
			if arg < result {
				result = arg
			}
		}
		return result, nil

	default:
		return 0, fmt.Errorf("unknown function: %s", name)
	}
}
