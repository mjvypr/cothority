package expression

import (
	"testing"

	parsec "github.com/prataprc/goparsec"
)

func trueFn(s string) bool {
	return true
}

func falseFn(s string) bool {
	return false
}

func TestExprAllTrue(t *testing.T) {
	Y := InitParser(trueFn)
	s := parsec.NewScanner([]byte("a:abc + b:bb"))
	v, s := Y(s)
	if v.(bool) != true {
		t.Fatalf("Mismatch value %v\n", v)
	}
	if !s.Endof() {
		t.Fatal("Scanner did not end")
	}
}

func TestExprAllFalse(t *testing.T) {
	Y := InitParser(falseFn)
	s := parsec.NewScanner([]byte("a:abc + b:bb"))
	v, s := Y(s)
	if v.(bool) != false {
		t.Fatalf("Mismatch value %v\n", v)
	}
	if !s.Endof() {
		t.Fatal("Scanner did not end")
	}
}

func TestPositive_One(t *testing.T) {
	expr := []byte("a:abc")
	fn := func(s string) bool {
		if s == "a:abc" {
			return true
		}
		return false
	}
	v, s := InitParser(fn)(parsec.NewScanner(expr))
	if v.(bool) != true {
		t.Fatalf("Mismatch value %v\n", v)
	}
	if !s.Endof() {
		t.Fatal("Scanner did not end")
	}
}

func TestPositive_Or(t *testing.T) {
	expr := []byte("a:abc - b:abc - c:abc")
	fn := func(s string) bool {
		if s == "b:abc" {
			return true
		}
		return false
	}
	v, s := InitParser(fn)(parsec.NewScanner(expr))
	if v.(bool) != true {
		t.Fatalf("Mismatch value %v\n", v)
	}
	if !s.Endof() {
		t.Fatal("Scanner did not end")
	}
}

func TestParsing_InvalidID(t *testing.T) {
	expr := []byte("x")
	_, err := ParseExpr(InitParser(trueFn), expr)
	if err == nil {
		t.Fatal("expect an error")
	}
	if err.Error() != scannerNotEmpty {
		t.Fatalf("wrong error message, got %s", err.Error())
	}
}

func TestParsing_InvalidOp(t *testing.T) {
	expr := []byte("a:abc / b:abc")
	_, err := ParseExpr(InitParser(trueFn), expr)
	if err == nil {
		t.Fatal("expect an error")
	}
	if err.Error() != scannerNotEmpty {
		t.Fatalf("wrong error message, got %s", err.Error())
	}
}

func TestParsing_Paran(t *testing.T) {
	expr := []byte("(a:b)")
	x, err := ParseExpr(InitParser(trueFn), expr)
	if err != nil {
		t.Fatal(err)
	}
	if x != true {
		t.Fatal("wrong result")
	}
}

func TestParsing_Nesting(t *testing.T) {
	expr := []byte("(a:b - (b:c + c:d))")
	x, err := ParseExpr(InitParser(func(s string) bool {
		if s == "b:c" || s == "c:d" {
			return true
		}
		return false
	}), expr)
	if err != nil {
		t.Fatal(err)
	}
	if x != true {
		t.Fatal("wrong result")
	}
}

func TestParsing_Imbalance(t *testing.T) {
	expr := []byte("(a:b - b:c + c:d))")
	_, err := ParseExpr(InitParser(trueFn), expr)
	if err == nil {
		t.Fatal("error is expected")
	}
}
