// Package a contains test cases for allowed context.Background() usage.
package a

import "context"

// init function - context.Background() is allowed
func init() {
	_ = context.Background() // OK - init function is allowed
}

// Exempted with comment - context.Background() is allowed
func exemptedWithComment() {
	// contextcheck:exempt reason="background worker initialization"
	_ = context.Background() // OK - has exemption comment
}

// Another exemption style
func anotherExemption() {
	ctx := context.Background() /* contextcheck:exempt */ // OK
	_ = ctx
}
