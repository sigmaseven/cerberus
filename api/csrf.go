package api

// This file previously contained CSRFProtection struct and methods,
// but they were unused and created inconsistency with the main CSRF
// token generation in jwt.go. All CSRF token generation now uses
// the generateCSRFToken() function in jwt.go which produces
// 64-character hex strings as expected by the middleware validation.
