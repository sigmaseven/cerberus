// Package core defines the domain model and service layer interfaces for Cerberus SIEM.
//
// # Architecture Overview
//
// The core package provides:
//   - Domain types (Alert, Investigation, Rule, Event, etc.)
//   - Service layer interfaces following Interface Segregation Principle
//   - Constants and enums for status values and configuration
//   - Business logic validation methods
//
// # Design Principles
//
// Service interfaces are designed following these principles:
//  1. Interfaces defined where used (consumer package), not where implemented
//  2. Small, focused interfaces (1-3 methods ideal)
//  3. Accept interfaces, return concrete types
//  4. context.Context as first parameter for cancellation support
//  5. Typed errors with proper wrapping
//
// # Service Layer Pattern
//
// Services extract business logic from HTTP handlers and provide:
//   - Transaction boundaries and atomicity
//   - Business rule enforcement
//   - Multi-storage operation orchestration
//   - Decoupling of transport layer from domain logic
//
// See services.go for complete service interface definitions.
package core
