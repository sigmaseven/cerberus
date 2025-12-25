// Package steps implements BDD step definitions for ACID transaction testing
// Requirement: DATA-001 - ACID Transactions
// Source: docs/requirements/storage-acid-requirements.md
package steps

import (
	"database/sql"

	"github.com/cucumber/godog"
	_ "github.com/mattn/go-sqlite3"
)

// ACIDContext maintains state for ACID transaction test scenarios
// Per AFFIRMATIONS.md Line 147: Context pattern for proper state encapsulation
type ACIDContext struct {
	db                *sql.DB
	transactions      map[string]*sql.Tx // transaction ID -> transaction handle
	transactionErrors map[string]error   // transaction ID -> error state
	lastError         error
	createdRules      map[string]bool
	createdAlerts     map[string]bool
	queryResults      map[string]interface{}
	crashSimulated    bool
	dbPath            string
}

// InitializeACIDContext registers all ACID transaction step definitions
// Requirement: DATA-001 - Complete ACID test coverage
func InitializeACIDContext(sc *godog.ScenarioContext) {
	ctx := &ACIDContext{
		transactions:      make(map[string]*sql.Tx),
		transactionErrors: make(map[string]error),
		createdRules:      make(map[string]bool),
		createdAlerts:     make(map[string]bool),
		queryResults:      make(map[string]interface{}),
		dbPath:            "./test_acid.db",
	}

	// Background steps
	sc.Step(`^the Cerberus storage layer is initialized$`, ctx.theCerberusStorageLayerIsInitialized)
	sc.Step(`^the database is empty$`, ctx.theDatabaseIsEmpty)

	// Transaction lifecycle steps
	sc.Step(`^I start a transaction$`, ctx.iStartATransaction)
	sc.Step(`^I start transaction ([A-Z0-9]+)$`, ctx.iStartTransactionWithID)
	sc.Step(`^I start transaction ([A-Z0-9]+) with repeatable read isolation$`, ctx.iStartTransactionWithRepeatableRead)
	sc.Step(`^I start transaction ([A-Z0-9]+) with serializable isolation$`, ctx.iStartTransactionWithSerializable)
	sc.Step(`^I commit the transaction$`, ctx.iCommitTheTransaction)
	sc.Step(`^I commit transaction ([A-Z0-9]+)$`, ctx.iCommitTransactionWithID)
	sc.Step(`^I rollback the transaction$`, ctx.iRollbackTheTransaction)
	sc.Step(`^I rollback transaction ([A-Z0-9]+)$`, ctx.iRollbackTransactionWithID)

	// Data manipulation in transaction steps
	sc.Step(`^I create a rule with id "([^"]*)" in the transaction$`, ctx.iCreateARuleWithIDInTheTransaction)
	sc.Step(`^I create a rule with id "([^"]*)" in transaction ([A-Z0-9]+)$`, ctx.iCreateARuleWithIDInTransactionWithID)
	sc.Step(`^I create a rule with invalid data causing an error$`, ctx.iCreateARuleWithInvalidData)

	// Query steps
	sc.Step(`^I query for rule "([^"]*)" in a separate transaction ([A-Z0-9]+)$`, ctx.iQueryForRuleInSeparateTransaction)
	sc.Step(`^I query for rule "([^"]*)" in transaction ([A-Z0-9]+)$`, ctx.iQueryForRuleInTransaction)
	sc.Step(`^I read rule "([^"]*)" in transaction ([A-Z0-9]+)$`, ctx.iReadRuleInTransaction)
	sc.Step(`^I count rules matching criteria "([^"]*)"$`, ctx.iCountRulesMatchingCriteria)
	sc.Step(`^I count rules matching criteria "([^"]*)" again in transaction ([A-Z0-9]+)$`, ctx.iCountRulesMatchingCriteriaAgainInTransaction)

	// Pre-existing data steps
	sc.Step(`^a rule with id "([^"]*)" exists$`, ctx.aRuleWithIDExists)
	sc.Step(`^a rule exists with id "([^"]*)" and name "([^"]*)"$`, ctx.aRuleExistsWithIDAndName)
	sc.Step(`^a correlation rule with id "([^"]*)" exists$`, ctx.aCorrelationRuleWithIDExists)
	sc.Step(`^the rule references (\d+) sub-rules$`, ctx.theRuleReferencesSubRules)

	// Alert operations
	sc.Step(`^I create an alert referencing rule id "([^"]*)"$`, ctx.iCreateAnAlertReferencingRuleID)
	sc.Step(`^I attempt to create (\d+) alerts in a batch$`, ctx.iAttemptToCreateAlertsInABatch)
	sc.Step(`^alert number (\d+) has invalid data$`, ctx.alertNumberHasInvalidData)

	// Rule operations
	sc.Step(`^I attempt to delete the rule "([^"]*)"$`, ctx.iAttemptToDeleteTheRule)
	sc.Step(`^I delete the correlation rule "([^"]*)" with cascade$`, ctx.iDeleteTheCorrelationRuleWithCascade)
	sc.Step(`^another transaction ([A-Z0-9]+) updates rule "([^"]*)" name to "([^"]*)"$`, ctx.anotherTransactionUpdatesRuleName)
	sc.Step(`^another transaction ([A-Z0-9]+) inserts a rule with severity "([^"]*)"$`, ctx.anotherTransactionInsertsRuleWithSeverity)

	// WAL and crash simulation
	sc.Step(`^write-ahead logging is enabled$`, ctx.writeAheadLoggingIsEnabled)
	sc.Step(`^I create (\d+) rules in rapid succession$`, ctx.iCreateRulesInRapidSuccession)
	sc.Step(`^each create operation returns success$`, ctx.eachCreateOperationReturnsSuccess)
	sc.Step(`^I simulate a system crash$`, ctx.iSimulateASystemCrash)
	sc.Step(`^I restart the database$`, ctx.iRestartTheDatabase)

	// Assertion steps - Existence
	sc.Step(`^no rules should exist in the database$`, ctx.noRulesShouldExistInTheDatabase)
	sc.Step(`^rule "([^"]*)" should not exist$`, ctx.ruleShouldNotExist)
	sc.Step(`^both rules should exist in the database$`, ctx.bothRulesShouldExistInTheDatabase)
	sc.Step(`^rule "([^"]*)" should be retrievable$`, ctx.ruleShouldBeRetrievable)
	sc.Step(`^rule "([^"]*)" should still exist$`, ctx.ruleShouldStillExist)
	sc.Step(`^only one rule with id "([^"]*)" should exist$`, ctx.onlyOneRuleWithIDShouldExist)
	sc.Step(`^all (\d+) rules should be retrievable after restart$`, ctx.allRulesShouldBeRetrievableAfterRestart)
	sc.Step(`^the rule data should be intact$`, ctx.theRuleDataShouldBeIntact)

	// Assertion steps - Creation/Deletion
	sc.Step(`^the alert should be created successfully$`, ctx.theAlertShouldBeCreatedSuccessfully)
	sc.Step(`^the alert should still exist$`, ctx.theAlertShouldStillExist)
	sc.Step(`^the deletion should fail with a foreign key constraint error$`, ctx.theDeletionShouldFailWithForeignKeyConstraintError)
	sc.Step(`^the creation should fail with a unique constraint violation$`, ctx.theCreationShouldFailWithUniqueConstraintViolation)
	sc.Step(`^zero alerts should be created$`, ctx.zeroAlertsShouldBeCreated)
	sc.Step(`^the correlation rule should be deleted$`, ctx.theCorrelationRuleShouldBeDeleted)
	sc.Step(`^all (\d+) sub-rule references should be cleaned up$`, ctx.allSubRuleReferencesShouldBeCleanedUp)
	sc.Step(`^no orphaned references should remain$`, ctx.noOrphanedReferencesShouldRemain)

	// Assertion steps - Transaction isolation
	sc.Step(`^transaction ([A-Z0-9]+) should not see the uncommitted rule$`, ctx.transactionShouldNotSeeUncommittedRule)
	sc.Step(`^transaction ([A-Z0-9]+) should now see the committed rule$`, ctx.transactionShouldNowSeeCommittedRule)
	sc.Step(`^I should still see the name as "([^"]*)"$`, ctx.iShouldStillSeeTheNameAs)
	sc.Step(`^the read should be repeatable within the transaction$`, ctx.theReadShouldBeRepeatableWithinTheTransaction)
	sc.Step(`^the count is (\d+)$`, ctx.theCountIs)
	sc.Step(`^I should still see a count of (\d+)$`, ctx.iShouldStillSeeACountOf)
	sc.Step(`^no phantom rows should appear$`, ctx.noPhantomRowsShouldAppear)
	sc.Step(`^no data loss should occur$`, ctx.noDataLossShouldOccur)
	sc.Step(`^the database should remain in a consistent state$`, ctx.theDatabaseShouldRemainInAConsistentState)

	// Cleanup
}
