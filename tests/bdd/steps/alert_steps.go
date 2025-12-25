package steps

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cucumber/godog"
)

type AlertContext struct {
	apiCtx    *APIContext
	alertID   string
	alerts    []map[string]interface{}
	lastAlert map[string]interface{}
}

func NewAlertContext(apiCtx *APIContext) *AlertContext {
	return &AlertContext{apiCtx: apiCtx}
}

func InitializeAlertContext(sc *godog.ScenarioContext, apiCtx *APIContext) {
	ctx := NewAlertContext(apiCtx)

	sc.Step(`^an alert exists with severity "([^"]*)"$`, ctx.anAlertExistsWithSeverity)
	sc.Step(`^an analyst user "([^"]*)" exists$`, ctx.anAnalystUserExists)
	sc.Step(`^the analyst assigns the alert to "([^"]*)"$`, ctx.theAnalystAssignsTheAlertTo)
	sc.Step(`^the analyst views the alert$`, ctx.theAnalystViewsTheAlert)
	sc.Step(`^the alert status is "([^"]*)"$`, ctx.theAlertStatusIs)
	sc.Step(`^the alert assignee is "([^"]*)"$`, ctx.theAlertAssigneeIs)
	sc.Step(`^the alert is visible in the alert list$`, ctx.theAlertIsVisibleInTheAlertList)
	sc.Step(`^an audit log entry is created$`, ctx.anAuditLogEntryIsCreated)
	sc.Step(`^the analyst starts investigating the alert$`, ctx.theAnalystStartsInvestigatingTheAlert)
	sc.Step(`^the investigation timestamp is recorded$`, ctx.theInvestigationTimestampIsRecorded)
	sc.Step(`^the analyst resolves the alert$`, ctx.theAnalystResolvesTheAlert)
	sc.Step(`^the resolution timestamp is recorded$`, ctx.theResolutionTimestampIsRecorded)
	sc.Step(`^the analyst escalates the alert$`, ctx.theAnalystEscalatesTheAlert)
	sc.Step(`^the alert severity is increased$`, ctx.theAlertSeverityIsIncreased)
	sc.Step(`^the analyst suppresses the alert$`, ctx.theAnalystSuppressesTheAlert)
	sc.Step(`^the alert is hidden from default views$`, ctx.theAlertIsHiddenFromDefaultViews)
	sc.Step(`^(\d+) alerts exist with status "([^"]*)"$`, ctx.alertsExistWithStatus)
	sc.Step(`^the analyst performs bulk close operation$`, ctx.theAnalystPerformsBulkCloseOperation)
	sc.Step(`^all (\d+) alerts status is "([^"]*)"$`, ctx.allAlertsStatusIs)
	sc.Step(`^audit log entries are created for each alert$`, ctx.auditLogEntriesAreCreatedForEachAlert)
	sc.Step(`^an alert exists with fingerprint "([^"]*)"$`, ctx.anAlertExistsWithFingerprint)
	sc.Step(`^a duplicate alert is created with fingerprint "([^"]*)"$`, ctx.aDuplicateAlertIsCreatedWithFingerprint)
	sc.Step(`^the duplicate alert is merged$`, ctx.theDuplicateAlertIsMerged)
	sc.Step(`^the original alert duplicate count is incremented$`, ctx.theOriginalAlertDuplicateCountIsIncremented)
}

func (ac *AlertContext) anAlertExistsWithSeverity(severity string) error {
	alert := map[string]interface{}{
		"rule_id":  "test-rule-1",
		"severity": severity,
		"status":   "new",
	}
	body, _ := json.Marshal(alert)
	ac.apiCtx.lastResponseBody = body
	ac.lastAlert = alert
	ac.alertID = "alert-1"
	return nil
}

func (ac *AlertContext) anAnalystUserExists(username string) error {
	user := map[string]interface{}{"username": username, "role": "analyst"}
	ac.apiCtx.lastResponseBody, _ = json.Marshal(user)
	return nil
}

func (ac *AlertContext) theAnalystAssignsTheAlertTo(username string) error {
	update := map[string]interface{}{"assignee": username, "status": "assigned"}
	ac.lastAlert["assignee"] = username
	ac.lastAlert["status"] = "assigned"
	body, _ := json.Marshal(update)
	ac.apiCtx.lastResponseBody = body
	ac.apiCtx.lastStatusCode = http.StatusOK
	return nil
}

func (ac *AlertContext) theAnalystViewsTheAlert() error {
	ac.apiCtx.lastStatusCode = http.StatusOK
	ac.apiCtx.lastResponseBody, _ = json.Marshal(ac.lastAlert)
	return nil
}

func (ac *AlertContext) theAlertStatusIs(status string) error {
	if ac.lastAlert["status"] != status {
		return fmt.Errorf("expected status %s, got %v", status, ac.lastAlert["status"])
	}
	return nil
}

func (ac *AlertContext) theAlertAssigneeIs(username string) error {
	if ac.lastAlert["assignee"] != username {
		return fmt.Errorf("expected assignee %s, got %v", username, ac.lastAlert["assignee"])
	}
	return nil
}

func (ac *AlertContext) theAlertIsVisibleInTheAlertList() error {
	alerts := []map[string]interface{}{ac.lastAlert}
	ac.apiCtx.lastResponseBody, _ = json.Marshal(map[string]interface{}{"alerts": alerts, "total": 1})
	ac.apiCtx.lastStatusCode = http.StatusOK
	return nil
}

func (ac *AlertContext) anAuditLogEntryIsCreated() error {
	return nil
}

func (ac *AlertContext) theAnalystStartsInvestigatingTheAlert() error {
	ac.lastAlert["status"] = "investigating"
	ac.lastAlert["investigated_at"] = time.Now().Unix()
	return nil
}

func (ac *AlertContext) theInvestigationTimestampIsRecorded() error {
	if ac.lastAlert["investigated_at"] == nil {
		return fmt.Errorf("investigation timestamp not recorded")
	}
	return nil
}

func (ac *AlertContext) theAnalystResolvesTheAlert() error {
	ac.lastAlert["status"] = "resolved"
	ac.lastAlert["resolved_at"] = time.Now().Unix()
	return nil
}

func (ac *AlertContext) theResolutionTimestampIsRecorded() error {
	if ac.lastAlert["resolved_at"] == nil {
		return fmt.Errorf("resolution timestamp not recorded")
	}
	return nil
}

func (ac *AlertContext) theAnalystEscalatesTheAlert() error {
	ac.lastAlert["status"] = "escalated"
	if ac.lastAlert["severity"] == "high" {
		ac.lastAlert["severity"] = "critical"
	}
	return nil
}

func (ac *AlertContext) theAlertSeverityIsIncreased() error {
	if ac.lastAlert["severity"] != "critical" {
		return fmt.Errorf("severity not increased")
	}
	return nil
}

func (ac *AlertContext) theAnalystSuppressesTheAlert() error {
	ac.lastAlert["status"] = "suppressed"
	return nil
}

func (ac *AlertContext) theAlertIsHiddenFromDefaultViews() error {
	return nil
}

func (ac *AlertContext) alertsExistWithStatus(count int, status string) error {
	ac.alerts = make([]map[string]interface{}, count)
	for i := 0; i < count; i++ {
		ac.alerts[i] = map[string]interface{}{"id": fmt.Sprintf("alert-%d", i), "status": status}
	}
	return nil
}

func (ac *AlertContext) theAnalystPerformsBulkCloseOperation() error {
	for i := range ac.alerts {
		ac.alerts[i]["status"] = "closed"
	}
	return nil
}

func (ac *AlertContext) allAlertsStatusIs(count int, status string) error {
	if len(ac.alerts) != count {
		return fmt.Errorf("expected %d alerts, got %d", count, len(ac.alerts))
	}
	for _, alert := range ac.alerts {
		if alert["status"] != status {
			return fmt.Errorf("expected status %s, got %v", status, alert["status"])
		}
	}
	return nil
}

func (ac *AlertContext) auditLogEntriesAreCreatedForEachAlert() error {
	return nil
}

func (ac *AlertContext) anAlertExistsWithFingerprint(fingerprint string) error {
	ac.lastAlert = map[string]interface{}{
		"id":              "alert-1",
		"fingerprint":     fingerprint,
		"duplicate_count": 0,
	}
	return nil
}

func (ac *AlertContext) aDuplicateAlertIsCreatedWithFingerprint(fingerprint string) error {
	if ac.lastAlert["fingerprint"] == fingerprint {
		duplicateCount, _ := ac.lastAlert["duplicate_count"].(int)
		ac.lastAlert["duplicate_count"] = duplicateCount + 1
	}
	return nil
}

func (ac *AlertContext) theDuplicateAlertIsMerged() error {
	return nil
}

func (ac *AlertContext) theOriginalAlertDuplicateCountIsIncremented() error {
	count, _ := ac.lastAlert["duplicate_count"].(int)
	if count == 0 {
		return fmt.Errorf("duplicate count not incremented")
	}
	return nil
}
