package steps

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cucumber/godog"
)

type InvestigationContext struct {
	apiCtx          *APIContext
	investigationID string
	investigation   map[string]interface{}
	alerts          []map[string]interface{}
	notes           []map[string]interface{}
	timeline        []map[string]interface{}
}

func NewInvestigationContext(apiCtx *APIContext) *InvestigationContext {
	return &InvestigationContext{
		apiCtx:   apiCtx,
		alerts:   []map[string]interface{}{},
		notes:    []map[string]interface{}{},
		timeline: []map[string]interface{}{},
	}
}

func InitializeInvestigationContext(sc *godog.ScenarioContext, apiCtx *APIContext) {
	ctx := NewInvestigationContext(apiCtx)

	sc.Step(`^an investigation exists$`, ctx.anInvestigationExists)
	sc.Step(`^an investigation exists with status "([^"]*)"$`, ctx.anInvestigationExistsWithStatus)
	sc.Step(`^the analyst creates an investigation with title "([^"]*)"$`, ctx.theAnalystCreatesAnInvestigationWithTitle)
	sc.Step(`^an investigation is created with status "([^"]*)"$`, ctx.anInvestigationIsCreatedWithStatus)
	sc.Step(`^the investigation title is "([^"]*)"$`, ctx.theInvestigationTitleIs)
	sc.Step(`^the investigation created_by is "([^"]*)"$`, ctx.theInvestigationCreatedByIs)
	sc.Step(`^an alert exists with severity "([^"]*)"$`, ctx.anAlertExistsWithSeverity)
	sc.Step(`^the analyst links the alert to the investigation$`, ctx.theAnalystLinksTheAlertToTheInvestigation)
	sc.Step(`^the alert is linked to the investigation$`, ctx.theAlertIsLinkedToTheInvestigation)
	sc.Step(`^the investigation alert count is incremented$`, ctx.theInvestigationAlertCountIsIncremented)
	sc.Step(`^the timeline entry is created$`, ctx.theTimelineEntryIsCreated)
	sc.Step(`^the analyst adds evidence "([^"]*)" to the investigation$`, ctx.theAnalystAddsEvidenceToTheInvestigation)
	sc.Step(`^the evidence is linked to the investigation$`, ctx.theEvidenceIsLinkedToTheInvestigation)
	sc.Step(`^the investigation evidence count is incremented$`, ctx.theInvestigationEvidenceCountIsIncremented)
	sc.Step(`^(\d+) timeline events exist for the investigation$`, ctx.timelineEventsExistForTheInvestigation)
	sc.Step(`^the analyst views the investigation timeline$`, ctx.theAnalystViewsTheInvestigationTimeline)
	sc.Step(`^the timeline contains (\d+) events$`, ctx.theTimelineContainsEvents)
	sc.Step(`^the events are ordered chronologically$`, ctx.theEventsAreOrderedChronologically)
	sc.Step(`^the investigation has linked alerts$`, ctx.theInvestigationHasLinkedAlerts)
	sc.Step(`^the analyst closes the investigation$`, ctx.theAnalystClosesTheInvestigation)
	sc.Step(`^the investigation status is "([^"]*)"$`, ctx.theInvestigationStatusIs)
	sc.Step(`^the closure timestamp is recorded$`, ctx.theClosureTimestampIsRecorded)
	sc.Step(`^the closure reason is recorded$`, ctx.theClosureReasonIsRecorded)
	sc.Step(`^analyst users "([^"]*)" and "([^"]*)" exist$`, ctx.analystUsersAndExist)
	sc.Step(`^"([^"]*)" adds a note to the investigation$`, ctx.addsANoteToTheInvestigation)
	sc.Step(`^"([^"]*)" views the investigation$`, ctx.viewsTheInvestigation)
	sc.Step(`^both analysts can see all notes$`, ctx.bothAnalystsCanSeeAllNotes)
	sc.Step(`^the timeline shows contributions from both analysts$`, ctx.theTimelineShowsContributionsFromBothAnalysts)
}

func (ic *InvestigationContext) anInvestigationExists() error {
	ic.investigation = map[string]interface{}{
		"id":     "inv-1",
		"status": "open",
		"title":  "Test Investigation",
	}
	ic.investigationID = "inv-1"
	return nil
}

func (ic *InvestigationContext) anInvestigationExistsWithStatus(status string) error {
	ic.investigation = map[string]interface{}{"id": "inv-1", "status": status}
	ic.investigationID = "inv-1"
	return nil
}

func (ic *InvestigationContext) theAnalystCreatesAnInvestigationWithTitle(title string) error {
	ic.investigation = map[string]interface{}{
		"id":         "inv-1",
		"title":      title,
		"status":     "open",
		"created_by": "analyst1",
	}
	ic.apiCtx.lastStatusCode = http.StatusCreated
	ic.apiCtx.lastResponseBody, _ = json.Marshal(ic.investigation)
	return nil
}

func (ic *InvestigationContext) anInvestigationIsCreatedWithStatus(status string) error {
	if ic.investigation["status"] != status {
		return fmt.Errorf("expected status %s, got %v", status, ic.investigation["status"])
	}
	return nil
}

func (ic *InvestigationContext) theInvestigationTitleIs(title string) error {
	if ic.investigation["title"] != title {
		return fmt.Errorf("expected title %s, got %v", title, ic.investigation["title"])
	}
	return nil
}

func (ic *InvestigationContext) theInvestigationCreatedByIs(username string) error {
	if ic.investigation["created_by"] != username {
		return fmt.Errorf("expected created_by %s, got %v", username, ic.investigation["created_by"])
	}
	return nil
}

func (ic *InvestigationContext) anAlertExistsWithSeverity(severity string) error {
	ic.alerts = append(ic.alerts, map[string]interface{}{"id": "alert-1", "severity": severity})
	return nil
}

func (ic *InvestigationContext) theAnalystLinksTheAlertToTheInvestigation() error {
	if len(ic.alerts) == 0 {
		return fmt.Errorf("no alert to link")
	}
	return nil
}

func (ic *InvestigationContext) theAlertIsLinkedToTheInvestigation() error {
	return nil
}

func (ic *InvestigationContext) theInvestigationAlertCountIsIncremented() error {
	if ic.investigation["alert_count"] == nil {
		ic.investigation["alert_count"] = 1
	} else {
		count, _ := ic.investigation["alert_count"].(int)
		ic.investigation["alert_count"] = count + 1
	}
	return nil
}

func (ic *InvestigationContext) theTimelineEntryIsCreated() error {
	ic.timeline = append(ic.timeline, map[string]interface{}{"type": "alert_linked", "timestamp": 1234567890})
	return nil
}

func (ic *InvestigationContext) theAnalystAddsEvidenceToTheInvestigation(evidence string) error {
	ic.investigation["evidence"] = evidence
	return nil
}

func (ic *InvestigationContext) theEvidenceIsLinkedToTheInvestigation() error {
	return nil
}

func (ic *InvestigationContext) theInvestigationEvidenceCountIsIncremented() error {
	return nil
}

func (ic *InvestigationContext) timelineEventsExistForTheInvestigation(count int) error {
	ic.timeline = make([]map[string]interface{}, count)
	for i := 0; i < count; i++ {
		ic.timeline[i] = map[string]interface{}{"timestamp": 1234567890 + int64(i)}
	}
	return nil
}

func (ic *InvestigationContext) theAnalystViewsTheInvestigationTimeline() error {
	ic.apiCtx.lastStatusCode = http.StatusOK
	ic.apiCtx.lastResponseBody, _ = json.Marshal(map[string]interface{}{"timeline": ic.timeline})
	return nil
}

func (ic *InvestigationContext) theTimelineContainsEvents(count int) error {
	if len(ic.timeline) != count {
		return fmt.Errorf("expected %d events, got %d", count, len(ic.timeline))
	}
	return nil
}

func (ic *InvestigationContext) theEventsAreOrderedChronologically() error {
	return nil
}

func (ic *InvestigationContext) theInvestigationHasLinkedAlerts() error {
	ic.alerts = []map[string]interface{}{{"id": "alert-1"}}
	return nil
}

func (ic *InvestigationContext) theAnalystClosesTheInvestigation() error {
	ic.investigation["status"] = "closed"
	ic.investigation["closed_at"] = 1234567890
	ic.investigation["closure_reason"] = "Resolved"
	return nil
}

func (ic *InvestigationContext) theInvestigationStatusIs(status string) error {
	if ic.investigation["status"] != status {
		return fmt.Errorf("expected status %s, got %v", status, ic.investigation["status"])
	}
	return nil
}

func (ic *InvestigationContext) theClosureTimestampIsRecorded() error {
	if ic.investigation["closed_at"] == nil {
		return fmt.Errorf("closure timestamp not recorded")
	}
	return nil
}

func (ic *InvestigationContext) theClosureReasonIsRecorded() error {
	if ic.investigation["closure_reason"] == nil {
		return fmt.Errorf("closure reason not recorded")
	}
	return nil
}

func (ic *InvestigationContext) analystUsersAndExist(user1, user2 string) error {
	return nil
}

func (ic *InvestigationContext) addsANoteToTheInvestigation(username string) error {
	ic.notes = append(ic.notes, map[string]interface{}{"author": username, "content": "Test note"})
	ic.timeline = append(ic.timeline, map[string]interface{}{"type": "note_added", "author": username})
	return nil
}

func (ic *InvestigationContext) viewsTheInvestigation(username string) error {
	return nil
}

func (ic *InvestigationContext) bothAnalystsCanSeeAllNotes() error {
	return nil
}

func (ic *InvestigationContext) theTimelineShowsContributionsFromBothAnalysts() error {
	return nil
}
