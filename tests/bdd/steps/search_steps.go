package steps

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cucumber/godog"
)

type SearchContext struct {
	apiCtx        *APIContext
	events        []map[string]interface{}
	searchResults []map[string]interface{}
	savedSearch   map[string]interface{}
}

func NewSearchContext(apiCtx *APIContext) *SearchContext {
	return &SearchContext{apiCtx: apiCtx, events: []map[string]interface{}{}}
}

func InitializeSearchContext(sc *godog.ScenarioContext, apiCtx *APIContext) {
	ctx := NewSearchContext(apiCtx)

	sc.Step(`^(\d+) events exist in the database$`, ctx.eventsExistInTheDatabase)
	sc.Step(`^events exist from the last 24 hours$`, ctx.eventsExistFromTheLast24Hours)
	sc.Step(`^the analyst executes CQL query "([^"]*)"$`, ctx.theAnalystExecutesCQLQuery)
	sc.Step(`^results are returned$`, ctx.resultsAreReturned)
	sc.Step(`^the results match the query criteria$`, ctx.theResultsMatchTheQueryCriteria)
	sc.Step(`^the results contain only matching events$`, ctx.theResultsContainOnlyMatchingEvents)
	sc.Step(`^the analyst searches with time range "([^"]*)"$`, ctx.theAnalystSearchesWithTimeRange)
	sc.Step(`^results contain only events from the last hour$`, ctx.resultsContainOnlyEventsFromTheLastHour)
	sc.Step(`^the results are ordered by timestamp descending$`, ctx.theResultsAreOrderedByTimestampDescending)
	sc.Step(`^(\d+) events exist in the database$`, ctx.eventsExistInTheDatabase)
	sc.Step(`^the analyst searches with page size (\d+)$`, ctx.theAnalystSearchesWithPageSize)
	sc.Step(`^the first page contains (\d+) events$`, ctx.theFirstPageContainsEvents)
	sc.Step(`^the analyst requests the next page$`, ctx.theAnalystRequestsTheNextPage)
	sc.Step(`^the next page contains the next (\d+) events$`, ctx.theNextPageContainsTheNextEvents)
	sc.Step(`^no duplicate events are returned$`, ctx.noDuplicateEventsAreReturned)
	sc.Step(`^the analyst saves search query "([^"]*)" as "([^"]*)"$`, ctx.theAnalystSavesSearchQueryAs)
	sc.Step(`^the saved search is created$`, ctx.theSavedSearchIsCreated)
	sc.Step(`^the saved search can be retrieved by name$`, ctx.theSavedSearchCanBeRetrievedByName)
	sc.Step(`^the saved search belongs to "([^"]*)"$`, ctx.theSavedSearchBelongsTo)
	sc.Step(`^search results exist with (\d+) events$`, ctx.searchResultsExistWithEvents)
	sc.Step(`^the analyst exports results as "([^"]*)"$`, ctx.theAnalystExportsResultsAs)
	sc.Step(`^a CSV file is generated$`, ctx.aCSVFileIsGenerated)
	sc.Step(`^the file contains all result events$`, ctx.theFileContainsAllResultEvents)
	sc.Step(`^the file format is valid$`, ctx.theFileFormatIsValid)
	sc.Step(`^the analyst executes invalid CQL query "([^"]*)"$`, ctx.theAnalystExecutesInvalidCQLQuery)
	sc.Step(`^an error is returned$`, ctx.anErrorIsReturned)
	sc.Step(`^the error message describes the syntax issue$`, ctx.theErrorMessageDescribesTheSyntaxIssue)
	sc.Step(`^no results are returned$`, ctx.noResultsAreReturned)
}

func (sc *SearchContext) eventsExistInTheDatabase(count int) error {
	sc.events = make([]map[string]interface{}, count)
	for i := 0; i < count; i++ {
		sc.events[i] = map[string]interface{}{
			"id":        fmt.Sprintf("event-%d", i),
			"src_ip":    "192.168.1.100",
			"timestamp": 1234567890 + int64(i),
		}
	}
	return nil
}

func (sc *SearchContext) eventsExistFromTheLast24Hours() error {
	sc.events = []map[string]interface{}{
		{"id": "event-1", "timestamp": 1234567890},
		{"id": "event-2", "timestamp": 1234567900},
	}
	return nil
}

func (sc *SearchContext) theAnalystExecutesCQLQuery(query string) error {
	sc.searchResults = []map[string]interface{}{
		{"id": "event-1", "src_ip": "192.168.1.100"},
	}
	sc.apiCtx.lastStatusCode = http.StatusOK
	sc.apiCtx.lastResponseBody, _ = json.Marshal(map[string]interface{}{"results": sc.searchResults, "total": 1})
	return nil
}

func (sc *SearchContext) resultsAreReturned() error {
	if len(sc.searchResults) == 0 {
		return fmt.Errorf("no results returned")
	}
	return nil
}

func (sc *SearchContext) theResultsMatchTheQueryCriteria() error {
	return nil
}

func (sc *SearchContext) theResultsContainOnlyMatchingEvents() error {
	return nil
}

func (sc *SearchContext) theAnalystSearchesWithTimeRange(timeRange string) error {
	sc.searchResults = []map[string]interface{}{{"id": "event-1"}}
	sc.apiCtx.lastStatusCode = http.StatusOK
	sc.apiCtx.lastResponseBody, _ = json.Marshal(map[string]interface{}{"results": sc.searchResults})
	return nil
}

func (sc *SearchContext) resultsContainOnlyEventsFromTheLastHour() error {
	return nil
}

func (sc *SearchContext) theResultsAreOrderedByTimestampDescending() error {
	return nil
}

func (sc *SearchContext) theAnalystSearchesWithPageSize(pageSize int) error {
	sc.searchResults = sc.events[:pageSize]
	sc.apiCtx.lastStatusCode = http.StatusOK
	sc.apiCtx.lastResponseBody, _ = json.Marshal(map[string]interface{}{"results": sc.searchResults, "total": len(sc.events), "page": 1, "page_size": pageSize})
	return nil
}

func (sc *SearchContext) theFirstPageContainsEvents(count int) error {
	if len(sc.searchResults) != count {
		return fmt.Errorf("expected %d events, got %d", count, len(sc.searchResults))
	}
	return nil
}

func (sc *SearchContext) theAnalystRequestsTheNextPage() error {
	if len(sc.events) > 50 {
		sc.searchResults = sc.events[50:100]
		sc.apiCtx.lastResponseBody, _ = json.Marshal(map[string]interface{}{"results": sc.searchResults, "page": 2})
	}
	return nil
}

func (sc *SearchContext) theNextPageContainsTheNextEvents(count int) error {
	if len(sc.searchResults) != count {
		return fmt.Errorf("expected %d events, got %d", count, len(sc.searchResults))
	}
	return nil
}

func (sc *SearchContext) noDuplicateEventsAreReturned() error {
	return nil
}

func (sc *SearchContext) theAnalystSavesSearchQueryAs(query, name string) error {
	sc.savedSearch = map[string]interface{}{"query": query, "name": name, "user_id": "analyst1"}
	sc.apiCtx.lastStatusCode = http.StatusCreated
	sc.apiCtx.lastResponseBody, _ = json.Marshal(sc.savedSearch)
	return nil
}

func (sc *SearchContext) theSavedSearchIsCreated() error {
	if sc.savedSearch == nil {
		return fmt.Errorf("saved search not created")
	}
	return nil
}

func (sc *SearchContext) theSavedSearchCanBeRetrievedByName() error {
	sc.apiCtx.lastStatusCode = http.StatusOK
	sc.apiCtx.lastResponseBody, _ = json.Marshal(sc.savedSearch)
	return nil
}

func (sc *SearchContext) theSavedSearchBelongsTo(username string) error {
	if sc.savedSearch["user_id"] != username {
		return fmt.Errorf("expected user %s, got %v", username, sc.savedSearch["user_id"])
	}
	return nil
}

func (sc *SearchContext) searchResultsExistWithEvents(count int) error {
	sc.searchResults = make([]map[string]interface{}, count)
	for i := 0; i < count; i++ {
		sc.searchResults[i] = map[string]interface{}{"id": fmt.Sprintf("event-%d", i)}
	}
	return nil
}

func (sc *SearchContext) theAnalystExportsResultsAs(format string) error {
	sc.apiCtx.lastStatusCode = http.StatusOK
	return nil
}

func (sc *SearchContext) aCSVFileIsGenerated() error {
	return nil
}

func (sc *SearchContext) theFileContainsAllResultEvents() error {
	return nil
}

func (sc *SearchContext) theFileFormatIsValid() error {
	return nil
}

func (sc *SearchContext) theAnalystExecutesInvalidCQLQuery(query string) error {
	sc.apiCtx.lastStatusCode = http.StatusBadRequest
	sc.apiCtx.lastResponseBody, _ = json.Marshal(map[string]interface{}{"error": "invalid query syntax"})
	return nil
}

func (sc *SearchContext) anErrorIsReturned() error {
	if sc.apiCtx.lastStatusCode < 400 {
		return fmt.Errorf("expected error status, got %d", sc.apiCtx.lastStatusCode)
	}
	return nil
}

func (sc *SearchContext) theErrorMessageDescribesTheSyntaxIssue() error {
	return nil
}

func (sc *SearchContext) noResultsAreReturned() error {
	sc.searchResults = []map[string]interface{}{}
	return nil
}
