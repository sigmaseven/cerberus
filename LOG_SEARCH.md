# Event Log Search Functionality - Feature Plan

## Table of Contents
1. [Overview](#overview)
2. [Query Language Specification](#query-language-specification)
3. [Functional Requirements](#functional-requirements)
4. [Acceptance Criteria](#acceptance-criteria)
5. [Wireframe Layouts](#wireframe-layouts)
6. [Technical Implementation](#technical-implementation)
7. [API Specification](#api-specification)
8. [Database Schema](#database-schema)
9. [Frontend Components](#frontend-components)
10. [Implementation Phases](#implementation-phases)

---

## Overview

The Event Log Search functionality provides users with a powerful query language to search, filter, and analyze security events stored in the SIEM. The interface will be similar to the Rules page with pagination, advanced filtering capabilities, and the ability to save/load searches.

### Key Features
- Advanced query language (CQL - Cerberus Query Language)
- Real-time search with pagination
- Save and manage search queries
- Export search results
- Time range filtering
- Field-based filtering using the same logic as detection rules
- Query builder UI with manual query editor fallback

---

## Query Language Specification

### Cerberus Query Language (CQL)

CQL is inspired by Splunk SPL, Elastic KQL, and SQL, designed to be intuitive for security analysts while providing powerful filtering capabilities.

#### Basic Syntax

```
field operator value [logic field operator value...]
```

#### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `=` or `equals` | Exact match | `event_type equals "security"` |
| `!=` or `not_equals` | Not equal | `severity != "Low"` |
| `contains` | String contains | `message contains "failed"` |
| `startswith` | String starts with | `user startswith "admin"` |
| `endswith` | String ends with | `filename endswith ".exe"` |
| `>` or `gt` | Greater than | `event_id > 4624` |
| `<` or `lt` | Less than | `port < 1024` |
| `>=` or `gte` | Greater than or equal | `severity_score >= 7` |
| `<=` or `lte` | Less than or equal | `response_time <= 100` |
| `in` | Value in list | `status in ["active", "pending"]` |
| `not in` | Value not in list | `user not in ["system", "root"]` |
| `matches` or `~=` | Regex match | `ip_address matches "192\.168\..*"` |
| `exists` | Field exists | `fields.error_code exists` |
| `not exists` | Field does not exist | `fields.username not exists` |

#### Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `AND` or `&&` | Both conditions must be true | `event_type = "security" AND severity = "High"` |
| `OR` or `\|\|` | Either condition must be true | `event_type = "login" OR event_type = "logout"` |
| `NOT` or `!` | Negates condition | `NOT user = "system"` |

#### Grouping

Use parentheses to group conditions:

```
(event_type = "login" OR event_type = "logout") AND severity = "High"
```

#### Time Range Filters

Special syntax for time-based filtering:

```
@timestamp > "2025-01-01T00:00:00Z"
@timestamp between "2025-01-01" and "2025-01-31"
@timestamp last 24h
@timestamp last 7d
@timestamp last 30d
```

Time units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks), `mo` (months)

#### Nested Field Access

Access nested fields using dot notation:

```
fields.user = "admin"
fields.source.ip = "192.168.1.1"
metadata.severity >= 7
```

#### Complex Query Examples

**Example 1: Failed login attempts from specific IP range**
```
event_type = "authentication_failure" AND
fields.source_ip matches "10\.0\..*" AND
@timestamp last 24h
```

**Example 2: High severity security events excluding system user**
```
(severity = "High" OR severity = "Critical") AND
event_type contains "security" AND
NOT fields.user = "system"
```

**Example 3: Multiple event types with specific conditions**
```
(
  (event_type = "file_access" AND fields.action = "read") OR
  (event_type = "file_modify" AND fields.filename endswith ".config")
) AND
@timestamp last 7d
```

**Example 4: Complex nested conditions**
```
event_type = "network_connection" AND
(
  (fields.destination_port in [80, 443, 8080] AND fields.protocol = "tcp") OR
  (fields.destination_port = 53 AND fields.protocol = "udp")
) AND
fields.bytes_sent > 1000000
```

#### Query Functions

Special functions for advanced operations:

```
count() - Count matching events
sum(field) - Sum numeric field values
avg(field) - Average of numeric field
min(field) - Minimum value
max(field) - Maximum value
distinct(field) - Unique values
```

**Aggregation Example:**
```
event_type = "login" | count() by fields.user
event_type = "network_connection" | sum(fields.bytes_sent) by fields.destination_ip
```

---

## Functional Requirements

### FR-1: Event Search Interface

**Description:** Users can search events using the query language or visual query builder.

**Requirements:**
- FR-1.1: Display paginated list of events (10, 25, 50, 100, 250, 500 per page)
- FR-1.2: Support manual query input via text field
- FR-1.3: Provide visual query builder as an alternative to manual queries
- FR-1.4: Real-time query validation with error highlighting
- FR-1.5: Auto-complete suggestions for field names and operators
- FR-1.6: Quick time range selector (Last 15m, 1h, 24h, 7d, 30d, Custom)
- FR-1.7: Display total result count
- FR-1.8: Show query execution time

### FR-2: Search Results Display

**Description:** Display search results in a clear, actionable format.

**Requirements:**
- FR-2.1: Display events in reverse chronological order (newest first)
- FR-2.2: Show key fields: timestamp, event_type, severity, source_ip, message
- FR-2.3: Expandable rows to show full event details
- FR-2.4: Color-coded severity indicators
- FR-2.5: Copy event data to clipboard
- FR-2.6: Link to related alerts/rules if applicable
- FR-2.7: Field highlighting for matched search terms
- FR-2.8: Column customization (show/hide fields)

### FR-3: Saved Searches

**Description:** Users can save, manage, and share search queries.

**Requirements:**
- FR-3.1: Save search queries with custom names and descriptions
- FR-3.2: Load saved searches from a dropdown or list
- FR-3.3: Edit existing saved searches
- FR-3.4: Delete saved searches with confirmation
- FR-3.5: Share saved searches with other users (optional)
- FR-3.6: Set default search for the page
- FR-3.7: Tag/categorize saved searches
- FR-3.8: Search history (last 10 searches)

### FR-4: Export Functionality

**Description:** Export search results in various formats.

**Requirements:**
- FR-4.1: Export to JSON format
- FR-4.2: Export to CSV format
- FR-4.3: Export current page or all results (with size limits)
- FR-4.4: Include query metadata in export (query, time range, timestamp)
- FR-4.5: Progress indicator for large exports
- FR-4.6: Download file with descriptive filename

### FR-5: Query Builder

**Description:** Visual interface for building queries without writing CQL.

**Requirements:**
- FR-5.1: Add/remove filter conditions
- FR-5.2: Select field from dropdown (populated from event schema)
- FR-5.3: Select operator based on field type
- FR-5.4: Input value with appropriate UI (text, number, date picker, dropdown)
- FR-5.5: Group conditions with AND/OR logic
- FR-5.6: Nested condition groups
- FR-5.7: Preview generated CQL query
- FR-5.8: Switch between builder and manual editor modes
- FR-5.9: Validate conditions in real-time

### FR-6: Performance & Optimization

**Description:** Ensure fast query execution and responsive UI.

**Requirements:**
- FR-6.1: Query execution time < 2 seconds for standard queries
- FR-6.2: Support querying up to 10M events efficiently
- FR-6.3: Index optimization for common query patterns
- FR-6.4: Query result caching (5 minute TTL)
- FR-6.5: Progressive loading for large result sets
- FR-6.6: Query timeout after 30 seconds with partial results
- FR-6.7: Prevent overly broad queries (require time range for wildcard searches)

### FR-7: Event Details Modal

**Description:** Detailed view of individual events.

**Requirements:**
- FR-7.1: Display all event fields in structured format
- FR-7.2: JSON tree view for nested data
- FR-7.3: Copy individual field values
- FR-7.4: Copy entire event as JSON
- FR-7.5: Link to related events (same source_ip, same user, etc.)
- FR-7.6: Show which rules matched this event (if any)
- FR-7.7: Timeline context (events before/after)
- FR-7.8: Navigate to next/previous event in results

### FR-8: Query Syntax Help

**Description:** In-application help for query syntax.

**Requirements:**
- FR-8.1: Syntax reference modal with examples
- FR-8.2: Inline help tooltips for operators
- FR-8.3: Example queries for common use cases
- FR-8.4: Link to full documentation
- FR-8.5: Field reference with data types

---

## Acceptance Criteria

### AC-1: Query Language Execution

**Given** a user enters a valid CQL query
**When** they execute the search
**Then** the system returns matching events within 2 seconds
**And** displays accurate result count
**And** shows events in descending chronological order

### AC-2: Field-Based Filtering

**Given** a user searches for `event_type = "login" AND severity = "High"`
**When** the query executes
**Then** all returned events have event_type of "login"
**And** all returned events have severity of "High"
**And** no events are returned that don't match both conditions

### AC-3: Numeric Comparison

**Given** a user searches for `fields.event_id > 4624`
**When** the query executes
**Then** all returned events have event_id greater than 4624
**And** numeric comparison is performed correctly (not string comparison)

### AC-4: Time Range Filtering

**Given** a user searches with `@timestamp last 24h`
**When** the query executes
**Then** all returned events are within the last 24 hours
**And** no events older than 24 hours are returned

### AC-5: Regex Matching

**Given** a user searches with `fields.ip_address matches "192\.168\..*"`
**When** the query executes
**Then** all returned events have IP addresses starting with 192.168.
**And** regex special characters are properly handled

### AC-6: Nested Field Access

**Given** a user searches for `fields.user.name = "admin"`
**When** the query executes
**Then** the system correctly accesses the nested field
**And** returns events where the nested field matches

### AC-7: Complex Query Logic

**Given** a user searches with `(A AND B) OR (C AND D)`
**When** the query executes
**Then** the system respects operator precedence
**And** returns events matching either group of conditions

### AC-8: Pagination

**Given** search results exceed page size
**When** a user navigates between pages
**Then** the correct page of results is displayed
**And** page numbers are accurate
**And** total count remains consistent

### AC-9: Saved Searches

**Given** a user saves a search query
**When** they load the saved search later
**Then** the exact query is restored
**And** the search executes with the same parameters
**And** the saved search appears in the saved searches list

### AC-10: Export Functionality

**Given** a user exports search results to JSON
**When** the export completes
**Then** a valid JSON file is downloaded
**And** all visible events are included
**And** the file contains query metadata

### AC-11: Query Validation

**Given** a user enters an invalid CQL query
**When** they attempt to execute it
**Then** the system displays a clear error message
**And** highlights the error location (if possible)
**And** prevents execution until the query is valid

### AC-12: Query Builder to CQL

**Given** a user builds a query using the visual builder
**When** they add conditions and logic
**Then** the generated CQL query is syntactically correct
**And** the CQL query matches the visual representation
**And** executing the generated query returns expected results

---

## Wireframe Layouts

### Main Event Search Page

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Cerberus SIEM                                     [Username] [Settings] [?] │
├─────────────────────────────────────────────────────────────────────────────┤
│ [Dashboard][Events][Alerts][Rules][Corr Rules][Actions][Listeners]         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Event Search                                                               │
│  ────────────────────                                                       │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Search Query                                                          │ │
│  │ ┌───────────────────────────────────────────────────────────────────┐ │ │
│  │ │ event_type = "login" AND severity = "High"                        │ │ │
│  │ └───────────────────────────────────────────────────────────────────┘ │ │
│  │ [Builder Mode] [Manual Mode]          [Syntax Help ?]   [Clear]      │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Time Range:                                                           │ │
│  │ ● Last 15 min  ○ Last 1 hour  ○ Last 24 hours  ○ Last 7 days        │ │
│  │ ○ Last 30 days  ○ Custom Range: [Start Date] to [End Date]          │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  [🔍 Search] [💾 Save Search] [📁 Load Search ▼] [📥 Export ▼]             │
│                                                                             │
│  ────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│  Search Results: 1,247 events found in 0.3s                                │
│                                                                             │
│  Show: [50 ▼] per page                [Columns ▼]    Page 1 of 25  [◀ ▶]  │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │Timestamp             Event Type       Severity   Source IP    ▼ │ │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │► 2025-11-04 11:45:32  login             🔴 High    192.168.1.50  │ │   │
│  │  User: admin | Message: Failed login attempt                    │ │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │► 2025-11-04 11:45:28  login             🔴 High    192.168.1.50  │ │   │
│  │  User: admin | Message: Failed login attempt                    │ │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │▼ 2025-11-04 11:45:15  login             🔴 High    10.0.0.15     │ │   │
│  │  User: root | Message: Failed login attempt                     │ │   │
│  │  ┌──────────────────────────────────────────────────────────────┐│ │   │
│  │  │ Event ID: evt_789012345                                      ││ │   │
│  │  │ Event Type: login                                            ││ │   │
│  │  │ Timestamp: 2025-11-04T11:45:15.234Z                          ││ │   │
│  │  │ Severity: High                                               ││ │   │
│  │  │ Source IP: 10.0.0.15                                         ││ │   │
│  │  │ Fields:                                                      ││ │   │
│  │  │   - user: root                                               ││ │   │
│  │  │   - auth_method: password                                    ││ │   │
│  │  │   - status: failure                                          ││ │   │
│  │  │   - attempt_count: 5                                         ││ │   │
│  │  │ Message: Failed login attempt                                ││ │   │
│  │  │ [View Details] [Copy JSON] [Related Events]                  ││ │   │
│  │  └──────────────────────────────────────────────────────────────┘│ │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │► 2025-11-04 11:45:10  login             🔴 High    192.168.1.23  │ │   │
│  │  User: admin | Message: Failed login attempt                    │ │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │► 2025-11-04 11:44:58  login             🔴 High    192.168.1.50  │ │   │
│  │  User: admin | Message: Failed login attempt                    │ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Page 1 of 25                                              [◀ 1 2 3 ... ▶] │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Query Builder Modal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Query Builder                                                      [✕ Close] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Build your search query visually                                          │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Condition Group 1                                          [Delete X] │ │
│  │                                                                       │ │
│  │ ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │ │ Field             Operator          Value                       │   │ │
│  │ │ [event_type ▼]    [equals ▼]        [login          ]          │   │ │
│  │ └─────────────────────────────────────────────────────────────────┘   │ │
│  │ [AND ▼]                                                               │ │
│  │ ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │ │ Field             Operator          Value                       │   │ │
│  │ │ [severity ▼]      [equals ▼]        [High ▼]                    │   │ │
│  │ └─────────────────────────────────────────────────────────────────┘   │ │
│  │                                                                       │ │
│  │ [+ Add Condition] [+ Add Nested Group]                                │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  [OR ▼]                                                                     │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Condition Group 2                                          [Delete X] │ │
│  │                                                                       │ │
│  │ ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │ │ Field             Operator          Value                       │   │ │
│  │ │ [event_type ▼]    [equals ▼]        [logout         ]          │   │ │
│  │ └─────────────────────────────────────────────────────────────────┘   │ │
│  │                                                                       │ │
│  │ [+ Add Condition] [+ Add Nested Group]                                │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  [+ Add Condition Group]                                                    │
│                                                                             │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│  Generated Query:                                                           │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ (event_type = "login" AND severity = "High") OR                       │ │
│  │ (event_type = "logout")                                               │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  [Apply Query] [Cancel]                                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Event Details Modal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Event Details                                 [◀ Prev] [Next ▶]  [✕ Close] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Event ID: evt_789012345                                   [Copy All JSON] │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Core Fields                                                           │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ Timestamp:      2025-11-04T11:45:15.234Z            [Copy]            │ │
│  │ Event Type:     login                               [Copy]            │ │
│  │ Severity:       🔴 High                              [Copy]            │ │
│  │ Source IP:      10.0.0.15                           [Copy]            │ │
│  │ Source Format:  syslog                              [Copy]            │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Custom Fields                                                         │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ ▼ fields                                                              │ │
│  │   │                                                                   │ │
│  │   ├─ user:           root                           [Copy]            │ │
│  │   ├─ auth_method:    password                       [Copy]            │ │
│  │   ├─ status:         failure                        [Copy]            │ │
│  │   ├─ attempt_count:  5                              [Copy]            │ │
│  │   └─ source_port:    52341                          [Copy]            │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Message                                                               │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ Failed login attempt for user 'root' from 10.0.0.15                   │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Matched Rules                                                         │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ • Failed Login Attempts (High Severity)                               │ │
│  │ • Brute Force Detection                                               │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Related Events                                                        │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ [Same Source IP]  [Same User]  [Same Event Type]  [Timeline Context] │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Raw JSON                                                   [▼ Expand] │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ {                                                                     │ │
│  │   "event_id": "evt_789012345",                                        │ │
│  │   "event_type": "login",                                              │ │
│  │   "timestamp": "2025-11-04T11:45:15.234Z",                            │ │
│  │   "severity": "High",                                                 │ │
│  │   ...                                                                 │ │
│  │ }                                                                     │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  [Close]                                                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Save Search Modal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Save Search                                                       [✕ Close] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Save this search query for quick access later                             │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Search Name *                                                         │ │
│  │ ┌───────────────────────────────────────────────────────────────────┐ │ │
│  │ │ High Severity Login Failures                                      │ │ │
│  │ └───────────────────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Description                                                           │ │
│  │ ┌───────────────────────────────────────────────────────────────────┐ │ │
│  │ │ Track all high severity failed login attempts for security        │ │ │
│  │ │ monitoring                                                        │ │ │
│  │ └───────────────────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Query                                                                 │ │
│  │ ┌───────────────────────────────────────────────────────────────────┐ │ │
│  │ │ event_type = "login" AND severity = "High"                        │ │ │
│  │ └───────────────────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Tags (optional)                                                       │ │
│  │ ┌───────────────────────────────────────────────────────────────────┐ │ │
│  │ │ [authentication ×] [security ×] [monitoring ×]  [+ Add tag]       │ │ │
│  │ └───────────────────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ☐ Save time range with query                                              │
│  ☐ Set as default search                                                   │
│  ☐ Share with other users                                                  │
│                                                                             │
│  [Save Search] [Cancel]                                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Saved Searches Management Modal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Saved Searches                                                    [✕ Close] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Manage your saved search queries                                          │
│                                                                             │
│  [Search saved queries...]                    [Sort by: Recent ▼]          │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ ⭐ High Severity Login Failures                                       │ │
│  │    authentication, security, monitoring                               │ │
│  │    Query: event_type = "login" AND severity = "High"                  │ │
│  │    Last used: 2025-11-04 10:30                                        │ │
│  │    [Load] [Edit] [Delete]                                             │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ Network Anomalies                                                     │ │
│  │    network, anomaly                                                   │ │
│  │    Query: event_type = "network_connection" AND fields.bytes_sent...  │ │
│  │    Last used: 2025-11-03 15:45                                        │ │
│  │    [Load] [Edit] [Delete]                                             │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ File Modification Tracking                                            │ │
│  │    file, security                                                     │ │
│  │    Query: event_type = "file_modify" AND fields.filename endswith...  │ │
│  │    Last used: 2025-11-02 09:20                                        │ │
│  │    [Load] [Edit] [Delete]                                             │ │
│  ├───────────────────────────────────────────────────────────────────────┤ │
│  │ Privilege Escalation Events                                           │ │
│  │    privilege, security, critical                                      │ │
│  │    Query: event_type = "privilege_escalation" AND severity = "Cri...  │ │
│  │    Last used: 2025-11-01 14:10                                        │ │
│  │    [Load] [Edit] [Delete]                                             │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  [Close]                                                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Export Results Modal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Export Search Results                                             [✕ Close] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Export Format:                                                             │
│  ● JSON    ○ CSV                                                            │
│                                                                             │
│  Export Scope:                                                              │
│  ○ Current page (50 events)                                                 │
│  ● All results (1,247 events)                                               │
│  ○ Custom range: [1] to [1000]                                              │
│                                                                             │
│  ⚠ Note: Exports are limited to 10,000 events maximum                      │
│                                                                             │
│  Include in Export:                                                         │
│  ☑ Query metadata (query, time range, timestamp)                           │
│  ☑ Event fields                                                             │
│  ☑ Custom fields                                                            │
│  ☐ Matched rules information                                                │
│                                                                             │
│  File Name:                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ cerberus_events_2025-11-04_114530                                     │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  Estimated file size: ~2.5 MB                                               │
│                                                                             │
│  [Export] [Cancel]                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Syntax Help Modal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Query Syntax Help                                                 [✕ Close] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [Overview] [Operators] [Examples] [Functions] [Time Ranges]               │
│                                                                             │
│  ─── Comparison Operators ─────────────────────────────────────────────    │
│                                                                             │
│  = or equals          Exact match                                           │
│  Example: event_type = "login"                                              │
│                                                                             │
│  != or not_equals     Not equal to                                          │
│  Example: severity != "Low"                                                 │
│                                                                             │
│  contains            String contains substring                              │
│  Example: message contains "failed"                                         │
│                                                                             │
│  startswith          String starts with                                     │
│  Example: user startswith "admin"                                           │
│                                                                             │
│  endswith            String ends with                                       │
│  Example: filename endswith ".exe"                                          │
│                                                                             │
│  > or gt             Greater than (numeric)                                 │
│  Example: event_id > 4624                                                   │
│                                                                             │
│  < or lt             Less than (numeric)                                    │
│  Example: port < 1024                                                       │
│                                                                             │
│  >= or gte           Greater than or equal                                  │
│  Example: severity_score >= 7                                               │
│                                                                             │
│  <= or lte           Less than or equal                                     │
│  Example: response_time <= 100                                              │
│                                                                             │
│  in                  Value in list                                          │
│  Example: status in ["active", "pending"]                                   │
│                                                                             │
│  matches or ~=       Regex match                                            │
│  Example: ip_address matches "192\.168\..*"                                 │
│                                                                             │
│  exists              Field exists                                           │
│  Example: fields.error_code exists                                          │
│                                                                             │
│  ─── Logical Operators ────────────────────────────────────────────────    │
│                                                                             │
│  AND or &&           Both conditions must be true                           │
│  OR or ||            Either condition must be true                          │
│  NOT or !            Negates condition                                      │
│                                                                             │
│  Use parentheses for grouping:                                              │
│  (A AND B) OR (C AND D)                                                     │
│                                                                             │
│  [View Full Documentation]                                                  │
│                                                                             │
│  [Close]                                                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Technical Implementation

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (React)                        │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Event Search │  │ Query Builder│  │ Saved Searches Mgmt  │  │
│  │   Page       │  │   Component  │  │     Component        │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────────────┘  │
│         │                 │                  │                  │
│         └─────────────────┴──────────────────┘                  │
│                           │                                     │
│                  ┌────────▼────────┐                            │
│                  │  API Service    │                            │
│                  │  (api.ts)       │                            │
│                  └────────┬────────┘                            │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                            │ HTTP/REST
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                      Backend (Go)                               │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  API Layer (api/handlers.go)             │  │
│  │                                                          │  │
│  │  POST /api/v1/events/search                             │  │
│  │  GET  /api/v1/events/search/saved                       │  │
│  │  POST /api/v1/events/search/saved                       │  │
│  │  PUT  /api/v1/events/search/saved/:id                   │  │
│  │  DELETE /api/v1/events/search/saved/:id                 │  │
│  │  POST /api/v1/events/export                             │  │
│  └──────────────────┬───────────────────────────────────────┘  │
│                     │                                          │
│  ┌──────────────────▼───────────────────────────────────────┐  │
│  │           Query Parser (search/parser.go)                │  │
│  │                                                          │  │
│  │  - Tokenize CQL query                                   │  │
│  │  - Parse into Abstract Syntax Tree (AST)                │  │
│  │  - Validate syntax and semantics                        │  │
│  └──────────────────┬───────────────────────────────────────┘  │
│                     │                                          │
│  ┌──────────────────▼───────────────────────────────────────┐  │
│  │      Query Executor (search/executor.go)                 │  │
│  │                                                          │  │
│  │  - Convert AST to MongoDB query                         │  │
│  │  - Apply time range filters                             │  │
│  │  - Execute query with pagination                        │  │
│  │  - Apply result transformations                         │  │
│  └──────────────────┬───────────────────────────────────────┘  │
│                     │                                          │
│  ┌──────────────────▼───────────────────────────────────────┐  │
│  │         Storage Layer (storage/eventstorage.go)          │  │
│  │                                                          │  │
│  │  - MongoDB query execution                              │  │
│  │  - Index management                                     │  │
│  │  - Result caching                                       │  │
│  └──────────────────┬───────────────────────────────────────┘  │
└────────────────────┼────────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────────┐
│                        MongoDB                                  │
│                                                                 │
│  Collections:                                                   │
│  - events           (event data)                                │
│  - saved_searches   (saved query configurations)                │
│                                                                 │
│  Indexes:                                                       │
│  - timestamp (descending)                                       │
│  - event_type                                                   │
│  - severity                                                     │
│  - source_ip                                                    │
│  - fields.user                                                  │
│  - compound: (timestamp, event_type)                            │
│  - text index: message                                          │
└─────────────────────────────────────────────────────────────────┘
```

### Backend Components

#### 1. Query Parser (`search/parser.go`)

**Purpose:** Parse CQL queries into an Abstract Syntax Tree (AST)

```go
package search

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Token types
type TokenType int

const (
	TokenField TokenType = iota
	TokenOperator
	TokenValue
	TokenLogic
	TokenLParen
	TokenRParen
	TokenComma
	TokenEOF
)

// Token represents a lexical token
type Token struct {
	Type  TokenType
	Value string
	Pos   int
}

// AST Node types
type NodeType int

const (
	NodeCondition NodeType = iota
	NodeLogical
	NodeGroup
)

// ASTNode represents a node in the abstract syntax tree
type ASTNode struct {
	Type     NodeType
	Field    string
	Operator string
	Value    interface{}
	Logic    string // AND, OR, NOT
	Left     *ASTNode
	Right    *ASTNode
	Children []*ASTNode
}

// Parser parses CQL queries
type Parser struct {
	input   string
	tokens  []Token
	current int
}

// NewParser creates a new parser
func NewParser(query string) *Parser {
	return &Parser{
		input:   query,
		current: 0,
	}
}

// Parse parses the query and returns an AST
func (p *Parser) Parse() (*ASTNode, error) {
	// Tokenize
	if err := p.tokenize(); err != nil {
		return nil, err
	}

	// Parse tokens into AST
	ast, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	return ast, nil
}

// tokenize breaks the input into tokens
func (p *Parser) tokenize() error {
	// Implementation of tokenizer
	// This would break down the query string into tokens
	// Handle operators, fields, values, parentheses, etc.

	// Example token patterns:
	patterns := map[TokenType]*regexp.Regexp{
		TokenOperator: regexp.MustCompile(`^(=|!=|>|<|>=|<=|equals|not_equals|contains|startswith|endswith|matches|in|not in|exists|not exists|gt|lt|gte|lte)`),
		TokenLogic:    regexp.MustCompile(`^(AND|OR|NOT|&&|\|\||!)`),
		TokenLParen:   regexp.MustCompile(`^\(`),
		TokenRParen:   regexp.MustCompile(`^\)`),
		// ... more patterns
	}

	// Tokenization logic here
	return nil
}

// parseExpression parses a complete expression
func (p *Parser) parseExpression() (*ASTNode, error) {
	return p.parseOrExpression()
}

// parseOrExpression handles OR logic
func (p *Parser) parseOrExpression() (*ASTNode, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	for p.matchLogic("OR", "||") {
		op := p.previous().Value
		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}

		left = &ASTNode{
			Type:  NodeLogical,
			Logic: "OR",
			Left:  left,
			Right: right,
		}
	}

	return left, nil
}

// parseAndExpression handles AND logic
func (p *Parser) parseAndExpression() (*ASTNode, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	for p.matchLogic("AND", "&&") {
		op := p.previous().Value
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}

		left = &ASTNode{
			Type:  NodeLogical,
			Logic: "AND",
			Left:  left,
			Right: right,
		}
	}

	return left, nil
}

// parsePrimary parses primary expressions (conditions or groups)
func (p *Parser) parsePrimary() (*ASTNode, error) {
	// Handle parentheses
	if p.match(TokenLParen) {
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if !p.match(TokenRParen) {
			return nil, fmt.Errorf("expected closing parenthesis")
		}
		return &ASTNode{
			Type:     NodeGroup,
			Children: []*ASTNode{expr},
		}, nil
	}

	// Handle NOT
	if p.matchLogic("NOT", "!") {
		expr, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &ASTNode{
			Type:  NodeLogical,
			Logic: "NOT",
			Left:  expr,
		}, nil
	}

	// Handle condition
	return p.parseCondition()
}

// parseCondition parses a single condition
func (p *Parser) parseCondition() (*ASTNode, error) {
	if !p.match(TokenField) {
		return nil, fmt.Errorf("expected field name at position %d", p.current)
	}
	field := p.previous().Value

	if !p.match(TokenOperator) {
		return nil, fmt.Errorf("expected operator at position %d", p.current)
	}
	operator := p.previous().Value

	if !p.match(TokenValue) {
		return nil, fmt.Errorf("expected value at position %d", p.current)
	}
	value := p.previous().Value

	// Parse value type
	parsedValue, err := p.parseValue(value)
	if err != nil {
		return nil, err
	}

	return &ASTNode{
		Type:     NodeCondition,
		Field:    field,
		Operator: operator,
		Value:    parsedValue,
	}, nil
}

// Helper methods
func (p *Parser) match(types ...TokenType) bool {
	for _, t := range types {
		if p.check(t) {
			p.advance()
			return true
		}
	}
	return false
}

func (p *Parser) matchLogic(values ...string) bool {
	if p.check(TokenLogic) {
		for _, v := range values {
			if p.peek().Value == v {
				p.advance()
				return true
			}
		}
	}
	return false
}

func (p *Parser) check(t TokenType) bool {
	if p.isAtEnd() {
		return false
	}
	return p.peek().Type == t
}

func (p *Parser) advance() Token {
	if !p.isAtEnd() {
		p.current++
	}
	return p.previous()
}

func (p *Parser) isAtEnd() bool {
	return p.current >= len(p.tokens) || p.peek().Type == TokenEOF
}

func (p *Parser) peek() Token {
	if p.current >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.current]
}

func (p *Parser) previous() Token {
	return p.tokens[p.current-1]
}

func (p *Parser) parseValue(value string) (interface{}, error) {
	// Parse string, number, array, etc.
	// Handle quoted strings, numeric values, arrays, etc.
	return value, nil
}

// Validate performs semantic validation on the AST
func (ast *ASTNode) Validate() error {
	// Check field names exist
	// Check operator compatibility with field types
	// Check value types match field types
	return nil
}
```

#### 2. Query Executor (`search/executor.go`)

**Purpose:** Convert AST to MongoDB query and execute

```go
package search

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Executor executes parsed queries against the database
type Executor struct {
	db *mongo.Database
}

// NewExecutor creates a new query executor
func NewExecutor(db *mongo.Database) *Executor {
	return &Executor{db: db}
}

// SearchRequest represents a search query request
type SearchRequest struct {
	Query     string                 `json:"query"`
	TimeRange *TimeRange             `json:"time_range,omitempty"`
	Page      int                    `json:"page"`
	Limit     int                    `json:"limit"`
	SortBy    string                 `json:"sort_by"`
	SortOrder string                 `json:"sort_order"`
	Fields    []string               `json:"fields,omitempty"`
	Params    map[string]interface{} `json:"params,omitempty"`
}

// TimeRange represents a time range filter
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// SearchResponse represents search results
type SearchResponse struct {
	Events       []bson.M  `json:"events"`
	Total        int64     `json:"total"`
	Page         int       `json:"page"`
	Limit        int       `json:"limit"`
	ExecutionTime float64  `json:"execution_time_ms"`
	Query        string    `json:"query"`
	TimeRange    *TimeRange `json:"time_range,omitempty"`
}

// Execute executes a search query
func (e *Executor) Execute(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
	startTime := time.Now()

	// Parse query
	parser := NewParser(req.Query)
	ast, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	// Validate AST
	if err := ast.Validate(); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	// Convert AST to MongoDB filter
	filter, err := e.astToMongoFilter(ast)
	if err != nil {
		return nil, fmt.Errorf("filter conversion error: %w", err)
	}

	// Apply time range filter
	if req.TimeRange != nil {
		timeFilter := bson.M{
			"timestamp": bson.M{
				"$gte": req.TimeRange.Start,
				"$lte": req.TimeRange.End,
			},
		}
		filter = bson.M{"$and": []bson.M{filter, timeFilter}}
	}

	// Count total results
	collection := e.db.Collection("events")
	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("count error: %w", err)
	}

	// Build query options
	findOptions := options.Find()
	findOptions.SetSkip(int64((req.Page - 1) * req.Limit))
	findOptions.SetLimit(int64(req.Limit))

	// Sort
	sortField := "timestamp"
	sortOrder := -1 // descending by default
	if req.SortBy != "" {
		sortField = req.SortBy
	}
	if req.SortOrder == "asc" {
		sortOrder = 1
	}
	findOptions.SetSort(bson.D{{Key: sortField, Value: sortOrder}})

	// Project specific fields if requested
	if len(req.Fields) > 0 {
		projection := bson.M{}
		for _, field := range req.Fields {
			projection[field] = 1
		}
		findOptions.SetProjection(projection)
	}

	// Execute query
	cursor, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		return nil, fmt.Errorf("query execution error: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	var events []bson.M
	if err := cursor.All(ctx, &events); err != nil {
		return nil, fmt.Errorf("result decoding error: %w", err)
	}

	executionTime := time.Since(startTime).Seconds() * 1000 // ms

	return &SearchResponse{
		Events:        events,
		Total:         total,
		Page:          req.Page,
		Limit:         req.Limit,
		ExecutionTime: executionTime,
		Query:         req.Query,
		TimeRange:     req.TimeRange,
	}, nil
}

// astToMongoFilter converts an AST to a MongoDB filter
func (e *Executor) astToMongoFilter(node *ASTNode) (bson.M, error) {
	if node == nil {
		return bson.M{}, nil
	}

	switch node.Type {
	case NodeCondition:
		return e.conditionToFilter(node)
	case NodeLogical:
		return e.logicalToFilter(node)
	case NodeGroup:
		if len(node.Children) > 0 {
			return e.astToMongoFilter(node.Children[0])
		}
		return bson.M{}, nil
	default:
		return nil, fmt.Errorf("unknown node type")
	}
}

// conditionToFilter converts a condition node to MongoDB filter
func (e *Executor) conditionToFilter(node *ASTNode) (bson.M, error) {
	field := node.Field
	operator := node.Operator
	value := node.Value

	switch operator {
	case "=", "equals":
		return bson.M{field: value}, nil
	case "!=", "not_equals":
		return bson.M{field: bson.M{"$ne": value}}, nil
	case ">", "gt":
		return bson.M{field: bson.M{"$gt": value}}, nil
	case "<", "lt":
		return bson.M{field: bson.M{"$lt": value}}, nil
	case ">=", "gte":
		return bson.M{field: bson.M{"$gte": value}}, nil
	case "<=", "lte":
		return bson.M{field: bson.M{"$lte": value}}, nil
	case "contains":
		return bson.M{field: bson.M{"$regex": value, "$options": "i"}}, nil
	case "startswith":
		return bson.M{field: bson.M{"$regex": fmt.Sprintf("^%s", value), "$options": "i"}}, nil
	case "endswith":
		return bson.M{field: bson.M{"$regex": fmt.Sprintf("%s$", value), "$options": "i"}}, nil
	case "matches", "~=":
		return bson.M{field: bson.M{"$regex": value}}, nil
	case "in":
		return bson.M{field: bson.M{"$in": value}}, nil
	case "not in":
		return bson.M{field: bson.M{"$nin": value}}, nil
	case "exists":
		return bson.M{field: bson.M{"$exists": true}}, nil
	case "not exists":
		return bson.M{field: bson.M{"$exists": false}}, nil
	default:
		return nil, fmt.Errorf("unsupported operator: %s", operator)
	}
}

// logicalToFilter converts a logical node to MongoDB filter
func (e *Executor) logicalToFilter(node *ASTNode) (bson.M, error) {
	switch node.Logic {
	case "AND":
		left, err := e.astToMongoFilter(node.Left)
		if err != nil {
			return nil, err
		}
		right, err := e.astToMongoFilter(node.Right)
		if err != nil {
			return nil, err
		}
		return bson.M{"$and": []bson.M{left, right}}, nil

	case "OR":
		left, err := e.astToMongoFilter(node.Left)
		if err != nil {
			return nil, err
		}
		right, err := e.astToMongoFilter(node.Right)
		if err != nil {
			return nil, err
		}
		return bson.M{"$or": []bson.M{left, right}}, nil

	case "NOT":
		left, err := e.astToMongoFilter(node.Left)
		if err != nil {
			return nil, err
		}
		return bson.M{"$nor": []bson.M{left}}, nil

	default:
		return nil, fmt.Errorf("unsupported logical operator: %s", node.Logic)
	}
}
```

#### 3. API Handlers (`api/search_handlers.go`)

**Purpose:** HTTP handlers for search endpoints

```go
package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/cerberus/search"
	"github.com/yourusername/cerberus/storage"
)

// SearchEventsHandler handles event search requests
func (s *Server) SearchEventsHandler(c *gin.Context) {
	var req search.SearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate request
	if req.Query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query is required"})
		return
	}

	// Set defaults
	if req.Page == 0 {
		req.Page = 1
	}
	if req.Limit == 0 {
		req.Limit = 50
	}
	if req.Limit > 500 {
		req.Limit = 500 // Max limit
	}

	// Execute search
	executor := search.NewExecutor(s.db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := executor.Execute(ctx, &req)
	if err != nil {
		s.logger.Error("Search execution failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetSavedSearchesHandler retrieves all saved searches for a user
func (s *Server) GetSavedSearchesHandler(c *gin.Context) {
	// TODO: Get user from context (JWT)
	userID := "default_user"

	searches, err := s.savedSearchStore.GetByUser(context.Background(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch saved searches"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items": searches,
		"total": len(searches),
	})
}

// CreateSavedSearchHandler creates a new saved search
func (s *Server) CreateSavedSearchHandler(c *gin.Context) {
	var savedSearch storage.SavedSearch
	if err := c.ShouldBindJSON(&savedSearch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Get user from context
	savedSearch.UserID = "default_user"
	savedSearch.CreatedAt = time.Now()
	savedSearch.UpdatedAt = time.Now()

	if err := s.savedSearchStore.Create(context.Background(), &savedSearch); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save search"})
		return
	}

	c.JSON(http.StatusCreated, savedSearch)
}

// UpdateSavedSearchHandler updates an existing saved search
func (s *Server) UpdateSavedSearchHandler(c *gin.Context) {
	id := c.Param("id")

	var savedSearch storage.SavedSearch
	if err := c.ShouldBindJSON(&savedSearch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	savedSearch.ID = id
	savedSearch.UpdatedAt = time.Now()

	if err := s.savedSearchStore.Update(context.Background(), &savedSearch); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update search"})
		return
	}

	c.JSON(http.StatusOK, savedSearch)
}

// DeleteSavedSearchHandler deletes a saved search
func (s *Server) DeleteSavedSearchHandler(c *gin.Context) {
	id := c.Param("id")

	if err := s.savedSearchStore.Delete(context.Background(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete search"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "search deleted"})
}

// ExportEventsHandler exports search results
func (s *Server) ExportEventsHandler(c *gin.Context) {
	var req struct {
		Query     string  `json:"query"`
		TimeRange *search.TimeRange `json:"time_range,omitempty"`
		Format    string  `json:"format"` // json or csv
		Limit     int     `json:"limit"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate
	if req.Format != "json" && req.Format != "csv" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "format must be json or csv"})
		return
	}

	if req.Limit == 0 {
		req.Limit = 10000 // Default export limit
	}
	if req.Limit > 10000 {
		req.Limit = 10000 // Max export limit
	}

	// Execute search
	executor := search.NewExecutor(s.db)
	searchReq := &search.SearchRequest{
		Query:     req.Query,
		TimeRange: req.TimeRange,
		Page:      1,
		Limit:     req.Limit,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := executor.Execute(ctx, searchReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
		return
	}

	// Export based on format
	filename := "cerberus_events_" + time.Now().Format("2006-01-02_150405")

	switch req.Format {
	case "json":
		c.Header("Content-Disposition", "attachment; filename="+filename+".json")
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, gin.H{
			"metadata": gin.H{
				"query":          req.Query,
				"time_range":     req.TimeRange,
				"exported_at":    time.Now(),
				"total_exported": len(result.Events),
			},
			"events": result.Events,
		})

	case "csv":
		c.Header("Content-Disposition", "attachment; filename="+filename+".csv")
		c.Header("Content-Type", "text/csv")

		writer := csv.NewWriter(c.Writer)
		defer writer.Flush()

		// Write header
		if len(result.Events) > 0 {
			// Get all unique fields
			fields := make(map[string]bool)
			for _, event := range result.Events {
				for k := range event {
					fields[k] = true
				}
			}

			// Create header row
			var header []string
			for field := range fields {
				header = append(header, field)
			}
			writer.Write(header)

			// Write data rows
			for _, event := range result.Events {
				row := make([]string, len(header))
				for i, field := range header {
					if val, ok := event[field]; ok {
						row[i] = fmt.Sprintf("%v", val)
					}
				}
				writer.Write(row)
			}
		}
	}
}

// ValidateQueryHandler validates a query without executing it
func (s *Server) ValidateQueryHandler(c *gin.Context) {
	var req struct {
		Query string `json:"query"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	parser := search.NewParser(req.Query)
	ast, err := parser.Parse()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	if err := ast.Validate(); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"message": "query is valid",
	})
}
```

---

## API Specification

### Base URL
```
/api/v1
```

### Endpoints

#### 1. Search Events

**POST** `/events/search`

Search events using CQL query language.

**Request Body:**
```json
{
  "query": "event_type = \"login\" AND severity = \"High\"",
  "time_range": {
    "start": "2025-11-01T00:00:00Z",
    "end": "2025-11-04T23:59:59Z"
  },
  "page": 1,
  "limit": 50,
  "sort_by": "timestamp",
  "sort_order": "desc",
  "fields": ["event_id", "event_type", "timestamp", "severity"]
}
```

**Response:**
```json
{
  "events": [
    {
      "event_id": "evt_123",
      "event_type": "login",
      "timestamp": "2025-11-04T11:45:32Z",
      "severity": "High",
      "source_ip": "192.168.1.50",
      "fields": {
        "user": "admin",
        "status": "failure"
      },
      "message": "Failed login attempt"
    }
  ],
  "total": 1247,
  "page": 1,
  "limit": 50,
  "execution_time_ms": 342.5,
  "query": "event_type = \"login\" AND severity = \"High\"",
  "time_range": {
    "start": "2025-11-01T00:00:00Z",
    "end": "2025-11-04T23:59:59Z"
  }
}
```

**Status Codes:**
- `200 OK` - Success
- `400 Bad Request` - Invalid query syntax
- `500 Internal Server Error` - Server error

---

#### 2. Validate Query

**POST** `/events/search/validate`

Validate a CQL query without executing it.

**Request Body:**
```json
{
  "query": "event_type = \"login\" AND severity = \"High\""
}
```

**Response (Valid):**
```json
{
  "valid": true,
  "message": "query is valid"
}
```

**Response (Invalid):**
```json
{
  "valid": false,
  "error": "syntax error at position 15: expected operator"
}
```

---

#### 3. Get Saved Searches

**GET** `/events/search/saved`

Retrieve all saved searches for the current user.

**Query Parameters:**
- `tags` (optional) - Filter by tags (comma-separated)
- `sort` (optional) - Sort by: `name`, `created_at`, `last_used` (default: `last_used`)

**Response:**
```json
{
  "items": [
    {
      "id": "search_123",
      "user_id": "user_456",
      "name": "High Severity Login Failures",
      "description": "Track all high severity failed login attempts",
      "query": "event_type = \"login\" AND severity = \"High\"",
      "time_range": {
        "start": "2025-11-01T00:00:00Z",
        "end": "2025-11-04T23:59:59Z"
      },
      "tags": ["authentication", "security"],
      "is_default": false,
      "is_shared": false,
      "created_at": "2025-10-15T10:30:00Z",
      "updated_at": "2025-11-03T14:20:00Z",
      "last_used": "2025-11-04T09:15:00Z"
    }
  ],
  "total": 15
}
```

---

#### 4. Create Saved Search

**POST** `/events/search/saved`

Create a new saved search.

**Request Body:**
```json
{
  "name": "High Severity Login Failures",
  "description": "Track all high severity failed login attempts",
  "query": "event_type = \"login\" AND severity = \"High\"",
  "time_range": {
    "start": "2025-11-01T00:00:00Z",
    "end": "2025-11-04T23:59:59Z"
  },
  "tags": ["authentication", "security"],
  "is_default": false,
  "is_shared": false
}
```

**Response:**
```json
{
  "id": "search_123",
  "user_id": "user_456",
  "name": "High Severity Login Failures",
  "description": "Track all high severity failed login attempts",
  "query": "event_type = \"login\" AND severity = \"High\"",
  "time_range": {
    "start": "2025-11-01T00:00:00Z",
    "end": "2025-11-04T23:59:59Z"
  },
  "tags": ["authentication", "security"],
  "is_default": false,
  "is_shared": false,
  "created_at": "2025-11-04T11:50:00Z",
  "updated_at": "2025-11-04T11:50:00Z",
  "last_used": null
}
```

**Status Codes:**
- `201 Created` - Success
- `400 Bad Request` - Invalid request
- `409 Conflict` - Search with same name already exists

---

#### 5. Update Saved Search

**PUT** `/events/search/saved/:id`

Update an existing saved search.

**Request Body:**
```json
{
  "name": "Updated Name",
  "description": "Updated description",
  "query": "event_type = \"login\" AND severity = \"Critical\"",
  "tags": ["authentication", "security", "monitoring"]
}
```

**Response:**
```json
{
  "id": "search_123",
  "user_id": "user_456",
  "name": "Updated Name",
  "description": "Updated description",
  "query": "event_type = \"login\" AND severity = \"Critical\"",
  "tags": ["authentication", "security", "monitoring"],
  "updated_at": "2025-11-04T12:00:00Z"
}
```

---

#### 6. Delete Saved Search

**DELETE** `/events/search/saved/:id`

Delete a saved search.

**Response:**
```json
{
  "message": "search deleted"
}
```

**Status Codes:**
- `200 OK` - Success
- `404 Not Found` - Search not found
- `403 Forbidden` - Not authorized to delete

---

#### 7. Export Events

**POST** `/events/export`

Export search results to JSON or CSV.

**Request Body:**
```json
{
  "query": "event_type = \"login\" AND severity = \"High\"",
  "time_range": {
    "start": "2025-11-01T00:00:00Z",
    "end": "2025-11-04T23:59:59Z"
  },
  "format": "json",
  "limit": 1000
}
```

**Response (JSON format):**
```json
{
  "metadata": {
    "query": "event_type = \"login\" AND severity = \"High\"",
    "time_range": {
      "start": "2025-11-01T00:00:00Z",
      "end": "2025-11-04T23:59:59Z"
    },
    "exported_at": "2025-11-04T12:05:00Z",
    "total_exported": 1000
  },
  "events": [...]
}
```

**Response Headers (CSV format):**
```
Content-Type: text/csv
Content-Disposition: attachment; filename=cerberus_events_2025-11-04_120500.csv
```

**Status Codes:**
- `200 OK` - Success
- `400 Bad Request` - Invalid request
- `413 Payload Too Large` - Export size exceeds limit

---

## Database Schema

### Events Collection

```javascript
{
  "_id": ObjectId("..."),
  "event_id": "evt_789012345",
  "event_type": "login",
  "timestamp": ISODate("2025-11-04T11:45:15.234Z"),
  "severity": "High",
  "source_ip": "10.0.0.15",
  "source_format": "syslog",
  "fields": {
    "user": "root",
    "auth_method": "password",
    "status": "failure",
    "attempt_count": 5,
    "source_port": 52341
  },
  "message": "Failed login attempt for user 'root' from 10.0.0.15",
  "matched_rules": ["rule_123", "rule_456"],
  "created_at": ISODate("2025-11-04T11:45:15.234Z")
}
```

**Indexes:**
```javascript
// Timestamp index (descending for recent events)
db.events.createIndex({ "timestamp": -1 })

// Event type index
db.events.createIndex({ "event_type": 1 })

// Severity index
db.events.createIndex({ "severity": 1 })

// Source IP index
db.events.createIndex({ "source_ip": 1 })

// Compound index for common queries
db.events.createIndex({ "timestamp": -1, "event_type": 1 })
db.events.createIndex({ "timestamp": -1, "severity": 1 })

// Text index for message field
db.events.createIndex({ "message": "text" })

// Nested field indexes
db.events.createIndex({ "fields.user": 1 })
db.events.createIndex({ "fields.status": 1 })

// TTL index (optional - auto-delete old events)
db.events.createIndex({ "created_at": 1 }, { expireAfterSeconds: 7776000 }) // 90 days
```

---

### Saved Searches Collection

```javascript
{
  "_id": ObjectId("..."),
  "id": "search_123",
  "user_id": "user_456",
  "name": "High Severity Login Failures",
  "description": "Track all high severity failed login attempts for security monitoring",
  "query": "event_type = \"login\" AND severity = \"High\"",
  "time_range": {
    "start": ISODate("2025-11-01T00:00:00Z"),
    "end": ISODate("2025-11-04T23:59:59Z")
  },
  "tags": ["authentication", "security", "monitoring"],
  "is_default": false,
  "is_shared": false,
  "shared_with": [],
  "created_at": ISODate("2025-10-15T10:30:00Z"),
  "updated_at": ISODate("2025-11-03T14:20:00Z"),
  "last_used": ISODate("2025-11-04T09:15:00Z"),
  "use_count": 127
}
```

**Indexes:**
```javascript
// User ID index
db.saved_searches.createIndex({ "user_id": 1 })

// Name uniqueness per user
db.saved_searches.createIndex({ "user_id": 1, "name": 1 }, { unique: true })

// Last used index for sorting
db.saved_searches.createIndex({ "user_id": 1, "last_used": -1 })

// Tags index for filtering
db.saved_searches.createIndex({ "tags": 1 })
```

---

## Frontend Components

### 1. Event Search Page (`EventSearch/index.tsx`)

```typescript
import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Box,
  Typography,
  TextField,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  CircularProgress,
  Alert,
  TablePagination,
  IconButton,
  Collapse,
  RadioGroup,
  FormControlLabel,
  Radio,
} from '@mui/material';
import {
  Search as SearchIcon,
  Save as SaveIcon,
  FolderOpen as FolderOpenIcon,
  Download as DownloadIcon,
  Help as HelpIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import { apiService } from '../../services/api';
import { Event } from '../../types';
import EventDetailsModal from '../../components/modals/EventDetailsModal';
import SaveSearchModal from '../../components/modals/SaveSearchModal';
import LoadSearchModal from '../../components/modals/LoadSearchModal';
import ExportModal from '../../components/modals/ExportModal';
import SyntaxHelpModal from '../../components/modals/SyntaxHelpModal';
import QueryBuilder from '../../components/search/QueryBuilder';

function EventSearch() {
  const [query, setQuery] = useState('');
  const [timeRange, setTimeRange] = useState('last_24h');
  const [customTimeRange, setCustomTimeRange] = useState({ start: '', end: '' });
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [eventDetailsOpen, setEventDetailsOpen] = useState(false);
  const [saveSearchOpen, setSaveSearchOpen] = useState(false);
  const [loadSearchOpen, setLoadSearchOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [syntaxHelpOpen, setSyntaxHelpOpen] = useState(false);
  const [queryMode, setQueryMode] = useState<'manual' | 'builder'>('manual');

  // Search query
  const { data: searchResults, isLoading, error, refetch } = useQuery({
    queryKey: ['eventSearch', query, timeRange, customTimeRange, page, rowsPerPage],
    queryFn: () => apiService.searchEvents({
      query,
      time_range: getTimeRange(),
      page: page + 1,
      limit: rowsPerPage,
    }),
    enabled: false, // Don't auto-run, only on explicit search
  });

  const getTimeRange = () => {
    if (timeRange === 'custom') {
      return {
        start: new Date(customTimeRange.start).toISOString(),
        end: new Date(customTimeRange.end).toISOString(),
      };
    }

    const now = new Date();
    const start = new Date();

    switch (timeRange) {
      case 'last_15m':
        start.setMinutes(now.getMinutes() - 15);
        break;
      case 'last_1h':
        start.setHours(now.getHours() - 1);
        break;
      case 'last_24h':
        start.setHours(now.getHours() - 24);
        break;
      case 'last_7d':
        start.setDate(now.getDate() - 7);
        break;
      case 'last_30d':
        start.setDate(now.getDate() - 30);
        break;
      default:
        start.setHours(now.getHours() - 24);
    }

    return {
      start: start.toISOString(),
      end: now.toISOString(),
    };
  };

  const handleSearch = () => {
    setPage(0); // Reset to first page
    refetch();
  };

  const handleRowExpand = (eventId: string) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(eventId)) {
      newExpanded.delete(eventId);
    } else {
      newExpanded.add(eventId);
    }
    setExpandedRows(newExpanded);
  };

  const handleViewDetails = (event: Event) => {
    setSelectedEvent(event);
    setEventDetailsOpen(true);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'error';
      case 'High':
        return 'error';
      case 'Medium':
        return 'warning';
      case 'Low':
        return 'info';
      default:
        return 'default';
    }
  };

  if (error) {
    return <Alert severity="error">Failed to search events</Alert>;
  }

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        Event Search
      </Typography>

      {/* Query Input */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
          <Button
            variant={queryMode === 'manual' ? 'contained' : 'outlined'}
            onClick={() => setQueryMode('manual')}
            size="small"
          >
            Manual Mode
          </Button>
          <Button
            variant={queryMode === 'builder' ? 'contained' : 'outlined'}
            onClick={() => setQueryMode('builder')}
            size="small"
          >
            Builder Mode
          </Button>
          <Box sx={{ flex: 1 }} />
          <Button
            variant="text"
            startIcon={<HelpIcon />}
            onClick={() => setSyntaxHelpOpen(true)}
            size="small"
          >
            Syntax Help
          </Button>
          <Button
            variant="text"
            onClick={() => setQuery('')}
            size="small"
          >
            Clear
          </Button>
        </Box>

        {queryMode === 'manual' ? (
          <TextField
            fullWidth
            multiline
            rows={3}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='event_type = "login" AND severity = "High"'
            variant="outlined"
          />
        ) : (
          <QueryBuilder
            value={query}
            onChange={setQuery}
          />
        )}
      </Paper>

      {/* Time Range Selector */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Typography variant="subtitle2" gutterBottom>
          Time Range:
        </Typography>
        <RadioGroup
          row
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
        >
          <FormControlLabel value="last_15m" control={<Radio />} label="Last 15 min" />
          <FormControlLabel value="last_1h" control={<Radio />} label="Last 1 hour" />
          <FormControlLabel value="last_24h" control={<Radio />} label="Last 24 hours" />
          <FormControlLabel value="last_7d" control={<Radio />} label="Last 7 days" />
          <FormControlLabel value="last_30d" control={<Radio />} label="Last 30 days" />
          <FormControlLabel value="custom" control={<Radio />} label="Custom Range" />
        </RadioGroup>

        {timeRange === 'custom' && (
          <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
            <TextField
              type="datetime-local"
              label="Start Date"
              value={customTimeRange.start}
              onChange={(e) => setCustomTimeRange({ ...customTimeRange, start: e.target.value })}
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              type="datetime-local"
              label="End Date"
              value={customTimeRange.end}
              onChange={(e) => setCustomTimeRange({ ...customTimeRange, end: e.target.value })}
              InputLabelProps={{ shrink: true }}
            />
          </Box>
        )}
      </Paper>

      {/* Action Buttons */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <Button
          variant="contained"
          startIcon={<SearchIcon />}
          onClick={handleSearch}
          disabled={!query}
        >
          Search
        </Button>
        <Button
          variant="outlined"
          startIcon={<SaveIcon />}
          onClick={() => setSaveSearchOpen(true)}
          disabled={!query}
        >
          Save Search
        </Button>
        <Button
          variant="outlined"
          startIcon={<FolderOpenIcon />}
          onClick={() => setLoadSearchOpen(true)}
        >
          Load Search
        </Button>
        <Button
          variant="outlined"
          startIcon={<DownloadIcon />}
          onClick={() => setExportOpen(true)}
          disabled={!searchResults?.events?.length}
        >
          Export
        </Button>
      </Box>

      {/* Results Summary */}
      {searchResults && (
        <Box sx={{ mb: 2 }}>
          <Typography variant="body2" color="textSecondary">
            Search Results: {searchResults.total.toLocaleString()} events found in {searchResults.execution_time_ms.toFixed(1)}ms
          </Typography>
        </Box>
      )}

      {/* Results Table */}
      {isLoading ? (
        <Box display="flex" justifyContent="center" p={4}>
          <CircularProgress />
        </Box>
      ) : searchResults?.events?.length ? (
        <>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell width={50}></TableCell>
                  <TableCell>Timestamp</TableCell>
                  <TableCell>Event Type</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Source IP</TableCell>
                  <TableCell>Message</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {searchResults.events.map((event: Event) => (
                  <>
                    <TableRow key={event.event_id} hover>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleRowExpand(event.event_id)}
                        >
                          {expandedRows.has(event.event_id) ? (
                            <ExpandLessIcon />
                          ) : (
                            <ExpandMoreIcon />
                          )}
                        </IconButton>
                      </TableCell>
                      <TableCell>
                        {new Date(event.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell>{event.event_type}</TableCell>
                      <TableCell>
                        <Chip
                          label={event.severity}
                          color={getSeverityColor(event.severity) as any}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>{event.source_ip}</TableCell>
                      <TableCell>{event.message}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell colSpan={6} sx={{ py: 0 }}>
                        <Collapse
                          in={expandedRows.has(event.event_id)}
                          timeout="auto"
                          unmountOnExit
                        >
                          <Box sx={{ p: 2, bgcolor: 'grey.900' }}>
                            <Typography variant="subtitle2" gutterBottom>
                              Event Details
                            </Typography>
                            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                              <Typography variant="body2">
                                <strong>Event ID:</strong> {event.event_id}
                              </Typography>
                              <Typography variant="body2">
                                <strong>Source Format:</strong> {event.source_format}
                              </Typography>
                              {event.fields && Object.keys(event.fields).length > 0 && (
                                <Box>
                                  <Typography variant="body2" gutterBottom>
                                    <strong>Fields:</strong>
                                  </Typography>
                                  <Box sx={{ pl: 2 }}>
                                    {Object.entries(event.fields).map(([key, value]) => (
                                      <Typography key={key} variant="body2">
                                        {key}: {JSON.stringify(value)}
                                      </Typography>
                                    ))}
                                  </Box>
                                </Box>
                              )}
                              <Box sx={{ mt: 2 }}>
                                <Button
                                  size="small"
                                  variant="outlined"
                                  onClick={() => handleViewDetails(event)}
                                >
                                  View Full Details
                                </Button>
                              </Box>
                            </Box>
                          </Box>
                        </Collapse>
                      </TableCell>
                    </TableRow>
                  </>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <TablePagination
            component="div"
            count={searchResults.total}
            page={page}
            onPageChange={(_, newPage) => setPage(newPage)}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={(event) => {
              setRowsPerPage(parseInt(event.target.value, 10));
              setPage(0);
            }}
            rowsPerPageOptions={[10, 25, 50, 100, 250, 500]}
          />
        </>
      ) : searchResults ? (
        <Alert severity="info">No events found matching your query</Alert>
      ) : null}

      {/* Modals */}
      <EventDetailsModal
        open={eventDetailsOpen}
        onClose={() => setEventDetailsOpen(false)}
        event={selectedEvent}
      />
      <SaveSearchModal
        open={saveSearchOpen}
        onClose={() => setSaveSearchOpen(false)}
        query={query}
        timeRange={getTimeRange()}
      />
      <LoadSearchModal
        open={loadSearchOpen}
        onClose={() => setLoadSearchOpen(false)}
        onLoad={(savedSearch) => {
          setQuery(savedSearch.query);
          if (savedSearch.time_range) {
            setCustomTimeRange({
              start: new Date(savedSearch.time_range.start).toISOString().slice(0, 16),
              end: new Date(savedSearch.time_range.end).toISOString().slice(0, 16),
            });
            setTimeRange('custom');
          }
          setLoadSearchOpen(false);
        }}
      />
      <ExportModal
        open={exportOpen}
        onClose={() => setExportOpen(false)}
        query={query}
        timeRange={getTimeRange()}
        totalEvents={searchResults?.total || 0}
      />
      <SyntaxHelpModal
        open={syntaxHelpOpen}
        onClose={() => setSyntaxHelpOpen(false)}
      />
    </Box>
  );
}

export default EventSearch;
```

### 2. Query Builder Component (`QueryBuilder.tsx`)

```typescript
import { useState } from 'react';
import {
  Box,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  IconButton,
  Paper,
  Typography,
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';

interface Condition {
  id: string;
  field: string;
  operator: string;
  value: string;
  logic: 'AND' | 'OR';
}

interface QueryBuilderProps {
  value: string;
  onChange: (query: string) => void;
}

const OPERATORS = [
  { value: 'equals', label: 'Equals' },
  { value: 'not_equals', label: 'Not Equals' },
  { value: 'contains', label: 'Contains' },
  { value: 'startswith', label: 'Starts With' },
  { value: 'endswith', label: 'Ends With' },
  { value: 'gt', label: 'Greater Than' },
  { value: 'lt', label: 'Less Than' },
  { value: 'gte', label: 'Greater Than or Equal' },
  { value: 'lte', label: 'Less Than or Equal' },
  { value: 'in', label: 'In' },
  { value: 'matches', label: 'Matches (Regex)' },
  { value: 'exists', label: 'Exists' },
];

const COMMON_FIELDS = [
  'event_type',
  'event_id',
  'timestamp',
  'severity',
  'source_ip',
  'source_format',
  'fields.user',
  'fields.status',
  'fields.action',
  'fields.filename',
  'fields.destination_ip',
  'fields.port',
  'message',
];

function QueryBuilder({ value, onChange }: QueryBuilderProps) {
  const [conditions, setConditions] = useState<Condition[]>([
    {
      id: '1',
      field: 'event_type',
      operator: 'equals',
      value: '',
      logic: 'AND',
    },
  ]);

  const addCondition = () => {
    const newCondition: Condition = {
      id: Date.now().toString(),
      field: 'event_type',
      operator: 'equals',
      value: '',
      logic: 'AND',
    };
    setConditions([...conditions, newCondition]);
  };

  const removeCondition = (id: string) => {
    setConditions(conditions.filter((c) => c.id !== id));
  };

  const updateCondition = (id: string, updates: Partial<Condition>) => {
    setConditions(
      conditions.map((c) => (c.id === id ? { ...c, ...updates } : c))
    );
  };

  const generateQuery = () => {
    if (conditions.length === 0) return '';

    let query = '';
    conditions.forEach((condition, index) => {
      if (index > 0) {
        query += ` ${condition.logic} `;
      }

      const valueQuoted =
        condition.operator === 'in'
          ? `[${condition.value}]`
          : `"${condition.value}"`;

      query += `${condition.field} ${condition.operator} ${valueQuoted}`;
    });

    onChange(query);
    return query;
  };

  return (
    <Box>
      {conditions.map((condition, index) => (
        <Paper key={condition.id} sx={{ p: 2, mb: 2 }}>
          {index > 0 && (
            <FormControl sx={{ mb: 2, minWidth: 120 }}>
              <InputLabel>Logic</InputLabel>
              <Select
                value={condition.logic}
                onChange={(e) =>
                  updateCondition(condition.id, {
                    logic: e.target.value as 'AND' | 'OR',
                  })
                }
                label="Logic"
                size="small"
              >
                <MenuItem value="AND">AND</MenuItem>
                <MenuItem value="OR">OR</MenuItem>
              </Select>
            </FormControl>
          )}

          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            <FormControl sx={{ flex: 1 }}>
              <InputLabel>Field</InputLabel>
              <Select
                value={condition.field}
                onChange={(e) =>
                  updateCondition(condition.id, { field: e.target.value })
                }
                label="Field"
                size="small"
              >
                {COMMON_FIELDS.map((field) => (
                  <MenuItem key={field} value={field}>
                    {field}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl sx={{ flex: 1 }}>
              <InputLabel>Operator</InputLabel>
              <Select
                value={condition.operator}
                onChange={(e) =>
                  updateCondition(condition.id, { operator: e.target.value })
                }
                label="Operator"
                size="small"
              >
                {OPERATORS.map((op) => (
                  <MenuItem key={op.value} value={op.value}>
                    {op.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <TextField
              sx={{ flex: 1 }}
              label="Value"
              value={condition.value}
              onChange={(e) =>
                updateCondition(condition.id, { value: e.target.value })
              }
              size="small"
            />

            <IconButton
              color="error"
              onClick={() => removeCondition(condition.id)}
              disabled={conditions.length === 1}
            >
              <DeleteIcon />
            </IconButton>
          </Box>
        </Paper>
      ))}

      <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
        <Button startIcon={<AddIcon />} onClick={addCondition} variant="outlined">
          Add Condition
        </Button>
        <Button onClick={generateQuery} variant="contained">
          Generate Query
        </Button>
      </Box>

      {value && (
        <Paper sx={{ p: 2, bgcolor: 'grey.900' }}>
          <Typography variant="subtitle2" gutterBottom>
            Generated Query:
          </Typography>
          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
            {value}
          </Typography>
        </Paper>
      )}
    </Box>
  );
}

export default QueryBuilder;
```

---

## Implementation Phases

### Phase 1: Core Query Engine (Week 1-2)

**Objectives:**
- Implement CQL parser and tokenizer
- Implement AST builder and validator
- Implement query executor with MongoDB integration
- Basic API endpoints for searching

**Deliverables:**
- `search/parser.go` - Complete CQL parser
- `search/executor.go` - Query execution engine
- `api/search_handlers.go` - API endpoints
- Unit tests for parser and executor
- Basic integration tests

**Acceptance Criteria:**
- Parser correctly tokenizes and parses valid CQL queries
- Parser detects and reports syntax errors with position
- Executor converts AST to correct MongoDB queries
- Basic searches return expected results
- Performance: Searches complete in < 2 seconds for 100k events

---

### Phase 2: Frontend Search Interface (Week 3)

**Objectives:**
- Implement Event Search page
- Implement query input with syntax highlighting
- Implement time range selector
- Implement results display with pagination
- Implement expandable row details

**Deliverables:**
- `frontend/src/pages/EventSearch/index.tsx`
- `frontend/src/services/api.ts` (search methods)
- Basic UI components for search interface
- Responsive design for mobile

**Acceptance Criteria:**
- Users can enter and execute CQL queries
- Results display correctly with pagination
- Time range filtering works
- Expandable rows show event details
- UI is responsive on mobile devices

---

### Phase 3: Query Builder & Advanced Features (Week 4)

**Objectives:**
- Implement visual query builder
- Implement saved searches functionality
- Implement query validation endpoint
- Implement syntax help modal

**Deliverables:**
- `frontend/src/components/search/QueryBuilder.tsx`
- Saved search API endpoints and UI
- Syntax help modal with examples
- Query validation with real-time feedback

**Acceptance Criteria:**
- Query builder generates valid CQL
- Users can save and load searches
- Syntax help provides clear examples
- Query validation provides helpful error messages

---

### Phase 4: Export & Performance Optimization (Week 5)

**Objectives:**
- Implement export functionality (JSON/CSV)
- Optimize database queries and indexes
- Implement query result caching
- Performance testing and tuning

**Deliverables:**
- Export API endpoint and UI
- Database index optimization
- Caching layer for frequent queries
- Performance test suite
- Documentation

**Acceptance Criteria:**
- Export works for both JSON and CSV formats
- Queries execute in < 2 seconds for datasets up to 10M events
- Cache reduces load on database
- Export handles up to 10,000 events
- Performance meets requirements

---

### Phase 5: Polish & Documentation (Week 6)

**Objectives:**
- Event details modal with related events
- UI polish and UX improvements
- Comprehensive documentation
- End-to-end testing

**Deliverables:**
- Event details modal component
- User documentation with examples
- API documentation
- E2E test suite with Playwright
- Developer documentation

**Acceptance Criteria:**
- Event details modal shows all information
- Related events links work correctly
- Documentation is clear and comprehensive
- E2E tests cover all major workflows
- All acceptance criteria met

---

## Success Metrics

### Performance Metrics
- Query execution time < 2 seconds for 95% of queries
- Support for 10M+ events without degradation
- Export completion time < 30 seconds for 10,000 events
- UI response time < 100ms for user interactions

### Usability Metrics
- Time to first successful search < 2 minutes for new users
- Query syntax error rate < 10%
- Saved search usage > 60% of power users
- Query builder adoption > 40% of users

### Technical Metrics
- API uptime > 99.9%
- Test coverage > 80%
- Zero critical security vulnerabilities
- All acceptance criteria passing

---

## Risk Mitigation

### Technical Risks

**Risk:** Query performance degrades with large datasets
**Mitigation:**
- Implement comprehensive indexing strategy
- Use query result caching
- Implement query timeout and pagination limits
- Monitor query performance in production

**Risk:** Complex queries cause parsing errors
**Mitigation:**
- Extensive parser testing with edge cases
- Clear error messages with position information
- Fallback to visual query builder for complex queries
- User education through examples and documentation

**Risk:** MongoDB query injection vulnerabilities
**Mitigation:**
- Parameterized queries only
- Input validation and sanitization
- AST-based query building (not string concatenation)
- Security audit of query executor

### User Experience Risks

**Risk:** Query language too complex for average users
**Mitigation:**
- Provide visual query builder alternative
- Comprehensive syntax help and examples
- Auto-complete for fields and operators
- Common query templates

**Risk:** Search results overwhelming or confusing
**Mitigation:**
- Clear result presentation with highlighting
- Expandable details to reduce clutter
- Sorting and filtering options
- Export for offline analysis

---

## Future Enhancements

### Phase 7+ (Future)
- Aggregation functions (count, sum, avg, etc.)
- Field aliasing and renaming in results
- Scheduled searches with email alerts
- Search result visualization (charts, graphs)
- Advanced regex support with testing UI
- Query optimization suggestions
- Search query sharing and collaboration
- Integration with detection rules (search → rule)
- Machine learning-based query suggestions
- Natural language query interface

---

## Appendix

### Example Queries Library

```
# Authentication Failures
event_type = "authentication_failure" AND @timestamp last 24h

# High Severity Security Events
(severity = "High" OR severity = "Critical") AND
event_type contains "security"

# Brute Force Detection
event_type = "login" AND
fields.status = "failure" AND
@timestamp last 1h

# Network Anomalies
event_type = "network_connection" AND
fields.bytes_sent > 1000000 AND
fields.destination_port not in [80, 443]

# Privilege Escalation
event_type = "privilege_escalation" AND
fields.user != "system" AND
severity = "Critical"

# File Modifications
event_type = "file_modify" AND
fields.filename matches ".*\.(config|cfg|conf)$" AND
@timestamp last 7d

# Admin Command Execution
event_type = "admin_command" AND
fields.user startswith "admin" AND
NOT fields.command contains "show"

# Suspicious Login Locations
event_type = "login" AND
fields.source_ip not in ["192.168.1.0/24", "10.0.0.0/8"]

# Failed Database Access
event_type contains "database" AND
fields.status = "error" AND
fields.error_code exists
```

### Field Reference

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `event_id` | string | Unique event identifier | `"evt_123456"` |
| `event_type` | string | Type of event | `"login"`, `"file_access"` |
| `timestamp` | datetime | Event timestamp | `"2025-11-04T11:45:32Z"` |
| `severity` | string | Event severity | `"Low"`, `"Medium"`, `"High"`, `"Critical"` |
| `source_ip` | string | Source IP address | `"192.168.1.50"` |
| `source_format` | string | Log format | `"syslog"`, `"json"` |
| `message` | string | Event message | `"Failed login attempt"` |
| `fields.*` | any | Custom event fields | `fields.user`, `fields.action` |
| `matched_rules` | array | IDs of matched rules | `["rule_123"]` |

---

## Document Information

**Version:** 1.0
**Last Updated:** 2025-11-04
**Author:** Cerberus SIEM Development Team
**Status:** Planning - Ready for Implementation

---
