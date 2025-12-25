# Task ID: 158

**Title:** Implement WebSocket Events for Feed Sync Progress

**Status:** done

**Dependencies:** 154 ✓, 156 ✓

**Priority:** medium

**Description:** Add real-time WebSocket notifications for feed sync start, progress, and completion

**Details:**

Backend implementation in api/api.go:

1. Add WebSocket message types:
   - feed:sync:started - Sync began
   - feed:sync:progress - Progress update (rules processed)
   - feed:sync:completed - Sync finished with stats
   - feed:sync:failed - Sync failed with error

2. Modify sigma/feeds/manager.go SyncFeed():
   - Add callback parameter for progress notifications
   - Emit feed:sync:started when sync begins
   - Emit feed:sync:progress every N rules (e.g., every 100)
   - Emit feed:sync:completed/failed on finish

3. Update API handler POST /api/v1/feeds/{id}/sync:
   - Broadcast WebSocket events during sync
   - Return sync result JSON as before

Frontend implementation:

1. Extend frontend/src/services/websocket.ts:
   - Add onFeedSyncStarted callback
   - Add onFeedSyncProgress callback
   - Add onFeedSyncCompleted callback
   - Add onFeedSyncFailed callback

2. Update SigmaFeedsSettings component:
   - Subscribe to feed sync events
   - Show progress bar during sync
   - Update feed status badge in real-time
   - Display toast notification on completion
   - Auto-refresh feed list after sync completes

3. Update FeedDetailModal:
   - Show live progress during sync
   - Update statistics in real-time

Message format:
{
  "type": "feed:sync:progress",
  "data": {
    "feed_id": "feed-123",
    "feed_name": "SigmaHQ",
    "processed_rules": 1500,
    "total_rules": 3000,
    "progress_percentage": 50
  },
  "timestamp": "2025-01-15T10:30:00Z"
}

**Test Strategy:**

Backend tests: Mock WebSocket broadcast, verify events emitted during sync lifecycle. Frontend tests: Mock WebSocket messages, verify UI updates on progress events, test error handling. Integration tests: Trigger sync, verify real-time UI updates.

## Subtasks

### 158.1. Add WebSocket message types and broadcast infrastructure for feed sync events

**Status:** done  
**Dependencies:** None  

Extend the WebSocket infrastructure in api/api.go to support feed synchronization events including started, progress, completed, and failed message types with proper data structures.

**Details:**

In api/api.go, add new WebSocket message type constants: 'feed:sync:started', 'feed:sync:progress', 'feed:sync:completed', 'feed:sync:failed'. Define corresponding data structures for each message type with fields for feed_id, feed_name, processed_rules, total_rules, progress_percentage, error messages, and timestamps. Implement or extend the broadcast helper function to send these messages to all connected WebSocket clients. Ensure thread-safety for concurrent broadcasts during sync operations. The message format should follow the existing WebSocket message structure with type, data, and timestamp fields.

### 158.2. Modify SyncFeed() to accept progress callback and emit WebSocket events

**Status:** done  
**Dependencies:** 158.1  

Update sigma/feeds/manager.go SyncFeed() method to support progress notifications through callback functions and emit WebSocket events at key synchronization milestones.

**Details:**

Modify the SyncFeed() function signature to accept an optional progress callback parameter (func(processed, total int)). Emit 'feed:sync:started' event at the beginning of sync operation with feed metadata. During rule processing loop, call the progress callback and emit 'feed:sync:progress' events every 100 rules processed (configurable threshold). On successful completion, emit 'feed:sync:completed' with final statistics (total rules, new rules, updated rules, duration). On error, emit 'feed:sync:failed' with error details. Ensure backward compatibility if callback is nil. Maintain existing sync logic without breaking changes to rule processing, validation, or storage operations.

### 158.3. Extend WebSocket service with feed sync event handlers and subscriptions

**Status:** done  
**Dependencies:** 158.1  

Enhance frontend/src/services/websocket.ts to handle feed synchronization events with typed callbacks and subscription management for real-time updates.

**Details:**

Add new callback types to the WebSocket service interface: onFeedSyncStarted, onFeedSyncProgress, onFeedSyncCompleted, onFeedSyncFailed. Define TypeScript interfaces for each event payload matching the backend message structure (FeedSyncStartedEvent, FeedSyncProgressEvent, etc.). Implement event router to dispatch incoming 'feed:sync:*' messages to appropriate callbacks. Add subscription methods: subscribeFeedSync(feedId, callbacks) and unsubscribeFeedSync(feedId) to manage per-feed listeners. Ensure proper cleanup of subscriptions to prevent memory leaks. Handle reconnection scenarios where sync may be in progress. Maintain type safety throughout with proper TypeScript generics.

### 158.4. Update SigmaFeedsSettings and FeedDetailModal with real-time sync UI

**Status:** done  
**Dependencies:** 158.3  

Implement real-time UI updates in feed management components to display live synchronization progress, status changes, and completion notifications.

**Details:**

In SigmaFeedsSettings component: Add useEffect hook to subscribe to feed sync events on mount and unsubscribe on unmount. Implement state management for tracking active syncs (Map<feedId, syncProgress>). Display progress bar component when sync is active, showing percentage and processed/total counts. Update feed status badges in real-time as events arrive. Show toast notification on sync completion with success/failure message and statistics. Auto-refresh the feed list after sync completes to show updated rule counts. In FeedDetailModal: Subscribe to sync events for the displayed feed. Show inline progress indicator with live rule counts during sync. Update the statistics section (total rules, last sync time) in real-time as sync progresses. Disable sync button while sync is active. Handle error states with user-friendly error messages.
