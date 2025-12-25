# Task ID: 155

**Title:** Add Feed TypeScript Types and API Service Methods

**Status:** done

**Dependencies:** 154 ✓

**Priority:** high

**Description:** Define TypeScript interfaces for feeds and implement frontend API service methods

**Details:**

Extend frontend/src/types/index.ts with feed-related types:

export interface Feed {
  id: string;
  name: string;
  description?: string;
  type: 'git' | 'filesystem';
  status: 'active' | 'disabled' | 'error' | 'syncing';
  enabled: boolean;
  priority: number;
  url?: string;
  branch?: string;
  path?: string;
  auth_config?: Record<string, unknown>;
  include_paths?: string[];
  exclude_paths?: string[];
  include_tags?: string[];
  exclude_tags?: string[];
  min_severity?: string;
  auto_enable_rules: boolean;
  update_strategy: 'manual' | 'startup' | 'scheduled';
  update_schedule?: string;
  last_sync?: string;
  next_sync?: string;
  stats: FeedStats;
  tags?: string[];
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  created_by?: string;
}

export interface FeedStats {
  total_rules: number;
  imported_rules: number;
  updated_rules: number;
  skipped_rules: number;
  failed_rules: number;
  last_sync?: string;
  last_sync_duration?: number;
  sync_count: number;
  last_error?: string;
}

export interface FeedSyncResult {
  feed_id: string;
  feed_name: string;
  success: boolean;
  start_time: string;
  end_time: string;
  duration: number;
  stats: FeedStats;
  errors: string[];
}

export interface FeedTemplate {
  id: string;
  name: string;
  description: string;
  type: string;
  config: Partial<Feed>;
}

Create frontend/src/services/feedsService.ts:
- getFeeds(): Promise<Feed[]>
- getFeed(id: string): Promise<Feed>
- createFeed(feed: Partial<Feed>): Promise<Feed>
- updateFeed(id: string, feed: Partial<Feed>): Promise<Feed>
- deleteFeed(id: string): Promise<void>
- syncFeed(id: string): Promise<FeedSyncResult>
- syncAllFeeds(): Promise<FeedSyncResult[]>
- getFeedHistory(id: string, limit?: number): Promise<FeedSyncResult[]>
- getFeedTemplates(): Promise<FeedTemplate[]>
- testFeed(id: string): Promise<{success: boolean; message: string}>
- enableFeed(id: string): Promise<void>
- disableFeed(id: string): Promise<void>

Add Zod schemas in frontend/src/schemas/api.schemas.ts for runtime validation.

**Test Strategy:**

Unit tests using Vitest: Mock axios calls, verify request payloads, test error handling, validate response parsing. Test type safety with TypeScript compiler checks.

## Subtasks

### 155.1. Define TypeScript interfaces in frontend/src/types/index.ts

**Status:** done  
**Dependencies:** None  

Add Feed, FeedStats, FeedSyncResult, and FeedTemplate interfaces to the types file matching backend Go struct definitions

**Details:**

Export the following interfaces in frontend/src/types/index.ts:

1. Feed interface with all fields: id, name, description, type ('git' | 'filesystem'), status ('active' | 'disabled' | 'error' | 'syncing'), enabled, priority, url, branch, path, auth_config, include_paths, exclude_paths, include_tags, exclude_tags, min_severity, auto_enable_rules, update_strategy ('manual' | 'startup' | 'scheduled'), update_schedule, last_sync, next_sync, stats (FeedStats type), tags, metadata, created_at, updated_at, created_by

2. FeedStats interface: total_rules, imported_rules, updated_rules, skipped_rules, failed_rules, last_sync, last_sync_duration, sync_count, last_error

3. FeedSyncResult interface: feed_id, feed_name, success, start_time, end_time, duration, stats (FeedStats type), errors array

4. FeedTemplate interface: id, name, description, type, config (Partial<Feed>)

Ensure all fields match the backend API contract and use appropriate TypeScript types (string literals for enums, optional fields with ?, Record for maps).

### 155.2. Create frontend/src/services/feedsService.ts with API methods

**Status:** done  
**Dependencies:** 155.1  

Implement complete feeds API service with all CRUD operations, sync methods, and feed management functions

**Details:**

Create frontend/src/services/feedsService.ts following the pattern in existing service files (actionsService.ts, rulesService.ts, etc.):

1. Import axios from './api' and feed types from '../types'
2. Implement all API methods:
   - getFeeds(): GET /api/feeds → Promise<Feed[]>
   - getFeed(id): GET /api/feeds/:id → Promise<Feed>
   - createFeed(feed): POST /api/feeds → Promise<Feed>
   - updateFeed(id, feed): PUT /api/feeds/:id → Promise<Feed>
   - deleteFeed(id): DELETE /api/feeds/:id → Promise<void>
   - syncFeed(id): POST /api/feeds/:id/sync → Promise<FeedSyncResult>
   - syncAllFeeds(): POST /api/feeds/sync → Promise<FeedSyncResult[]>
   - getFeedHistory(id, limit?): GET /api/feeds/:id/history?limit=N → Promise<FeedSyncResult[]>
   - getFeedTemplates(): GET /api/feeds/templates → Promise<FeedTemplate[]>
   - testFeed(id): POST /api/feeds/:id/test → Promise<{success: boolean; message: string}>
   - enableFeed(id): POST /api/feeds/:id/enable → Promise<void>
   - disableFeed(id): POST /api/feeds/:id/disable → Promise<void>

3. Use proper HTTP methods, handle response.data, propagate errors
4. Add JSDoc comments for each function
5. Export all functions as named exports

### 155.3. Add Zod schemas in frontend/src/schemas/api.schemas.ts

**Status:** done  
**Dependencies:** 155.1  

Define runtime validation schemas for Feed, FeedStats, FeedSyncResult, and FeedTemplate using Zod

**Details:**

Add to frontend/src/schemas/api.schemas.ts (or create if doesn't exist):

1. Import zod: import { z } from 'zod'
2. Create schemas matching the TypeScript interfaces:
   - FeedStatsSchema: z.object with all FeedStats fields
   - FeedSchema: z.object with all Feed fields, using z.enum for type/status/update_strategy, z.array for arrays, z.record for maps, .optional() for optional fields
   - FeedSyncResultSchema: z.object with FeedSyncResult fields, referencing FeedStatsSchema
   - FeedTemplateSchema: z.object with FeedTemplate fields

3. Export schemas and inferred types:
   export const FeedSchema = z.object({...})
   export type Feed = z.infer<typeof FeedSchema>

4. Add runtime validation helpers if needed (validateFeed, parseFeed, etc.)
5. Ensure schemas align exactly with TypeScript interfaces from subtask 1
6. Follow existing Zod schema patterns in the codebase
