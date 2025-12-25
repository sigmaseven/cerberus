# Bug Report: Evidence Upload Endpoint Missing

**Date:** 2025-12-13
**Reporter:** Frontend Team
**Priority:** Medium
**Component:** Backend API

---

## Summary

Evidence upload functionality in Alert Triage is non-functional because the required API endpoint is not implemented in the backend.

---

## Current Behavior

When a user attempts to upload evidence to an alert via the Alert Detail Panel:
1. User clicks "Add" button in the Evidence section
2. Modal opens, user selects file and optional description
3. User clicks "Upload Evidence"
4. **Request fails** - endpoint returns 404 Not Found

---

## Expected Behavior

Evidence upload should successfully store the file and return the evidence metadata.

---

## Technical Details

### Frontend Implementation (Complete)

**Service function:** `src/services/alertService.ts:646-668`
```typescript
export async function uploadAlertEvidence(
  alertId: string,
  file: File,
  description?: string
): Promise<ServiceResult<AlertEvidence>> {
  const formData = new FormData();
  formData.append('file', file);
  if (description !== undefined) {
    formData.append('description', description);
  }

  const response = await apiClient.post<unknown>(
    `/api/v1/alerts/${encodeURIComponent(alertId)}/evidence`,
    formData,
    { headers: { 'Content-Type': 'multipart/form-data' } }
  );
  // ... validation
}
```

**UI Components:**
- `src/pages/AlertTriage/index.tsx` - `EvidenceAddModal` component (line 945)
- `src/pages/AlertTriage/components/AlertDetailPanel.tsx` - Evidence section with Add button

### Missing Backend Endpoint

**Endpoint:** `POST /api/v1/alerts/{alertId}/evidence`

**Not found in:** `docs/swagger.yaml`

---

## Required Backend Implementation

### 1. Add Endpoint to swagger.yaml

```yaml
/api/v1/alerts/{alertId}/evidence:
  post:
    tags:
      - alerts
    summary: Upload evidence to an alert
    operationId: uploadAlertEvidence
    parameters:
      - name: alertId
        in: path
        required: true
        schema:
          type: string
    requestBody:
      required: true
      content:
        multipart/form-data:
          schema:
            type: object
            required:
              - file
            properties:
              file:
                type: string
                format: binary
                description: Evidence file to upload
              description:
                type: string
                description: Optional description of the evidence
    responses:
      '201':
        description: Evidence uploaded successfully
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AlertEvidence'
      '400':
        description: Invalid request (file too large, invalid format, etc.)
      '404':
        description: Alert not found
      '500':
        description: Internal server error
```

### 2. AlertEvidence Schema (for swagger.yaml)

```yaml
AlertEvidence:
  type: object
  required:
    - id
    - type
    - name
    - size
    - mime_type
    - uploaded_at
    - uploaded_by
    - hash
  properties:
    id:
      type: string
      description: Unique evidence identifier
    type:
      type: string
      enum: [log, file, screenshot, network_capture, process_dump, other]
      description: Type of evidence
    name:
      type: string
      description: Original filename
    size:
      type: integer
      description: File size in bytes
    mime_type:
      type: string
      description: MIME type of the file
    uploaded_at:
      type: string
      format: date-time
      description: ISO 8601 timestamp
    uploaded_by:
      $ref: '#/components/schemas/UserReference'
    hash:
      type: string
      description: SHA256 hash of the file
    description:
      type: string
      description: Optional description
```

### 3. Additional Related Endpoints (also missing)

These endpoints are also called by the frontend but not in swagger.yaml:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/alerts/{alertId}/evidence/{evidenceId}/download` | Download evidence file |
| DELETE | `/api/v1/alerts/{alertId}/evidence/{evidenceId}` | Delete evidence |

---

## Frontend Zod Validation Schema

The frontend expects this response structure (`src/services/alertService.ts:87-97`):

```typescript
const alertEvidenceSchema = z.object({
  id: z.string(),
  type: z.enum(['log', 'file', 'screenshot', 'network_capture', 'process_dump', 'other']),
  name: z.string(),
  size: z.number(),
  mime_type: z.string(),
  uploaded_at: z.string(),
  uploaded_by: userReferenceSchema,  // { id, name, email, role, avatar_url? }
  hash: z.string(),
  description: z.string().optional(),
});
```

---

## Acceptance Criteria

- [ ] `POST /api/v1/alerts/{alertId}/evidence` endpoint implemented
- [ ] Accepts `multipart/form-data` with `file` (required) and `description` (optional)
- [ ] Returns `AlertEvidence` object on success (201)
- [ ] Returns 404 if alert doesn't exist
- [ ] Returns 400 for invalid/oversized files
- [ ] File is stored securely with SHA256 hash computed
- [ ] Evidence is associated with the alert in the database
- [ ] Endpoint documented in swagger.yaml

---

## Notes

- Frontend UI is fully implemented and ready
- Evidence section in Alert Detail Panel displays existing evidence correctly (if present in alert data)
- Download and delete functionality also depend on unimplemented endpoints
