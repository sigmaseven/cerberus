import { http, HttpResponse } from 'msw';
import {
  mockListeners,
  mockTemplates,
  mockEvents,
  mockBulkOperationResult,
  mockBulkImportResult,
} from '../fixtures/listeners';

import { BACKEND_PORT } from '../../config/ports';

const API_BASE = `http://localhost:${BACKEND_PORT}/api/v1`;

export const handlers = [
  // Dynamic Listeners
  http.get(`${API_BASE}/listeners/dynamic`, () => {
    return HttpResponse.json(mockListeners);
  }),

   http.post(`${API_BASE}/listeners/dynamic`, async ({ request }) => {
     const body = await request.json();
     return HttpResponse.json({
       // eslint-disable-next-line @typescript-eslint/no-explicit-any
       ...(body as any),
       id: 'new-listener-id',
       status: 'stopped',
       created_at: new Date().toISOString(),
     });
   }),

   http.put(`${API_BASE}/listeners/dynamic/:id`, async ({ params, request }) => {
     const body = await request.json();
     return HttpResponse.json({
       // eslint-disable-next-line @typescript-eslint/no-explicit-any
       ...(body as any),
       id: params.id,
     });
   }),

  http.delete(`${API_BASE}/listeners/dynamic/:id`, () => {
    return new HttpResponse(null, { status: 204 });
  }),

  http.post(`${API_BASE}/listeners/dynamic/:id/start`, () => {
    return new HttpResponse(null, { status: 204 });
  }),

  http.post(`${API_BASE}/listeners/dynamic/:id/stop`, () => {
    return new HttpResponse(null, { status: 204 });
  }),

  http.get(`${API_BASE}/listeners/dynamic/:id/stats`, () => {
    return HttpResponse.json({
      events_received: 1234,
      events_per_minute: 42,
      error_count: 5,
      error_rate: 0.004,
      bytes_received: 1048576,
      last_event: new Date().toISOString(),
      uptime_duration: 3600000000000,
      connection_count: 3,
    });
  }),

   // Bulk Operations
   http.post(`${API_BASE}/listeners/bulk`, async ({ request }) => {
     // eslint-disable-next-line @typescript-eslint/no-explicit-any
     const body: any = await request.json();
     return HttpResponse.json(mockBulkOperationResult(body.operation, body.listener_ids));
   }),

  http.get(`${API_BASE}/listeners/bulk/export`, () => {
    return HttpResponse.json(mockListeners, {
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename=listeners.json',
      },
    });
  }),

  http.post(`${API_BASE}/listeners/bulk/import`, () => {
    return HttpResponse.json(mockBulkImportResult());
  }),

  // Templates
  http.get(`${API_BASE}/listeners/templates`, ({ request }) => {
    const url = new URL(request.url);
    const category = url.searchParams.get('category');
    const tag = url.searchParams.get('tag');

    let filtered = mockTemplates;
    if (category) {
      filtered = filtered.filter(t => t.category === category);
    }
    if (tag) {
      filtered = filtered.filter(t => t.tags.includes(tag));
    }

    return HttpResponse.json(filtered);
  }),

  http.get(`${API_BASE}/listeners/templates/:id`, ({ params }) => {
    const template = mockTemplates.find(t => t.id === params.id);
    if (!template) {
      return new HttpResponse(null, { status: 404 });
    }
    return HttpResponse.json(template);
  }),

   http.post(`${API_BASE}/listeners/templates/:id/create`, async ({ params, request }) => {
     // eslint-disable-next-line @typescript-eslint/no-explicit-any
     const customizations: any = await request.json();
     const template = mockTemplates.find(t => t.id === params.id);

    if (!template) {
      return new HttpResponse(null, { status: 404 });
    }

    return HttpResponse.json({
      ...template.config,
      ...customizations,
      id: 'new-listener-from-template',
      created_at: new Date().toISOString(),
    });
  }),

  // Event Preview
  http.get(`${API_BASE}/listeners/dynamic/:id/events`, ({ request }) => {
    const url = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit') || '10');

    return HttpResponse.json({
      listener_id: 'test-listener',
      listener_name: 'Test Listener',
      source: 'test-source',
      events: mockEvents.slice(0, limit),
      count: Math.min(mockEvents.length, limit),
      limit,
    });
  }),

  http.get(`${API_BASE}/events/by-source`, ({ request }) => {
    const url = new URL(request.url);
    const source = url.searchParams.get('source');
    const limit = parseInt(url.searchParams.get('limit') || '10');

    if (!source) {
      return new HttpResponse(JSON.stringify({ error: 'source parameter is required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return HttpResponse.json({
      source,
      events: mockEvents.slice(0, limit),
      count: Math.min(mockEvents.length, limit),
      limit,
    });
  }),

  // Rules (existing)
  http.get(`${API_BASE}/rules`, () => {
    return HttpResponse.json({
      items: [],
      total: 0,
      page: 1,
      limit: 50,
      total_pages: 0,
    });
  }),

  // Correlation Rules (existing)
  http.get(`${API_BASE}/correlation-rules`, () => {
    return HttpResponse.json({
      items: [],
      total: 0,
      page: 1,
      limit: 50,
      total_pages: 0,
    });
  }),

  // Actions (existing)
  http.get(`${API_BASE}/actions`, () => {
    return HttpResponse.json([]);
  }),

  // Alerts (existing)
  http.get(`${API_BASE}/alerts`, () => {
    return HttpResponse.json({
      items: [],
      total: 0,
      page: 1,
      limit: 50,
      total_pages: 0,
    });
  }),

  // Events (existing)
  http.get(`${API_BASE}/events`, () => {
    return HttpResponse.json({
      items: [],
      total: 0,
      page: 1,
      limit: 50,
      total_pages: 0,
    });
  }),

  // Dashboard stats
  http.get(`${API_BASE}/dashboard/stats`, () => {
    return HttpResponse.json({
      total_events: 0,
      active_alerts: 0,
      rules_fired: 0,
      system_health: 'healthy',
    });
  }),

  // Listener status
  http.get(`${API_BASE}/listeners/status`, () => {
    return HttpResponse.json({
      syslog: { active: true, port: 514, events_per_minute: 0, errors: 0 },
      cef: { active: true, port: 515, events_per_minute: 0, errors: 0 },
      json: { active: false, port: 8888, events_per_minute: 0, errors: 0 },
    });
  }),
];
