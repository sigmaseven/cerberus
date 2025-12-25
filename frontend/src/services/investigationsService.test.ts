import { describe, it, expect, vi, beforeEach } from 'vitest';
import investigationsService from './investigationsService';
import api from './api';

vi.mock('./api');

describe('InvestigationsService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getInvestigations', () => {
    it('fetches investigations with filters', async () => {
      const mockResponse = {
        data: {
          investigations: [
            {
              investigation_id: 'inv-1',
              title: 'Test Investigation',
              status: 'open',
              priority: 'high'},
          ],
          total: 1}};

      vi.mocked(api.get).mockResolvedValue(mockResponse);

      const result = await investigationsService.getInvestigations({
        status: 'open',
        priority: 'high',
        limit: 20,
        offset: 0});

      expect(api.get).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/investigations')
      );
      expect(result).toEqual(mockResponse.data);
    });

    it('handles empty filters', async () => {
      const mockResponse = {
        data: {
          investigations: [],
          total: 0}};

      vi.mocked(api.get).mockResolvedValue(mockResponse);

      const result = await investigationsService.getInvestigations();

      expect(api.get).toHaveBeenCalled();
      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('getInvestigation', () => {
    it('fetches a single investigation by ID', async () => {
      const mockInvestigation = {
        investigation_id: 'inv-123',
        title: 'Test Investigation',
        status: 'open',
        priority: 'high'};

      vi.mocked(api.get).mockResolvedValue({ data: mockInvestigation });

      const result = await investigationsService.getInvestigation('inv-123');

      expect(api.get).toHaveBeenCalledWith('/api/v1/investigations/inv-123');
      expect(result).toEqual(mockInvestigation);
    });
  });

  describe('createInvestigation', () => {
    it('creates a new investigation', async () => {
      const newInvestigation = {
        title: 'New Investigation',
        description: 'Test description',
        priority: 'medium'};

      const mockResponse = {
        data: {
          investigation_id: 'inv-new',
          ...newInvestigation,
          status: 'open',
          created_at: '2024-01-01T00:00:00Z'}};

      vi.mocked(api.post).mockResolvedValue(mockResponse);

      const result = await investigationsService.createInvestigation(newInvestigation);

      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/investigations',
        newInvestigation
      );
      expect(result).toEqual(mockResponse.data);
    });

    it('creates investigation with alert IDs', async () => {
      const newInvestigation = {
        title: 'New Investigation',
        description: 'Test description',
        priority: 'high',
        alert_ids: ['alert-1', 'alert-2']};

      vi.mocked(api.post).mockResolvedValue({ data: { investigation_id: 'inv-new' } });

      await investigationsService.createInvestigation(newInvestigation);

      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/investigations',
        expect.objectContaining({
          alert_ids: ['alert-1', 'alert-2']})
      );
    });
  });

  describe('updateInvestigation', () => {
    it('updates an existing investigation', async () => {
      const updates = {
        title: 'Updated Title',
        priority: 'critical'};

      const mockResponse = {
        data: {
          investigation_id: 'inv-123',
          ...updates}};

      vi.mocked(api.put).mockResolvedValue(mockResponse);

      const result = await investigationsService.updateInvestigation('inv-123', updates);

      expect(api.put).toHaveBeenCalledWith(
        '/api/v1/investigations/inv-123',
        updates
      );
      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('closeInvestigation', () => {
    it('closes an investigation with verdict', async () => {
      const closeData = {
        verdict: 'true_positive' as const,
        resolution_category: 'Malware Infection',
        summary: 'Investigation completed'};

      const mockResponse = {
        data: {
          investigation_id: 'inv-123',
          status: 'closed',
          verdict: 'true_positive'}};

      vi.mocked(api.post).mockResolvedValue(mockResponse);

      const result = await investigationsService.closeInvestigation('inv-123', closeData);

      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/investigations/inv-123/close',
        closeData
      );
      expect(result).toEqual(mockResponse.data);
    });

    it('includes ML feedback when provided', async () => {
      const closeData = {
        verdict: 'false_positive' as const,
        resolution_category: 'False Positive',
        summary: 'Not a real threat',
        ml_feedback: {
          was_correct: false,
          false_positive_reason: 'Benign activity'}};

      vi.mocked(api.post).mockResolvedValue({ data: {} });

      await investigationsService.closeInvestigation('inv-123', closeData);

      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/investigations/inv-123/close',
        expect.objectContaining({
          ml_feedback: expect.objectContaining({
            was_correct: false,
            false_positive_reason: 'Benign activity'})})
      );
    });
  });

  describe('addNote', () => {
    it('adds a note to an investigation', async () => {
      const mockResponse = {
        data: {
          investigation_id: 'inv-123',
          notes: [
            {
              note_id: 'note-1',
              content: 'Test note',
              created_at: '2024-01-01T00:00:00Z',
              created_by: 'analyst-1'},
          ]}};

      vi.mocked(api.post).mockResolvedValue(mockResponse);

      const result = await investigationsService.addNote('inv-123', 'Test note');

      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/investigations/inv-123/notes',
        { content: 'Test note' }
      );
      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('addAlert', () => {
    it('links an alert to an investigation', async () => {
      const mockResponse = {
        data: {
          investigation_id: 'inv-123',
          alert_ids: ['alert-1', 'alert-2']}};

      vi.mocked(api.post).mockResolvedValue(mockResponse);

      const result = await investigationsService.addAlert('inv-123', 'alert-2');

      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/investigations/inv-123/alerts',
        { alert_id: 'alert-2' }
      );
      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('getTimeline', () => {
    it('fetches investigation timeline', async () => {
      const mockTimeline = {
        events: [
          {
            type: 'alert',
            timestamp: '2024-01-01T00:00:00Z',
            data: { alert_id: 'alert-1' }},
          {
            type: 'note',
            timestamp: '2024-01-01T01:00:00Z',
            data: { content: 'Investigation started' }},
        ]};

      vi.mocked(api.get).mockResolvedValue({ data: mockTimeline });

      const result = await investigationsService.getTimeline('inv-123');

      expect(api.get).toHaveBeenCalledWith('/api/v1/investigations/inv-123/timeline');
      expect(result).toEqual(mockTimeline);
    });
  });

  describe('getStatistics', () => {
    it('fetches investigation statistics', async () => {
      const mockStats = {
        total: 100,
        open_count: 25,
        closed_count: 75,
        by_status: {
          open: 10,
          in_progress: 15,
          awaiting_review: 5,
          closed: 70},
        by_priority: {
          critical: 5,
          high: 20,
          medium: 50,
          low: 25},
        avg_resolution_time_hours: 48.5};

      vi.mocked(api.get).mockResolvedValue({ data: mockStats });

      const result = await investigationsService.getStatistics();

      expect(api.get).toHaveBeenCalledWith('/api/v1/investigations/statistics');
      expect(result).toEqual(mockStats);
    });
  });

  describe('error handling', () => {
    it('throws error when API call fails', async () => {
      vi.mocked(api.get).mockRejectedValue(new Error('Network error'));

      await expect(
        investigationsService.getInvestigation('inv-123')
      ).rejects.toThrow('Network error');
    });
  });
});
