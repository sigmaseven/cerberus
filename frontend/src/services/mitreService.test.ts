import { describe, it, expect, vi, beforeEach } from 'vitest';
import MitreService from './mitreService';
import { AxiosInstance } from 'axios';

describe('MitreService', () => {
  let mitreService: MitreService;
  let mockApi: AxiosInstance;

  beforeEach(() => {
    mockApi = {
      get: vi.fn(),
      post: vi.fn()} as any;
    mitreService = new MitreService(mockApi);
  });

  describe('getTactics', () => {
    it('fetches all MITRE tactics', async () => {
      const mockTactics = [
        { id: 'TA0001', name: 'Initial Access', description: 'Initial access tactics' },
        { id: 'TA0002', name: 'Execution', description: 'Execution tactics' },
      ];

      vi.mocked(mockApi.get).mockResolvedValue({ data: mockTactics });

      const result = await mitreService.getTactics();

      expect(mockApi.get).toHaveBeenCalledWith('/mitre/tactics');
      expect(result).toEqual(mockTactics);
    });
  });

  describe('getTactic', () => {
    it('fetches a single tactic by ID', async () => {
      const mockTactic = {
        id: 'TA0001',
        name: 'Initial Access',
        description: 'The adversary is trying to get into your network.'};

      vi.mocked(mockApi.get).mockResolvedValue({ data: mockTactic });

      const result = await mitreService.getTactic('TA0001');

      expect(mockApi.get).toHaveBeenCalledWith('/mitre/tactics/TA0001');
      expect(result).toEqual(mockTactic);
    });
  });

  describe('getTechniques', () => {
    it('fetches all MITRE techniques', async () => {
      const mockTechniques = [
        {
          id: 'T1078',
          name: 'Valid Accounts',
          description: 'Valid account usage',
          tactics: ['initial-access', 'persistence']},
      ];

      vi.mocked(mockApi.get).mockResolvedValue({ data: { techniques: mockTechniques } });

      const result = await mitreService.getTechniques();

      expect(mockApi.get).toHaveBeenCalled();
      expect(result.techniques).toEqual(mockTechniques);
    });

    it('fetches techniques by tactic', async () => {
      const mockTechniques = [
        {
          id: 'T1078',
          name: 'Valid Accounts',
          tactics: ['initial-access']},
      ];

      vi.mocked(mockApi.get).mockResolvedValue({ data: { techniques: mockTechniques } });

      const result = await mitreService.getTechniques({ tactic_id: 'initial-access' });

      expect(mockApi.get).toHaveBeenCalled();
      expect(result.techniques).toEqual(mockTechniques);
    });
  });

  describe('getTechnique', () => {
    it('fetches a single technique by ID', async () => {
      const mockTechnique = {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may obtain and abuse credentials',
        tactics: ['initial-access', 'persistence', 'privilege-escalation'],
        detection: 'Monitor for unusual account activity'};

      vi.mocked(mockApi.get).mockResolvedValue({ data: mockTechnique });

      const result = await mitreService.getTechnique('T1078');

      expect(mockApi.get).toHaveBeenCalledWith('/mitre/techniques/T1078');
      expect(result).toEqual(mockTechnique);
    });
  });

  describe('searchTechniques', () => {
    it('searches techniques by query', async () => {
      const mockResults = [
        {
          id: 'T1078',
          name: 'Valid Accounts',
          description: 'Valid account usage'},
        {
          id: 'T1098',
          name: 'Account Manipulation',
          description: 'Account manipulation'},
      ];

      vi.mocked(mockApi.get).mockResolvedValue({ data: mockResults });

      const result = await mitreService.searchTechniques('account');

      expect(mockApi.get).toHaveBeenCalled();
      expect(result).toEqual(mockResults);
    });

    it('handles empty search query', async () => {
      vi.mocked(mockApi.get).mockResolvedValue({ data: [] });

      const result = await mitreService.searchTechniques('');

      expect(mockApi.get).toHaveBeenCalled();
      expect(result).toEqual([]);
    });
  });

  describe('getCoverageReport', () => {
    it('fetches MITRE ATT&CK coverage statistics', async () => {
      const mockCoverage = {
        total_techniques: 200,
        covered_techniques: 150,
        coverage_percentage: 75,
        by_tactic: {
          'initial-access': 10,
          execution: 15,
          persistence: 20}};

      vi.mocked(mockApi.get).mockResolvedValue({ data: mockCoverage });

      const result = await mitreService.getCoverageReport();

      expect(mockApi.get).toHaveBeenCalledWith('/mitre/coverage');
      expect(result).toEqual(mockCoverage);
    });
  });

  describe('getTacticColor', () => {
    it('returns correct color for known tactics', () => {
      expect(mitreService.getTacticColor('initial-access')).toBe('#5F7A8B');
      expect(mitreService.getTacticColor('execution')).toBe('#4F8A8B');
      expect(mitreService.getTacticColor('persistence')).toBe('#2D7A8B');
      expect(mitreService.getTacticColor('credential-access')).toBe('#8B7A5F');
    });

    it('returns default color for unknown tactics', () => {
      expect(mitreService.getTacticColor('unknown-tactic')).toBe('#888888');
    });

    it('handles case insensitivity', () => {
      expect(mitreService.getTacticColor('INITIAL-ACCESS')).toBe('#5F7A8B');
      expect(mitreService.getTacticColor('Initial-Access')).toBe('#5F7A8B');
    });
  });

  describe('error handling', () => {
    it('throws error when API call fails', async () => {
      vi.mocked(mockApi.get).mockRejectedValue(new Error('Network error'));

      await expect(mitreService.getTactics()).rejects.toThrow('Network error');
    });

    it('handles 404 errors gracefully', async () => {
      const error = new Error('Not found');
      (error as any).response = { status: 404 };
      vi.mocked(mockApi.get).mockRejectedValue(error);

      await expect(mitreService.getTechnique('T9999')).rejects.toThrow();
    });
  });
});
