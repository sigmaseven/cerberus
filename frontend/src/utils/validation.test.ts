import { describe, it, expect, vi, beforeEach } from 'vitest';
import { z } from 'zod';
import { safeParse, safeParseArray, safeParsePagination, PaginationResponse } from './validation';

describe('validation utilities', () => {
  beforeEach(() => {
    // Clear console.warn spy
    vi.clearAllMocks();
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  describe('safeParse', () => {
    const UserSchema = z.object({
      id: z.string(),
      name: z.string(),
      email: z.string().email(),
    });

    it('should return parsed data for valid input', () => {
      const validData = {
        id: '123',
        name: 'John Doe',
        email: 'john@example.com',
      };

      const result = safeParse(UserSchema, validData, null, 'TEST');

      expect(result).toEqual(validData);
      expect(console.warn).not.toHaveBeenCalled();
    });

    it('should return fallback for invalid input', () => {
      const invalidData = {
        id: '123',
        name: 'John Doe',
        // Missing email
      };

      const fallback = null;
      const result = safeParse(UserSchema, invalidData, fallback, 'TEST');

      expect(result).toBe(fallback);
      expect(console.warn).toHaveBeenCalled();
      const warnCall = (console.warn as any).mock.calls[0];
      expect(warnCall[0]).toContain('[Validation Warning] TEST');
      expect(warnCall[1]).toMatchObject({
        receivedData: invalidData,
      });
    });

    it('should handle null data', () => {
      const result = safeParse(UserSchema, null, { id: 'default', name: 'Default', email: 'default@example.com' }, 'TEST');

      expect(result).toEqual({ id: 'default', name: 'Default', email: 'default@example.com' });
      expect(console.warn).toHaveBeenCalled();
    });

    it('should handle undefined data', () => {
      const result = safeParse(UserSchema, undefined, null, 'TEST');

      expect(result).toBe(null);
      expect(console.warn).toHaveBeenCalled();
    });

    it('should include context in warning message', () => {
      safeParse(UserSchema, {}, null, 'GET /api/users/123');

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('GET /api/users/123'),
        expect.any(Object)
      );
    });
  });

  describe('safeParseArray', () => {
    const ItemSchema = z.object({
      id: z.string(),
      value: z.number(),
    });

    it('should return parsed array for valid input', () => {
      const validData = [
        { id: '1', value: 10 },
        { id: '2', value: 20 },
      ];

      const result = safeParseArray(ItemSchema, validData, 'TEST');

      expect(result).toEqual(validData);
      expect(console.warn).not.toHaveBeenCalled();
    });

    it('should return empty array for null input', () => {
      const result = safeParseArray(ItemSchema, null, 'TEST');

      expect(result).toEqual([]);
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Received null/undefined, expected array')
      );
    });

    it('should return empty array for undefined input', () => {
      const result = safeParseArray(ItemSchema, undefined, 'TEST');

      expect(result).toEqual([]);
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Received null/undefined, expected array')
      );
    });

    it('should return empty array for non-array input', () => {
      const result = safeParseArray(ItemSchema, { not: 'an array' }, 'TEST');

      expect(result).toEqual([]);
      expect(console.warn).toHaveBeenCalled();
    });

    it('should return empty array for array with invalid items', () => {
      const invalidData = [
        { id: '1', value: 10 },
        { id: '2' }, // Missing value
      ];

      const result = safeParseArray(ItemSchema, invalidData, 'TEST');

      expect(result).toEqual([]);
      expect(console.warn).toHaveBeenCalled();
    });

    it('should handle empty array', () => {
      const result = safeParseArray(ItemSchema, [], 'TEST');

      expect(result).toEqual([]);
      expect(console.warn).not.toHaveBeenCalled();
    });
  });

  describe('safeParsePagination', () => {
    const ItemSchema = z.object({
      id: z.string(),
      name: z.string(),
    });

    it('should return parsed pagination for valid input', () => {
      const validData = {
        items: [
          { id: '1', name: 'Item 1' },
          { id: '2', name: 'Item 2' },
        ],
        total: 10,
        page: 1,
        limit: 2,
        total_pages: 5,
      };

      const result = safeParsePagination(ItemSchema, validData, 'TEST');

      expect(result).toEqual(validData);
      expect(console.warn).not.toHaveBeenCalled();
    });

    it('should return default pagination for null input', () => {
      const result = safeParsePagination(ItemSchema, null, 'TEST');

      expect(result).toEqual({
        items: [],
        total: 0,
        page: 1,
        limit: 50,
      });
      expect(console.warn).toHaveBeenCalled();
    });

    it('should return default pagination for undefined input', () => {
      const result = safeParsePagination(ItemSchema, undefined, 'TEST');

      expect(result).toEqual({
        items: [],
        total: 0,
        page: 1,
        limit: 50,
      });
    });

    it('should return default pagination for malformed object', () => {
      const malformedData = {
        // Missing items array
        total: 10,
        page: 1,
      };

      const result = safeParsePagination(ItemSchema, malformedData, 'TEST');

      expect(result).toEqual({
        items: [],
        total: 0,
        page: 1,
        limit: 50,
      });
      expect(console.warn).toHaveBeenCalled();
    });

    it('should handle pagination with null items field', () => {
      const dataWithNullItems = {
        items: null,
        total: 0,
        page: 1,
        limit: 50,
      };

      const result = safeParsePagination(ItemSchema, dataWithNullItems, 'TEST');

      expect(result).toEqual({
        items: [],
        total: 0,
        page: 1,
        limit: 50,
      });
      expect(console.warn).toHaveBeenCalled();
    });

    it('should handle pagination with invalid items', () => {
      const dataWithInvalidItems = {
        items: [{ id: '1' }], // Missing name field
        total: 1,
        page: 1,
        limit: 50,
      };

      const result = safeParsePagination(ItemSchema, dataWithInvalidItems, 'TEST');

      expect(result).toEqual({
        items: [],
        total: 0,
        page: 1,
        limit: 50,
      });
    });

    it('should work with optional total_pages', () => {
      const validDataWithoutTotalPages = {
        items: [{ id: '1', name: 'Item' }],
        total: 1,
        page: 1,
        limit: 50,
      };

      const result = safeParsePagination(ItemSchema, validDataWithoutTotalPages, 'TEST');

      expect(result).toEqual(validDataWithoutTotalPages);
      expect(result.total_pages).toBeUndefined();
    });

    it('should ensure items is always an array, never null', () => {
      const result1 = safeParsePagination(ItemSchema, null, 'TEST');
      const result2 = safeParsePagination(ItemSchema, undefined, 'TEST');
      const result3 = safeParsePagination(ItemSchema, {}, 'TEST');

      expect(Array.isArray(result1.items)).toBe(true);
      expect(Array.isArray(result2.items)).toBe(true);
      expect(Array.isArray(result3.items)).toBe(true);

      expect(result1.items).not.toBeNull();
      expect(result2.items).not.toBeNull();
      expect(result3.items).not.toBeNull();
    });
  });

  describe('type inference', () => {
    it('should infer correct types for safeParse', () => {
      const schema = z.object({ id: z.string() });
      const result = safeParse(schema, { id: '123' }, { id: 'default' }, 'TEST');

      // TypeScript should infer result as { id: string }
      expect(result.id).toBeDefined();
    });

    it('should infer correct types for safeParseArray', () => {
      const schema = z.object({ id: z.string() });
      const result = safeParseArray(schema, [{ id: '123' }], 'TEST');

      // TypeScript should infer result as Array<{ id: string }>
      expect(result).toBeInstanceOf(Array);
      if (result.length > 0) {
        expect(result[0].id).toBeDefined();
      }
    });

    it('should infer correct types for safeParsePagination', () => {
      const schema = z.object({ id: z.string() });
      const result = safeParsePagination(schema, {
        items: [{ id: '123' }],
        total: 1,
        page: 1,
        limit: 50,
      }, 'TEST');

      // TypeScript should infer result as PaginationResponse<{ id: string }>
      expect(result.items).toBeInstanceOf(Array);
      expect(result.total).toBeTypeOf('number');
      expect(result.page).toBeTypeOf('number');
      expect(result.limit).toBeTypeOf('number');
    });
  });
});
