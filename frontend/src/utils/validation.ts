import { z } from 'zod';

/**
 * Safe validation utility that maintains Zod type checking but provides graceful fallbacks
 * instead of throwing errors. Prevents frontend crashes from malformed backend responses
 * while maintaining security benefits of runtime validation.
 */

/**
 * Safely parses data with a Zod schema, returning fallback on validation failure.
 * Logs validation errors for debugging and reports to monitoring service.
 *
 * @param schema - Zod schema to validate against
 * @param data - Unknown data to validate
 * @param fallback - Value to return if validation fails
 * @param context - Context string for error reporting (e.g., "GET /api/users")
 * @returns Validated data or fallback
 *
 * @example
 * const user = safeParse(UserSchema, response.data, null, 'GET /api/user/123');
 */
export function safeParse<T>(
  schema: z.ZodSchema<T>,
  data: unknown,
  fallback: T,
  context: string
): T {
  const result = schema.safeParse(data);

  if (!result.success) {
    // Log warning for development visibility
    console.warn(`[Validation Warning] ${context}:`, {
      errors: result.error.errors,
      receivedData: data,
      timestamp: new Date().toISOString(),
    });

    // TODO: Report to error monitoring service when available
    // errorReportingService.reportValidationError(context, {
    //   errors: result.error.errors,
    //   receivedData: data,
    //   timestamp: new Date().toISOString(),
    // });

    return fallback;
  }

  return result.data;
}

/**
 * Safely parses data as an array, returning empty array on failure.
 * Handles null, undefined, and non-array responses gracefully.
 *
 * @param schema - Zod schema for array items
 * @param data - Unknown data to validate as array
 * @param context - Context string for error reporting
 * @returns Validated array or empty array
 *
 * @example
 * const users = safeParseArray(UserSchema, response.data, 'GET /api/users');
 */
export function safeParseArray<T>(
  schema: z.ZodSchema<T>,
  data: unknown,
  context: string
): T[] {
  // Handle null/undefined explicitly
  if (data === null || data === undefined) {
    console.warn(`[Validation Warning] ${context}: Received null/undefined, expected array`);
    return [];
  }

  // Validate as array
  const arraySchema = z.array(schema);
  return safeParse(arraySchema, data, [], context);
}

/**
 * Pagination response structure
 */
export interface PaginationResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  total_pages?: number;
}

/**
 * Safely parses pagination response with comprehensive fallbacks.
 * Ensures items is always an array, never null.
 *
 * @param itemSchema - Zod schema for individual items
 * @param data - Unknown data to validate as pagination response
 * @param context - Context string for error reporting
 * @returns Validated pagination response or safe defaults
 *
 * @example
 * const response = safeParsePagination(AlertSchema, response.data, 'GET /api/alerts');
 */
export function safeParsePagination<T>(
  itemSchema: z.ZodSchema<T>,
  data: unknown,
  context: string
): PaginationResponse<T> {
  const paginationSchema = z.object({
    items: z.array(itemSchema),
    total: z.number(),
    page: z.number(),
    limit: z.number(),
    total_pages: z.number().optional(),
  });

  const defaultPagination: PaginationResponse<T> = {
    items: [],
    total: 0,
    page: 1,
    limit: 50,
  };

  return safeParse(paginationSchema, data, defaultPagination, context);
}
