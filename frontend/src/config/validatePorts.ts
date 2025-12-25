/**
 * Runtime port validation
 * This runs when the app starts and will throw an error if ports are misconfigured
 */

import { BACKEND_PORT, FRONTEND_DEV_PORT } from './ports';

export function validatePortConfiguration(): void {
  // Validate that constants are set correctly
  if (BACKEND_PORT !== 8080) {
    throw new Error(
      `CRITICAL ERROR: BACKEND_PORT is ${BACKEND_PORT} but MUST be 8080. ` +
      `Fix this in frontend/src/config/ports.ts`
    );
  }

  if (FRONTEND_DEV_PORT !== 3001) {
    throw new Error(
      `CRITICAL ERROR: FRONTEND_DEV_PORT is ${FRONTEND_DEV_PORT} but MUST be 3001. ` +
      `Fix this in frontend/src/config/ports.ts`
    );
  }

  // Port configuration validated
}
