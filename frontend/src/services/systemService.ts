/**
 * System Service (TASK 160.2)
 * Provides API methods for system-level operations
 * Including first-run detection and setup completion
 */

import { AxiosInstance } from 'axios';

export interface FirstRunResponse {
  is_first_run: boolean;
}

export interface SetupCompleteRequest {
  skipped_wizard?: boolean;
}

export interface SetupCompleteResponse {
  success: boolean;
  message: string;
}

class SystemService {
  private api: AxiosInstance;

  constructor(apiInstance: AxiosInstance) {
    this.api = apiInstance;
  }

  /**
   * Check if this is the first run of the application
   * SECURITY: This endpoint is unauthenticated by design
   */
  async checkFirstRun(): Promise<boolean> {
    const response = await this.api.get<FirstRunResponse>('/system/first-run');
    return response.data.is_first_run;
  }

  /**
   * Mark the setup wizard as completed
   * Requires authentication
   */
  async completeSetup(skippedWizard = false): Promise<SetupCompleteResponse> {
    const response = await this.api.post<SetupCompleteResponse>('/system/complete-setup', {
      skipped_wizard: skippedWizard,
    } as SetupCompleteRequest);
    return response.data;
  }
}

export default SystemService;
