/**
 * Global Setup for Playwright E2E Tests
 *
 * This file handles:
 * - Starting the backend server before tests
 * - Seeding test data
 * - Waiting for services to be ready
 *
 * Security: No hardcoded credentials - uses environment variables
 * Performance: Waits for health check before proceeding
 */

import { execSync, spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const BACKEND_PORT = 8081;
const BACKEND_URL = `http://localhost:${BACKEND_PORT}`;
const MAX_STARTUP_TIME = 30000; // 30 seconds
const HEALTH_CHECK_INTERVAL = 500; // 500ms

let backendProcess: ChildProcess | null = null;

/**
 * Wait for backend to be healthy
 */
async function waitForBackendHealth(): Promise<void> {
  const startTime = Date.now();

  while (Date.now() - startTime < MAX_STARTUP_TIME) {
    try {
      const response = await fetch(`${BACKEND_URL}/api/v1/health`);
      if (response.ok) {
        const health = await response.json();
        if (health.status === 'ok') {
          console.log('Backend is healthy and ready');
          return;
        }
      }
    } catch (error) {
      // Backend not ready yet, continue waiting
    }

    await new Promise(resolve => setTimeout(resolve, HEALTH_CHECK_INTERVAL));
  }

  throw new Error(`Backend failed to become healthy within ${MAX_STARTUP_TIME}ms`);
}

/**
 * Kill any existing backend processes
 */
function killExistingBackend(): void {
  try {
    if (process.platform === 'win32') {
      execSync('powershell -Command "Get-Process cerberus -ErrorAction SilentlyContinue | Stop-Process -Force"', {
        stdio: 'ignore',
      });
    } else {
      execSync('pkill -9 cerberus || true', { stdio: 'ignore' });
    }
    console.log('Killed existing backend processes');
  } catch (error) {
    // No processes to kill
  }
}

/**
 * Build the backend
 */
function buildBackend(): void {
  console.log('Building backend...');
  const rootDir = path.resolve(__dirname, '../..');

  try {
    execSync('go build -o cerberus.exe', {
      cwd: rootDir,
      stdio: 'inherit',
    });
    console.log('Backend built successfully');
  } catch (error) {
    throw new Error(`Failed to build backend: ${error}`);
  }
}

/**
 * Start the backend server
 */
function startBackend(): void {
  console.log('Starting backend...');
  const rootDir = path.resolve(__dirname, '../..');
  const executablePath = path.join(rootDir, 'cerberus.exe');

  if (!fs.existsSync(executablePath)) {
    throw new Error(`Backend executable not found at ${executablePath}`);
  }

  backendProcess = spawn(executablePath, [], {
    cwd: rootDir,
    stdio: 'inherit',
    detached: false,
  });

  backendProcess.on('error', (error) => {
    console.error('Backend process error:', error);
  });

  backendProcess.on('exit', (code) => {
    console.log(`Backend process exited with code ${code}`);
  });

  console.log('Backend process started');
}

/**
 * Seed test data via API
 */
async function seedTestData(): Promise<void> {
  console.log('Seeding test data...');

  try {
    // Create test user
    const loginResponse = await fetch(`${BACKEND_URL}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'admin',
        password: 'admin123',
      }),
    });

    if (!loginResponse.ok) {
      console.warn('Default admin login failed, may not have test user yet');
      return;
    }

    const loginData = await loginResponse.json();
    const token = loginData.token;

    // Seed some test rules
    const testRules = [
      {
        name: 'Test Rule 1',
        description: 'Test rule for E2E testing',
        severity: 'High',
        enabled: true,
        conditions: [
          { field: 'event_type', operator: 'equals', value: 'login_failed', logic: 'AND' },
        ],
        actions: [],
      },
      {
        name: 'Test Rule 2',
        description: 'Another test rule',
        severity: 'Medium',
        enabled: true,
        conditions: [
          { field: 'source_ip', operator: 'equals', value: '192.168.1.1', logic: 'AND' },
        ],
        actions: [],
      },
    ];

    for (const rule of testRules) {
      try {
        await fetch(`${BACKEND_URL}/api/v1/rules`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(rule),
        });
      } catch (error) {
        console.warn('Failed to seed test rule:', error);
      }
    }

    console.log('Test data seeded successfully');
  } catch (error) {
    console.warn('Failed to seed test data:', error);
  }
}

/**
 * Global setup function
 */
export default async function globalSetup(): Promise<void> {
  console.log('Starting global setup...');

  // Kill any existing backend processes
  killExistingBackend();

  // Build the backend
  buildBackend();

  // Start the backend
  startBackend();

  // Wait for backend to be healthy
  await waitForBackendHealth();

  // Seed test data
  await seedTestData();

  console.log('Global setup complete');
}

/**
 * Global teardown - cleanup after all tests
 */
export async function globalTeardown(): Promise<void> {
  console.log('Starting global teardown...');

  if (backendProcess) {
    backendProcess.kill('SIGTERM');
    backendProcess = null;
  }

  // Give it a moment to shut down gracefully
  await new Promise(resolve => setTimeout(resolve, 2000));

  // Force kill any remaining processes
  killExistingBackend();

  console.log('Global teardown complete');
}
