import { render } from '@testing-library/react';
import { vi } from 'vitest';
import App from './App';

// Mock all the components to avoid MUI issues
vi.mock('@mui/material', () => ({
  ThemeProvider: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  CssBaseline: () => null,
  Box: ({ children }: { children: React.ReactNode }) => <div>{children}</div>}));

vi.mock('@tanstack/react-query', () => ({
  QueryClient: vi.fn(() => ({})),
  QueryClientProvider: ({ children }: { children: React.ReactNode }) => <div>{children}</div>}));

vi.mock('react-router-dom', () => ({
  BrowserRouter: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Routes: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Route: () => null,
  Navigate: () => null}));

vi.mock('../stores/auth', () => ({
  useAuthStore: vi.fn(() => ({}))}));

vi.mock('../theme', () => ({
  theme: {}}));

vi.mock('../components/layout/Layout', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>}));

vi.mock('./Login', () => ({
  default: () => <div>Login</div>}));

vi.mock('./Dashboard', () => ({
  default: () => <div>Dashboard</div>}));

vi.mock('./Alerts', () => ({
  default: () => <div>Alerts</div>}));

vi.mock('./Events', () => ({
  default: () => <div>Events</div>}));

vi.mock('./Rules', () => ({
  default: () => <div>Rules</div>}));

vi.mock('./CorrelationRules', () => ({
  default: () => <div>CorrelationRules</div>}));

vi.mock('./Actions', () => ({
  default: () => <div>Actions</div>}));

vi.mock('./Listeners', () => ({
  default: () => <div>Listeners</div>}));

describe('App', () => {
  it('renders without crashing', () => {
    expect(() => render(<App />)).not.toThrow();
  });
});