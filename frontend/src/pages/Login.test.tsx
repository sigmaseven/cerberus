import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import Login from './Login';

// Mock the auth store
vi.mock('../stores/auth', () => ({
  useAuthStore: vi.fn()}));

import { useAuthStore } from '../stores/auth';

// Mock MUI components to avoid EMFILE issues
vi.mock('@mui/material', () => ({
  Box: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  Typography: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  Button: ({ children, ...props }: any) => <button {...props}>{children}</button>,
  Paper: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  Container: ({ children, ...props }: any) => <div {...props}>{children}</div>}));

// Mock react-router-dom
const mockNavigate = vi.fn();
vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
  MemoryRouter: ({ children }: any) => <div>{children}</div>}));

describe('Login', () => {
  const mockLogin = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    (useAuthStore as any).mockImplementation((selector) => {
      const state = { login: mockLogin };
      return selector ? selector(state) : state;
    });
  });

  it('renders login page', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    expect(screen.getByText('Cerberus SIEM')).toBeInTheDocument();
    expect(screen.getByText('Security Information and Event Management')).toBeInTheDocument();
    expect(screen.getByText('Auto-login in progress...')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Login \(Demo\)/i })).toBeInTheDocument();
  });

  it('auto-logs in after 1 second', async () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('demo-token');
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
    }, { timeout: 1100 });
  });

  it('handles manual login click', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    const loginButton = screen.getByRole('button', { name: /Login \(Demo\)/i });
    await user.click(loginButton);

    expect(mockLogin).toHaveBeenCalledWith('demo-token');
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
  });

  it('clears timeout on unmount', () => {
    const { unmount } = render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    // Mock setTimeout and clearTimeout to verify cleanup
    const mockClearTimeout = vi.spyOn(global, 'clearTimeout');

    unmount();

    // The cleanup function should have been called
    expect(mockClearTimeout).toHaveBeenCalled();
  });
});