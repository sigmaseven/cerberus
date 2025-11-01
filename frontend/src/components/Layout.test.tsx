import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { MantineProvider } from '@mantine/core';
import { Layout } from './Layout';

describe('Layout', () => {
  it('renders header with title', () => {
    render(
      <MantineProvider>
        <MemoryRouter>
          <Layout />
        </MemoryRouter>
      </MantineProvider>
    );
    expect(screen.getByText('Cerberus SIEM')).toBeInTheDocument();
  });

  it('renders navigation links', () => {
    render(
      <MantineProvider>
        <MemoryRouter>
          <Layout />
        </MemoryRouter>
      </MantineProvider>
    );
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Events')).toBeInTheDocument();
    expect(screen.getByText('Alerts')).toBeInTheDocument();
  });
});