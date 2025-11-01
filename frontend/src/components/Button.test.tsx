import { render, screen } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { Button } from './Button';

describe('Button', () => {
  it('renders children correctly', () => {
    render(<MantineProvider><Button>Click me</Button></MantineProvider>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
  });

  it('passes props to MantineButton', () => {
    render(<MantineProvider><Button variant="filled" color="blue">Test</Button></MantineProvider>);
    const button = screen.getByText('Test');
    expect(button).toBeInTheDocument();
  });
});