import { render, screen } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { Table } from './Table';

interface TestRecord {
  id: number;
  name: string;
}

describe('Table', () => {
  const columns = [
    { accessor: 'id', title: 'ID' },
    { accessor: 'name', title: 'Name' },
  ];
  const records: TestRecord[] = [
    { id: 1, name: 'Test 1' },
    { id: 2, name: 'Test 2' },
  ];

  it('renders table with records', () => {
    render(<MantineProvider><Table records={records} columns={columns} height="200px" /></MantineProvider>);
    expect(screen.getByRole('table')).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(3); // header + 2 data rows
  });
});