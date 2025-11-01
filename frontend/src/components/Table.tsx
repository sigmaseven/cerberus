import { DataTable, type DataTableColumn } from 'mantine-datatable';
import { Button, Group, Checkbox, Text, Menu, Pagination } from '@mantine/core';
import { IconDownload, IconTrash, IconEdit } from '@tabler/icons-react';
import { useState, useMemo } from 'react';

interface TableProps<T> {
  records: T[];
  columns: DataTableColumn<T>[];
  loading?: boolean;
  onExport?: (format: 'csv' | 'json') => void;
  onBulkDelete?: (selectedIds: string[]) => void;
  onBulkEdit?: (selectedIds: string[]) => void;
  selectable?: boolean;
  getRecordId?: (record: T) => string;
  totalRecords?: number;
  recordsPerPage?: number;
  page?: number;
  onPageChange?: (page: number) => void;
  [key: string]: unknown;
}

export const Table = <T,>({
  records,
  columns,
  loading = false,
  onExport,
  onBulkDelete,
  onBulkEdit,
  selectable = false,
  getRecordId = (record: any) => record.id || record._id,
  totalRecords,
  recordsPerPage = 25,
  page = 1,
  onPageChange,
  ...props
}: TableProps<T>) => {
  const [selectedRecords, setSelectedRecords] = useState<string[]>([]);

  const enhancedColumns = useMemo(() => {
    let cols = [...columns];

    if (selectable) {
      cols = [
        {
          accessor: 'select',
          title: (
            <Checkbox
              checked={selectedRecords.length === records.length && records.length > 0}
              indeterminate={selectedRecords.length > 0 && selectedRecords.length < records.length}
              onChange={(event) => {
                if (event.currentTarget.checked) {
                  setSelectedRecords(records.map(getRecordId));
                } else {
                  setSelectedRecords([]);
                }
              }}
            />
          ),
          render: (record: T) => (
            <Checkbox
              checked={selectedRecords.includes(getRecordId(record))}
              onChange={(event) => {
                const id = getRecordId(record);
                if (event.currentTarget.checked) {
                  setSelectedRecords(prev => [...prev, id]);
                } else {
                  setSelectedRecords(prev => prev.filter(selectedId => selectedId !== id));
                }
              }}
            />
          ),
          width: 50,
        },
        ...cols,
      ];
    }

    return cols;
  }, [columns, selectable, selectedRecords, records, getRecordId]);

  const handleExport = (format: 'csv' | 'json') => {
    onExport?.(format);
  };

  const handleBulkDelete = () => {
    onBulkDelete?.(selectedRecords);
    setSelectedRecords([]);
  };

  const handleBulkEdit = () => {
    onBulkEdit?.(selectedRecords);
    setSelectedRecords([]);
  };

  const totalPages = totalRecords ? Math.ceil(totalRecords / recordsPerPage) : 1;

  return (
    <div className="space-y-4">
      {/* Table Actions */}
      <Group justify="space-between">
        <div>
          {selectedRecords.length > 0 && (
            <Text size="sm" className="text-text-secondary">
              {selectedRecords.length} item{selectedRecords.length !== 1 ? 's' : ''} selected
            </Text>
          )}
        </div>
        <Group>
          {selectedRecords.length > 0 && (
            <Group gap="xs">
              {onBulkEdit && (
                <Button size="xs" variant="outline" leftSection={<IconEdit size={14} />} onClick={handleBulkEdit}>
                  Edit Selected
                </Button>
              )}
              {onBulkDelete && (
                <Button size="xs" color="red" variant="outline" leftSection={<IconTrash size={14} />} onClick={handleBulkDelete}>
                  Delete Selected
                </Button>
              )}
            </Group>
          )}
          {onExport && (
            <Menu shadow="md" width={120}>
              <Menu.Target>
                <Button size="xs" variant="outline" leftSection={<IconDownload size={14} />}>
                  Export
                </Button>
              </Menu.Target>
              <Menu.Dropdown>
                <Menu.Item onClick={() => handleExport('csv')}>Export as CSV</Menu.Item>
                <Menu.Item onClick={() => handleExport('json')}>Export as JSON</Menu.Item>
              </Menu.Dropdown>
            </Menu>
          )}
        </Group>
      </Group>

      {/* Data Table */}
      <DataTable
        records={records}
        columns={enhancedColumns}
        noRecordsText="No records found"
        {...props}
      />

      {/* Pagination */}
      {totalRecords && totalRecords > recordsPerPage && (
        <Group justify="center">
          <Pagination
            total={totalPages}
            value={page}
            onChange={onPageChange}
            size="sm"
            classNames={{
              control: 'bg-background-secondary border-border hover:bg-background',
            }}
          />
          <Text size="sm" className="text-text-secondary">
            {Math.min((page - 1) * recordsPerPage + 1, totalRecords)} - {Math.min(page * recordsPerPage, totalRecords)} of {totalRecords}
          </Text>
        </Group>
      )}
    </div>
  );
};