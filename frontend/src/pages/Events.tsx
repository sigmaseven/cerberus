import { useState, useMemo } from 'react';
import { Title, TextInput, Select, Text, Group, Badge, ActionIcon } from '@mantine/core';
import { IconEye } from '@tabler/icons-react';
import { Table } from '../components/Table';
import { Modal } from '../components/Modal';
import { Loading } from '../components/Loading';
import { Card } from '../components/Card';
import type { Event } from '../types';
import { getEvents } from '../services/api';
import { SEVERITY_OPTIONS } from '../constants';
import { useFetch } from '../hooks/useFetch';
import { escapeHtml, getSeverityColor } from '../utils';

const getEventsColumns = (setSelectedEvent: (event: Event) => void) => [
   {
     accessor: 'timestamp',
     title: 'Timestamp',
     sortable: true,
     render: (event: Event) => new Date(event.timestamp).toLocaleString()
   },
   { accessor: 'event_type', title: 'Type', sortable: true },
   {
     accessor: 'severity',
     title: 'Severity',
     sortable: true,
     render: (event: Event) => (
       <Badge color={getSeverityColor(event.severity)} variant="light">
         {event.severity}
       </Badge>
     )
   },
   { accessor: 'source_ip', title: 'Source IP' },
   {
     accessor: 'actions',
     title: 'Actions',
     render: (event: Event) => (
       <ActionIcon
         variant="light"
         color="blue"
         onClick={() => setSelectedEvent(event)}
         title="View Details"
       >
         <IconEye size={16} />
       </ActionIcon>
     )
   },
];

export const Events = () => {
    const { data: events, loading } = useFetch(() => getEvents(), []);
    const [search, setSearch] = useState('');
    const [severityFilter, setSeverityFilter] = useState<string | null>(null);
    const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);

   const filteredEvents = useMemo(() => {
     if (!events) return [];
     let filtered = events;
     if (search) {
       filtered = filtered.filter(event =>
         event.event_type.toLowerCase().includes(search.toLowerCase()) ||
         event.raw_data.toLowerCase().includes(search.toLowerCase())
       );
     }
     if (severityFilter) {
       filtered = filtered.filter(event => event.severity === severityFilter);
     }
     return filtered;
    }, [events, search, severityFilter]);

  const handleExport = (format: 'csv' | 'json') => {
    const dataToExport = filteredEvents;

    if (format === 'csv') {
      const csvContent = [
        ['Event ID', 'Timestamp', 'Type', 'Severity', 'Source IP'],
        ...dataToExport.map(event => [
          event.event_id,
          event.timestamp,
          event.event_type,
          event.severity,
          event.source_ip || ''
        ])
      ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'events.csv';
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const jsonContent = JSON.stringify(dataToExport, null, 2);
      const blob = new Blob([jsonContent], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'events.json';
      a.click();
      URL.revokeObjectURL(url);
    }
  };

    const columns = useMemo(() => getEventsColumns(setSelectedEvent), []);

    if (loading) {
      return <Loading type="table" />;
    }

    return (
      <>
        <Group justify="space-between" mb="lg">
          <div>
            <Title order={2} className="text-text-primary">Events</Title>
            <Text size="sm" className="text-text-secondary">Browse and analyze security events</Text>
          </div>
          <Group>
            <Badge color="blue" variant="light">
              {filteredEvents.length} Events
            </Badge>
          </Group>
        </Group>

        <Card className="mb-6">
          <Group grow>
            <TextInput
              placeholder="Search events..."
              value={search}
              onChange={(event) => setSearch(event.currentTarget.value)}
              leftSection={<IconEye size={16} />}
            />
            <Select
              placeholder="Filter by severity"
              data={SEVERITY_OPTIONS}
              value={severityFilter}
              onChange={setSeverityFilter}
              clearable
            />
          </Group>
        </Card>

        <Table
          records={filteredEvents}
          columns={columns}
          selectable
          getRecordId={(event) => event.event_id}
          onExport={handleExport}
        />

        <Modal
          opened={!!selectedEvent}
          onClose={() => setSelectedEvent(null)}
          title="Event Details"
          size="xl"
        >
          {selectedEvent && (
            <div className="space-y-4">
              <Card title="Event Information">
                <Group grow>
                  <div>
                    <Text size="sm" className="text-text-secondary">Event ID</Text>
                    <Text className="font-mono text-sm">{selectedEvent.event_id}</Text>
                  </div>
                  <div>
                    <Text size="sm" className="text-text-secondary">Event Type</Text>
                    <Text>{selectedEvent.event_type}</Text>
                  </div>
                  <div>
                    <Text size="sm" className="text-text-secondary">Severity</Text>
                    <Badge color={getSeverityColor(selectedEvent.severity)} variant="light">
                      {selectedEvent.severity}
                    </Badge>
                  </div>
                  <div>
                    <Text size="sm" className="text-text-secondary">Source IP</Text>
                    <Text className="font-mono text-sm">{selectedEvent.source_ip || 'N/A'}</Text>
                  </div>
                </Group>
                <div className="mt-4">
                  <Text size="sm" className="text-text-secondary">Timestamp</Text>
                  <Text>{new Date(selectedEvent.timestamp).toLocaleString()}</Text>
                </div>
              </Card>

              <Card title="Raw Event Data">
                <div className="bg-background border border-border rounded-md p-3 max-h-96 overflow-auto">
                  <pre className="text-xs font-mono text-text-primary whitespace-pre-wrap">
                    {escapeHtml(selectedEvent.raw_data)}
                  </pre>
                </div>
              </Card>

              {selectedEvent.fields && Object.keys(selectedEvent.fields).length > 0 && (
                <Card title="Parsed Fields">
                  <div className="grid grid-cols-2 gap-4">
                    {Object.entries(selectedEvent.fields).map(([key, value]) => (
                      <div key={key}>
                        <Text size="sm" className="text-text-secondary">{key}</Text>
                        <Text className="font-mono text-sm">
                          {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                        </Text>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </div>
          )}
        </Modal>
      </>
    );
 };