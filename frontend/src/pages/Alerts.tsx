import { useEffect, useState, useMemo, useCallback } from 'react';
import { Title, TextInput, Select, Text, Badge, Button, Group, ActionIcon } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { Table } from '../components/Table';
import { Modal } from '../components/Modal';
import { Loading } from '../components/Loading';
import { Card } from '../components/Card';
import type { Alert } from '../types';
import { getAlerts, acknowledgeAlert, dismissAlert } from '../services/api';
import { SEVERITY_OPTIONS } from '../constants';
import { getSeverityColor, escapeHtml } from '../utils';
import { IconEye, IconCheck, IconX } from '@tabler/icons-react';

export const Alerts = () => {
     const [alerts, setAlerts] = useState<Alert[]>([]);
     const [loading, setLoading] = useState(true);
     const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
    const [search, setSearch] = useState('');
    const [severityFilter, setSeverityFilter] = useState<string | null>(null);
    const [selectedAlerts, setSelectedAlerts] = useState<string[]>([]);

   useEffect(() => {
     const fetchAlerts = async () => {
        try {
          const data = await getAlerts();
          setAlerts(data);
          setLoading(false);
        } catch (error) {
          console.error('Failed to load alerts:', error);
          notifications.show({
            title: 'Error',
            message: 'Failed to load alerts',
            color: 'red',
          });
          setLoading(false);
        }
     };
     fetchAlerts();
   }, []);

   const handleAcknowledge = async (alertId: string) => {
      try {
        await acknowledgeAlert(alertId);
        setAlerts(prev => prev.map(alert => alert.alert_id === alertId ? { ...alert, status: 'Acknowledged' } : alert));
        notifications.show({
          title: 'Success',
          message: 'Alert acknowledged',
          color: 'green',
        });
      } catch (error) {
        console.error('Failed to acknowledge alert:', error);
        setAlerts(prev => prev.map(alert => alert.alert_id === alertId ? { ...alert, status: 'New' } : alert));
        notifications.show({
          title: 'Error',
          message: 'Failed to acknowledge alert',
          color: 'red',
        });
      }
   };

   const handleDismiss = async (alertId: string) => {
      try {
        await dismissAlert(alertId);
        setAlerts(prev => prev.map(alert => alert.alert_id === alertId ? { ...alert, status: 'Dismissed' } : alert));
        notifications.show({
          title: 'Success',
          message: 'Alert dismissed',
          color: 'green',
        });
      } catch (error) {
        console.error('Failed to dismiss alert:', error);
        setAlerts(prev => prev.map(alert => alert.alert_id === alertId ? { ...alert, status: 'New' } : alert));
        notifications.show({
          title: 'Error',
          message: 'Failed to dismiss alert',
          color: 'red',
        });
      }
   };

   const filteredAlerts = useMemo(() => {
     let filtered = alerts;
     if (search) {
       filtered = filtered.filter(alert =>
         alert.event.event_type.toLowerCase().includes(search.toLowerCase()) ||
         alert.event.raw_data.toLowerCase().includes(search.toLowerCase())
       );
     }
     if (severityFilter) {
       filtered = filtered.filter(alert => alert.severity === severityFilter);
     }
     return filtered;
   }, [alerts, search, severityFilter]);

  const handleBulkAcknowledge = useCallback(async (alertIds: string[]) => {
    try {
      await Promise.all(alertIds.map(id => acknowledgeAlert(id)));
      setAlerts(prev => prev.map(alert =>
        alertIds.includes(alert.alert_id)
          ? { ...alert, status: 'Acknowledged' }
          : alert
      ));
      setSelectedAlerts([]);
      notifications.show({
        title: 'Success',
        message: `Acknowledged ${alertIds.length} alert${alertIds.length !== 1 ? 's' : ''}`,
        color: 'green',
      });
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to acknowledge some alerts',
        color: 'red',
      });
    }
  }, []);



  const handleBulkActions = useCallback(async (alertIds: string[]) => {
    // This could be enhanced with a bulk action modal
    await handleBulkAcknowledge(alertIds);
  }, [handleBulkAcknowledge]);

  const handleExport = useCallback((format: 'csv' | 'json') => {
    const dataToExport = selectedAlerts.length > 0
      ? alerts.filter(alert => selectedAlerts.includes(alert.alert_id))
      : alerts;

    if (format === 'csv') {
      const csvContent = [
        ['Alert ID', 'Rule ID', 'Timestamp', 'Severity', 'Status', 'Jira Ticket'],
        ...dataToExport.map(alert => [
          alert.alert_id,
          alert.rule_id,
          alert.timestamp,
          alert.severity,
          alert.status,
          alert.jira_ticket_id || ''
        ])
      ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'alerts.csv';
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const jsonContent = JSON.stringify(dataToExport, null, 2);
      const blob = new Blob([jsonContent], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'alerts.json';
      a.click();
      URL.revokeObjectURL(url);
    }
  }, [alerts, selectedAlerts]);

   const ALERTS_COLUMNS = useMemo(() => [
     {
       accessor: 'timestamp',
       title: 'Timestamp',
       sortable: true,
       render: (alert: Alert) => new Date(alert.timestamp).toLocaleString()
     },
     { accessor: 'rule_id', title: 'Rule ID' },
     {
       accessor: 'severity',
       title: 'Severity',
       sortable: true,
       render: (alert: Alert) => (
         <Badge color={getSeverityColor(alert.severity)} variant="light">
           {alert.severity}
         </Badge>
       )
     },
     {
       accessor: 'status',
       title: 'Status',
       render: (alert: Alert) => (
         <Badge
           color={
             alert.status === 'New' ? 'red' :
             alert.status === 'Acknowledged' ? 'yellow' :
             'green'
           }
           variant="light"
         >
           {alert.status}
         </Badge>
       )
     },
     { accessor: 'jira_ticket_id', title: 'Jira Ticket' },
      {
        accessor: 'actions',
        title: 'Actions',
        render: (alert: Alert) => (
        <Group gap="xs">
          <ActionIcon
            variant="light"
            color="blue"
            onClick={() => setSelectedAlert(alert)}
            title="View Details"
          >
            <IconEye size={16} />
          </ActionIcon>
          {alert.status === 'New' && (
            <>
              <ActionIcon
                variant="light"
                color="green"
                onClick={() => handleAcknowledge(alert.alert_id)}
                title="Acknowledge"
              >
                <IconCheck size={16} />
              </ActionIcon>
              <ActionIcon
                variant="light"
                color="red"
                onClick={() => handleDismiss(alert.alert_id)}
                title="Dismiss"
              >
                <IconX size={16} />
              </ActionIcon>
            </>
          )}
        </Group>
      ) },
   ], [handleAcknowledge, handleDismiss]);

  if (loading) {
    return <Loading type="table" />;
  }

  return (
    <>
      <Group justify="space-between" mb="lg">
        <div>
          <Title order={2} className="text-text-primary">Alerts</Title>
          <Text size="sm" className="text-text-secondary">Monitor and manage security alerts</Text>
        </div>
        <Group>
          <Badge color="red" variant="light">
            {filteredAlerts.filter(a => a.status === 'New').length} New
          </Badge>
          <Badge color="yellow" variant="light">
            {filteredAlerts.filter(a => a.status === 'Acknowledged').length} Acknowledged
          </Badge>
        </Group>
      </Group>

      <Card className="mb-6">
        <Group grow>
          <TextInput
            placeholder="Search alerts..."
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
        records={filteredAlerts}
        columns={ALERTS_COLUMNS}
        selectable
        getRecordId={(alert) => alert.alert_id}
        onExport={handleExport}
        onBulkEdit={handleBulkActions}
      />

      <Modal
        opened={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title="Alert Details"
        size="xl"
      >
        {selectedAlert && (
          <div className="space-y-4">
            <Card title="Alert Information">
              <Group grow>
                <div>
                  <Text size="sm" className="text-text-secondary">Alert ID</Text>
                  <Text className="font-mono text-sm">{selectedAlert.alert_id}</Text>
                </div>
                <div>
                  <Text size="sm" className="text-text-secondary">Rule ID</Text>
                  <Text className="font-mono text-sm">{selectedAlert.rule_id}</Text>
                </div>
                <div>
                  <Text size="sm" className="text-text-secondary">Severity</Text>
                  <Badge color={getSeverityColor(selectedAlert.severity)} variant="light">
                    {selectedAlert.severity}
                  </Badge>
                </div>
                <div>
                  <Text size="sm" className="text-text-secondary">Status</Text>
                  <Badge
                    color={
                      selectedAlert.status === 'New' ? 'red' :
                      selectedAlert.status === 'Acknowledged' ? 'yellow' :
                      'green'
                    }
                    variant="light"
                  >
                    {selectedAlert.status}
                  </Badge>
                </div>
              </Group>
              <Group grow className="mt-4">
                <div>
                  <Text size="sm" className="text-text-secondary">Timestamp</Text>
                  <Text>{new Date(selectedAlert.timestamp).toLocaleString()}</Text>
                </div>
                <div>
                  <Text size="sm" className="text-text-secondary">Jira Ticket</Text>
                  <Text>{selectedAlert.jira_ticket_id || 'N/A'}</Text>
                </div>
              </Group>
            </Card>

            <Card title="Event Details">
              <Group grow className="mb-4">
                <div>
                  <Text size="sm" className="text-text-secondary">Event ID</Text>
                  <Text className="font-mono text-sm">{selectedAlert.event.event_id}</Text>
                </div>
                <div>
                  <Text size="sm" className="text-text-secondary">Event Type</Text>
                  <Text>{selectedAlert.event.event_type}</Text>
                </div>
                <div>
                  <Text size="sm" className="text-text-secondary">Source IP</Text>
                  <Text className="font-mono text-sm">{selectedAlert.event.source_ip || 'N/A'}</Text>
                </div>
              </Group>
              <div>
                <Text size="sm" className="text-text-secondary mb-2">Raw Event Data</Text>
                <div className="bg-background border border-border rounded-md p-3 max-h-64 overflow-auto">
                  <pre className="text-xs font-mono text-text-primary whitespace-pre-wrap">
                    {escapeHtml(selectedAlert.event.raw_data)}
                  </pre>
                </div>
              </div>
            </Card>

            {selectedAlert.status === 'New' && (
              <Group justify="flex-end">
                <Button
                  variant="outline"
                  color="red"
                  onClick={() => {
                    handleDismiss(selectedAlert.alert_id);
                    setSelectedAlert(null);
                  }}
                >
                  Dismiss Alert
                </Button>
                <Button
                  onClick={() => {
                    handleAcknowledge(selectedAlert.alert_id);
                    setSelectedAlert(null);
                  }}
                >
                  Acknowledge Alert
                </Button>
              </Group>
            )}
          </div>
        )}
      </Modal>
    </>
  );
};