import { useEffect, useState, useMemo, useCallback } from 'react';
import { Title, Button, Group, Switch, Text, TextInput, Textarea, Select, NumberInput, Checkbox, Badge } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconEdit, IconTrash, IconPlus } from '@tabler/icons-react';
import { Table } from '../components/Table';
import { Modal } from '../components/Modal';
import { Loading } from '../components/Loading';
import type { CorrelationRule } from '../types';
import { notifications } from '@mantine/notifications';
import { getCorrelationRules, deleteCorrelationRule, updateCorrelationRule, createCorrelationRule } from '../services/api';
import { SEVERITY_OPTIONS, ACTION_TYPES, NANOSECONDS_PER_SECOND, DEFAULT_RULE_VERSION } from '../constants';

type CorrelationRuleFormValues = {
  name: string;
  description: string;
  severity: string;
  enabled: boolean;
  window: number;
  sequence: string[];
  actionType: string;
  actionConfig: string;
};

const getCorrelationRulesColumns = (handleToggleEnabled: (rule: CorrelationRule) => void, openEditModal: (rule: CorrelationRule) => void, setRuleToDelete: (rule: CorrelationRule) => void, setDeleteModalOpen: (open: boolean) => void) => [
   { accessor: 'name', title: 'Name', sortable: true },
   { accessor: 'description', title: 'Description' },
   {
     accessor: 'severity',
     title: 'Severity',
     sortable: true,
     render: (rule: CorrelationRule) => (
       <Badge
         color={
           rule.severity === 'critical' ? 'red' :
           rule.severity === 'high' ? 'orange' :
           rule.severity === 'medium' ? 'yellow' :
           'green'
         }
         variant="light"
       >
         {rule.severity}
       </Badge>
     )
   },
   {
     accessor: 'enabled',
     title: 'Status',
     render: (rule: CorrelationRule) => (
       <Switch
         checked={rule.enabled ?? false}
         onChange={() => handleToggleEnabled(rule)}
         size="sm"
       />
     )
   },
   {
     accessor: 'sequence',
     title: 'Sequence',
     render: (rule: CorrelationRule) => (
       <div className="max-w-xs">
         <Text size="sm" className="font-mono">
           {rule.sequence?.join(' → ') || 'N/A'}
         </Text>
       </div>
     )
   },
   {
     accessor: 'actions',
     title: 'Actions',
     render: (rule: CorrelationRule) => (
       <Group gap="xs">
         <Button
           size="xs"
           variant="subtle"
           leftSection={<IconEdit size={14} />}
           onClick={() => openEditModal(rule)}
         >
           Edit
         </Button>
         <Button
           size="xs"
           variant="subtle"
           color="red"
           leftSection={<IconTrash size={14} />}
           onClick={() => { setRuleToDelete(rule); setDeleteModalOpen(true); }}
         >
           Delete
         </Button>
       </Group>
     )
   },
];

export const CorrelationRules = () => {
   const [rules, setRules] = useState<CorrelationRule[]>([]);
   const [loading, setLoading] = useState(true);
   const [deleteModalOpen, setDeleteModalOpen] = useState(false);
   const [ruleToDelete, setRuleToDelete] = useState<CorrelationRule | null>(null);
   const [ruleModalOpen, setRuleModalOpen] = useState(false);
   const [editingRule, setEditingRule] = useState<CorrelationRule | null>(null);
   const [selectedRules, setSelectedRules] = useState<string[]>([]);

  const form = useForm<CorrelationRuleFormValues>({
    initialValues: {
      name: '',
      description: '',
      severity: 'medium',
      enabled: true,
       window: 300, // 5 minutes in seconds
      sequence: [],
      actionType: 'webhook',
      actionConfig: '',
    },
    validate: {
      name: (value) => value.length < 1 ? 'Name is required' : null,
      sequence: (value) => !value || value.length === 0 || value.some(s => s.trim() === '') ? 'At least one non-empty event type required' : null,
      actionConfig: (value) => {
        try {
          JSON.parse(value);
          return null;
        } catch {
          return 'Action config must be valid JSON';
        }
      },
    },
  });

  useEffect(() => {
    const fetchRules = async () => {
      try {
        const data = await getCorrelationRules();
        setRules(data);
      } catch (error) {
        console.error('Error loading correlation rules:', error);
        notifications.show({
          title: 'Error',
          message: 'Failed to load correlation rules',
          color: 'red',
        });
      } finally {
        setLoading(false);
      }
    };
    fetchRules();
  }, []);

   const handleToggleEnabled = useCallback(async (rule: CorrelationRule) => {
      try {
        await updateCorrelationRule(rule.id, { enabled: !rule.enabled });
        setRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r));
        notifications.show({
          title: 'Success',
          message: `Rule ${!rule.enabled ? 'enabled' : 'disabled'}`,
           color: 'green',
        });
       } catch (error) {
         console.error('Error updating correlation rule enabled status:', error);
         setRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: rule.enabled } : r));
         notifications.show({
           title: 'Error',
           message: 'Failed to update rule',
           color: 'red',
        });
      }
   }, []);

   const openEditModal = useCallback((rule: CorrelationRule) => {
     setEditingRule(rule);
     form.setValues({
       name: rule.name,
       description: rule.description,
       severity: rule.severity,
       enabled: rule.enabled,
        window: rule.window / NANOSECONDS_PER_SECOND,
       sequence: rule.sequence,
       actionType: rule.actions[0]?.type || 'webhook',
       actionConfig: JSON.stringify(rule.actions[0]?.config || {}, null, 2),
     });
     setRuleModalOpen(true);
   }, [form]);

   const handleSubmit = async (values: typeof form.values) => {
     const ruleData = {
       name: values.name,
       description: values.description,
       severity: values.severity,
       enabled: values.enabled,
        window: values.window * NANOSECONDS_PER_SECOND,
       sequence: values.sequence.filter(s => s !== ''),
       actions: [{
         type: values.actionType,
         config: (() => {
           try {
             return JSON.parse(values.actionConfig || '{}');
           } catch {
             throw new Error('Invalid JSON in action config');
           }
         })(),
       }],
     };

      let newRule: CorrelationRule | undefined;
      try {
        if (editingRule) {
          const updatedRule = await updateCorrelationRule(editingRule.id, ruleData);
          setRules(prev => prev.map(r => r.id === editingRule.id ? updatedRule : r));
          notifications.show({
            title: 'Success',
            message: 'Correlation rule updated',
            color: 'green',
          });
        } else {
           newRule = await createCorrelationRule({ ...ruleData, version: DEFAULT_RULE_VERSION });
          setRules(prev => [...prev, newRule!]);
          notifications.show({
            title: 'Success',
            message: 'Correlation rule created',
            color: 'green',
          });
        }

         setRuleModalOpen(false);
         form.reset();
         setEditingRule(null);
         } catch (error) {
           console.error('Error saving correlation rule:', error);
           if (editingRule) {
             // Revert edit
             setRules(prev => prev.map(r => r.id === editingRule.id ? editingRule : r));
           }
          notifications.show({
           title: 'Error',
           message: 'Failed to save correlation rule',
           color: 'red',
         });
       }
   };

   const handleDelete = async () => {
     if (!ruleToDelete) return;

      try {
        await deleteCorrelationRule(ruleToDelete.id);
        setRules(prev => prev.filter(r => r.id !== ruleToDelete.id));
        notifications.show({
          title: 'Success',
          message: 'Correlation rule deleted',
          color: 'green',
        });
         setDeleteModalOpen(false);
         setRuleToDelete(null);
       } catch (error) {
         console.error('Error deleting correlation rule:', error);
         setRules(prev => [...prev, ruleToDelete]);
         notifications.show({
           title: 'Error',
           message: 'Failed to delete correlation rule',
           color: 'red',
        });
      }
   };

  const handleExport = useCallback((format: 'csv' | 'json') => {
    const dataToExport = selectedRules.length > 0
      ? rules.filter(rule => selectedRules.includes(rule.id))
      : rules;

    if (format === 'csv') {
      const csvContent = [
        ['ID', 'Name', 'Description', 'Severity', 'Enabled', 'Sequence', 'Window'],
        ...dataToExport.map(rule => [
          rule.id,
          rule.name,
          rule.description,
          rule.severity,
          rule.enabled ? 'Yes' : 'No',
          rule.sequence?.join(';') || '',
          (rule.window / NANOSECONDS_PER_SECOND).toString()
        ])
      ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'correlation-rules.csv';
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const jsonContent = JSON.stringify(dataToExport, null, 2);
      const blob = new Blob([jsonContent], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'correlation-rules.json';
      a.click();
      URL.revokeObjectURL(url);
    }
  }, [rules, selectedRules]);

  const handleBulkDelete = useCallback(async (ruleIds: string[]) => {
    try {
      await Promise.all(ruleIds.map(id => deleteCorrelationRule(id)));
      setRules(prev => prev.filter(rule => !ruleIds.includes(rule.id)));
      setSelectedRules([]);
      notifications.show({
        title: 'Success',
        message: `Deleted ${ruleIds.length} correlation rule${ruleIds.length !== 1 ? 's' : ''}`,
        color: 'green',
      });
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to delete some correlation rules',
        color: 'red',
      });
    }
  }, []);

    const columns = useMemo(() => getCorrelationRulesColumns(handleToggleEnabled, openEditModal, setRuleToDelete, setDeleteModalOpen), [handleToggleEnabled, openEditModal]);

    if (loading) {
      return <Loading type="table" />;
    }

    return (
      <>
        <Group justify="space-between" mb="lg">
          <div>
            <Title order={2} className="text-text-primary">Correlation Rules</Title>
            <Text size="sm" className="text-text-secondary">Advanced pattern detection across multiple events</Text>
          </div>
          <Button leftSection={<IconPlus size="1rem" />} onClick={() => setRuleModalOpen(true)}>
            Add Correlation Rule
          </Button>
        </Group>

        <Table
          records={rules}
          columns={columns}
          selectable
          getRecordId={(rule) => rule.id}
          onExport={handleExport}
          onBulkDelete={handleBulkDelete}
        />

        <Modal
          opened={deleteModalOpen}
          onClose={() => { setDeleteModalOpen(false); setRuleToDelete(null); }}
          title="Delete Correlation Rule"
          confirmLabel="Delete"
          cancelLabel="Cancel"
          onConfirm={handleDelete}
          showFooter
        >
          <Text>Are you sure you want to delete the correlation rule "{ruleToDelete?.name}"?</Text>
          <Text size="sm" className="text-text-secondary mt-2">
            This action cannot be undone.
          </Text>
        </Modal>

        <Modal
          opened={ruleModalOpen}
          onClose={() => { setRuleModalOpen(false); form.reset(); setEditingRule(null); }}
          title={editingRule ? 'Edit Correlation Rule' : 'Create Correlation Rule'}
          size="xl"
          showFooter={false}
        >
          <form onSubmit={form.onSubmit(handleSubmit)}>
            <TextInput
              label="Name"
              placeholder="Rule name"
              {...form.getInputProps('name')}
              mb="md"
            />
            <Textarea
              label="Description"
              placeholder="Rule description"
              {...form.getInputProps('description')}
              mb="md"
            />
            <Group grow mb="md">
              <Select
                label="Severity"
                data={SEVERITY_OPTIONS}
                {...form.getInputProps('severity')}
              />
              <div className="flex items-end">
                <Checkbox
                  label="Enabled"
                  {...form.getInputProps('enabled', { type: 'checkbox' })}
                />
              </div>
            </Group>

            <NumberInput
              label="Time Window (seconds)"
              description="Maximum time span for event correlation"
              {...form.getInputProps('window')}
              mb="md"
            />

            <div className="mb-4">
              <Text size="sm" fw={500} mb="xs" className="text-text-primary">Event Sequence</Text>
              <TextInput
                placeholder="login,failed_login,success"
                value={form.values.sequence.join(', ')}
                onChange={(event) => form.setFieldValue('sequence', event.currentTarget.value.split(',').map(s => s.trim()).filter(s => s.length > 0))}
                description="Comma-separated list of event types in sequence"
              />
              {form.values.sequence.length > 0 && (
                <div className="mt-2 p-2 bg-background border border-border rounded">
                  <Text size="sm" className="text-text-secondary">Sequence: </Text>
                  <Text size="sm" className="font-mono">
                    {form.values.sequence.join(' → ')}
                  </Text>
                </div>
              )}
            </div>

            <div className="mb-6">
              <Text size="sm" fw={500} mb="xs" className="text-text-primary">Action</Text>
              <div className="border border-border rounded-md p-4 bg-background">
                <Select
                  label="Action Type"
                  data={ACTION_TYPES}
                  {...form.getInputProps('actionType')}
                  mb="sm"
                />
                <Textarea
                  label="Action Config (JSON)"
                  placeholder='{"url": "https://example.com/webhook"}'
                  {...form.getInputProps('actionConfig')}
                  minRows={3}
                  className="font-mono text-sm"
                />
              </div>
            </div>

            <Group justify="flex-end">
              <Button variant="default" onClick={() => { setRuleModalOpen(false); form.reset(); setEditingRule(null); }}>
                Cancel
              </Button>
              <Button type="submit">
                {editingRule ? 'Update' : 'Create'} Rule
              </Button>
            </Group>
          </form>
        </Modal>
      </>
    );
};