import { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import { Title, Button, Group, Switch, Text, TextInput, Textarea, Select, Checkbox } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconEdit, IconTrash, IconPlus } from '@tabler/icons-react';
import { Table } from '../components/Table';
import { Modal } from '../components/Modal';
import { Loading } from '../components/Loading';
import type { Rule } from '../types';
import { getRules, deleteRule, updateRule, createRule } from '../services/api';

interface EditingRule extends Rule {
  actionConfig: string;
}
import { notifications } from '@mantine/notifications';
import { SEVERITY_OPTIONS, OPERATOR_OPTIONS, ACTION_TYPES, DEFAULT_RULE_VERSION } from '../constants';

const getRulesColumns = (handleToggleEnabled: (rule: Rule) => void, openEditModal: (rule: Rule) => void, setRuleToDelete: (rule: Rule) => void, setDeleteModalOpen: (open: boolean) => void) => [
  { accessor: 'name', title: 'Name', sortable: true },
  { accessor: 'description', title: 'Description' },
  {
    accessor: 'severity',
    title: 'Severity',
    sortable: true,
    render: (rule: Rule) => (
      <span className={`px-2 py-1 rounded text-xs font-medium ${
        rule.severity === 'critical' ? 'bg-red-900/20 text-red-400' :
        rule.severity === 'high' ? 'bg-orange-900/20 text-orange-400' :
        rule.severity === 'medium' ? 'bg-yellow-900/20 text-yellow-400' :
        'bg-green-900/20 text-green-400'
      }`}>
        {rule.severity}
      </span>
    )
  },
  {
    accessor: 'enabled',
    title: 'Status',
    render: (rule: Rule) => (
      <Switch
        checked={rule.enabled ?? false}
        onChange={() => handleToggleEnabled(rule)}
        size="sm"
      />
    )
  },
  {
    accessor: 'actions',
    title: 'Actions',
    render: (rule: Rule) => (
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

export const Rules = () => {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [ruleToDelete, setRuleToDelete] = useState<Rule | null>(null);
  const [ruleModalOpen, setRuleModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<EditingRule | null>(null);
  const [selectedRules, setSelectedRules] = useState<string[]>([]);
  const mountedRef = useRef(true);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const form = useForm({
    initialValues: {
      name: '',
      description: '',
      severity: 'medium',
      enabled: true,
      conditionField: '',
      conditionOperator: 'equals',
      conditionValue: '',
      actionType: 'webhook',
      actionConfig: '{}',
    },
    validate: {
      name: (value) => (value.length < 1 ? 'Name is required' : null),
      conditionField: (value) => (value.length < 1 ? 'Condition field is required' : null),
      conditionValue: (value) => (value.length < 1 ? 'Condition value is required' : null),
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
        const data = await getRules();
        setRules(data);
      } catch {
        notifications.show({
          title: 'Error',
          message: 'Failed to load rules',
          color: 'red',
        });
      } finally {
        setLoading(false);
      }
    };
    fetchRules();
  }, []);

  useEffect(() => {
    if (editingRule) {
      form.setValues({
        name: editingRule.name,
        description: editingRule.description,
        severity: editingRule.severity,
        enabled: editingRule.enabled,
        conditionField: String(editingRule.conditions?.[0]?.field || ''),
        conditionOperator: String(editingRule.conditions?.[0]?.operator || 'equals'),
        conditionValue: typeof editingRule.conditions?.[0]?.value === 'string' ? editingRule.conditions[0].value : JSON.stringify(editingRule.conditions?.[0]?.value) ?? '',
        actionType: String(editingRule.actions?.[0]?.type || 'webhook'),
        actionConfig: editingRule.actionConfig,
      });
    }
  }, [editingRule, form]);

    const handleToggleEnabled = useCallback(async (rule: Rule) => {
      try {
        await updateRule(rule.id, { enabled: !rule.enabled });
        if (mountedRef.current) {
          setRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r));
        }
      } catch (error) {
        if (mountedRef.current) {
          setRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: rule.enabled } : r));
        }
        notifications.show({
          title: 'Error',
          message: `Failed to toggle rule: ${(error as Error).message}`,
          color: 'red',
        });
      }
    }, []);

   const handleDelete = async () => {
     if (!ruleToDelete) return;
     try {
       await deleteRule(ruleToDelete.id);
        setRules(prev => prev.filter(r => r.id !== ruleToDelete.id));
       setDeleteModalOpen(false);
       setRuleToDelete(null);
       notifications.show({
         title: 'Success',
         message: 'Rule deleted successfully',
          color: 'green',
        });
      } catch {
        setRules(prev => [...prev, ruleToDelete]);
        notifications.show({
          title: 'Error',
          message: 'Failed to delete rule',
         color: 'red',
       });
     }
   };

   const handleCreateEdit = async (values: typeof form.values) => {
     const ruleData = {
       name: values.name,
       description: values.description,
       severity: values.severity,
       enabled: values.enabled,
        conditions: [{
          field: values.conditionField,
          operator: values.conditionOperator,
          value: (() => {
            try {
              return JSON.parse(values.conditionValue);
            } catch {
              return values.conditionValue;
            }
          })(),
          logic: 'AND',
        }],
       actions: [{
         type: values.actionType,
         config: JSON.parse(values.actionConfig),
       }],
      };

      let newRule: Rule | undefined;
      try {
        if (editingRule) {
          const updatedRule = await updateRule(editingRule.id, ruleData);
          setRules(prev => prev.map(r => r.id === editingRule.id ? updatedRule : r));
          notifications.show({
            title: 'Success',
            message: 'Rule updated successfully',
            color: 'green',
          });
        } else {
          newRule = await createRule({ ...ruleData, version: DEFAULT_RULE_VERSION });
          setRules(prev => [...prev, newRule!]);
          notifications.show({
            title: 'Success',
            message: 'Rule created successfully',
            color: 'green',
          });
        }
        setRuleModalOpen(false);
        form.reset();
         setEditingRule(null);
        } catch (error) {
          console.error('Failed to save rule:', error);
          if (editingRule) {
            setRules(prev => prev.map(r => r.id === editingRule.id ? editingRule : r));
          } else if (newRule !== undefined) {
            setRules(prev => prev.filter(r => r.id !== newRule!.id));
          }
          notifications.show({
            title: 'Error',
            message: `${editingRule ? 'Failed to update' : 'Failed to create'} rule: ${(error as Error).message}`,
            color: 'red',
          });
      }
   };

  const openCreateModal = () => {
    setEditingRule(null);
    form.reset();
    setRuleModalOpen(true);
  };

  const openEditModal = useCallback((rule: Rule) => {
    setEditingRule({
      id: rule.id,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      version: rule.version,
      conditions: rule.conditions,
      actions: rule.actions,
      enabled: rule.enabled,
      actionConfig: rule.actions && rule.actions.length > 0 ? JSON.stringify(rule.actions[0].config, null, 2) : '{}',
    });
    setRuleModalOpen(true);
  }, []);

  const handleExport = useCallback((format: 'csv' | 'json') => {
    const dataToExport = selectedRules.length > 0
      ? rules.filter(rule => selectedRules.includes(rule.id))
      : rules;

    if (format === 'csv') {
      const csvContent = [
        ['ID', 'Name', 'Description', 'Severity', 'Enabled', 'Version'],
        ...dataToExport.map(rule => [
          rule.id,
          rule.name,
          rule.description,
          rule.severity,
          rule.enabled ? 'Yes' : 'No',
          rule.version
        ])
      ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'rules.csv';
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const jsonContent = JSON.stringify(dataToExport, null, 2);
      const blob = new Blob([jsonContent], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'rules.json';
      a.click();
      URL.revokeObjectURL(url);
    }
  }, [rules, selectedRules]);

  const handleBulkDelete = useCallback(async (ruleIds: string[]) => {
    try {
      await Promise.all(ruleIds.map(id => deleteRule(id)));
      setRules(prev => prev.filter(rule => !ruleIds.includes(rule.id)));
      setSelectedRules([]);
      notifications.show({
        title: 'Success',
        message: `Deleted ${ruleIds.length} rule${ruleIds.length !== 1 ? 's' : ''}`,
        color: 'green',
      });
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to delete some rules',
        color: 'red',
      });
    }
  }, []);

  const columns = useMemo(() => getRulesColumns(handleToggleEnabled, openEditModal, setRuleToDelete, setDeleteModalOpen), [handleToggleEnabled, openEditModal, setRuleToDelete, setDeleteModalOpen]);

  if (loading) {
    return <Loading type="table" />;
  }

  return (
    <>
      <Group justify="space-between" mb="lg">
        <div>
          <Title order={2} className="text-text-primary">Rules</Title>
          <Text size="sm" className="text-text-secondary">Manage detection rules and alerting logic</Text>
        </div>
        <Button leftSection={<IconPlus size="1rem" />} onClick={openCreateModal}>
          Add Rule
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
        onClose={() => setDeleteModalOpen(false)}
        title="Confirm Delete"
        confirmLabel="Delete"
        cancelLabel="Cancel"
        onConfirm={handleDelete}
        showFooter
      >
        <Text>Are you sure you want to delete the rule "{ruleToDelete?.name}"?</Text>
        <Text size="sm" className="text-text-secondary mt-2">
          This action cannot be undone.
        </Text>
      </Modal>

      <Modal
        opened={ruleModalOpen}
        onClose={() => setRuleModalOpen(false)}
        title={editingRule ? 'Edit Rule' : 'Create Rule'}
        size="xl"
        showFooter={false}
      >
        <form onSubmit={form.onSubmit(handleCreateEdit)}>
          <TextInput
            label="Name"
            placeholder="Rule name"
            {...form.getInputProps('name')}
            required
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

          <Text size="sm" fw={500} mb="sm" className="text-text-primary">Condition</Text>
          <div className="border border-border rounded-md p-4 mb-4 bg-background">
            <Group grow mb="sm">
              <TextInput
                placeholder="Field (e.g., event_type)"
                {...form.getInputProps('conditionField')}
              />
              <Select
                placeholder="Operator"
                data={OPERATOR_OPTIONS}
                {...form.getInputProps('conditionOperator')}
              />
            </Group>
            <TextInput
              placeholder="Value (e.g., failed_login)"
              {...form.getInputProps('conditionValue')}
            />
          </div>

          <Text size="sm" fw={500} mb="sm" className="text-text-primary">Action</Text>
          <div className="border border-border rounded-md p-4 mb-6 bg-background">
            <Select
              placeholder="Action Type"
              data={ACTION_TYPES}
              {...form.getInputProps('actionType')}
              mb="sm"
            />
            <Textarea
              placeholder='{"url": "https://example.com/webhook"}'
              {...form.getInputProps('actionConfig')}
              minRows={3}
            />
          </div>

          <Group justify="flex-end">
            <Button variant="default" onClick={() => setRuleModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit">
              {editingRule ? 'Update Rule' : 'Create Rule'}
            </Button>
          </Group>
        </form>
      </Modal>
    </>
  );
};