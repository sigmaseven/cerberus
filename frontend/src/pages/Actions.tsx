import { useEffect, useState, useMemo, useCallback } from 'react';
import { Title, Button, Group, Text, TextInput, Textarea, Select, Badge } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconEdit, IconTrash, IconPlus } from '@tabler/icons-react';
import { Table } from '../components/Table';
import { Modal } from '../components/Modal';
import { Loading } from '../components/Loading';
import type { Action } from '../types';
import { getActions, deleteAction, updateAction, createAction } from '../services/api';
import { notifications } from '@mantine/notifications';
import { ACTION_TYPES } from '../constants';

const getActionsColumns = (openEditModal: (action: Action) => void, setActionToDelete: (action: Action) => void, setDeleteModalOpen: (open: boolean) => void) => [
   {
     accessor: 'id',
     title: 'ID',
     render: (action: Action) => (
       <span className="font-mono text-sm">{action.id || 'N/A'}</span>
     )
   },
   {
     accessor: 'type',
     title: 'Type',
     sortable: true,
     render: (action: Action) => (
       <Badge color="blue" variant="light">{action.type}</Badge>
     )
   },
   {
     accessor: 'config',
     title: 'Configuration',
     render: (action: Action) => (
       <div className="max-w-xs truncate font-mono text-xs">
         {JSON.stringify(action.config)}
       </div>
     )
   },
   {
     accessor: 'actions',
     title: 'Actions',
     render: (action: Action) => (
       <Group gap="xs">
         <Button
           size="xs"
           variant="subtle"
           leftSection={<IconEdit size={14} />}
           onClick={() => openEditModal(action)}
         >
           Edit
         </Button>
         <Button
           size="xs"
           variant="subtle"
           color="red"
           leftSection={<IconTrash size={14} />}
           onClick={() => { setActionToDelete(action); setDeleteModalOpen(true); }}
           disabled={!action.id}
         >
           Delete
         </Button>
       </Group>
     )
   },
];

export const Actions = () => {
   const [actions, setActions] = useState<Action[]>([]);
   const [loading, setLoading] = useState(true);
   const [deleteModalOpen, setDeleteModalOpen] = useState(false);
   const [actionToDelete, setActionToDelete] = useState<Action | null>(null);
   const [actionModalOpen, setActionModalOpen] = useState(false);
   const [editingAction, setEditingAction] = useState<Action | null>(null);
   const [selectedActions, setSelectedActions] = useState<string[]>([]);

  type ActionFormValues = {
    type: string;
    config: string;
  };

  const form = useForm<ActionFormValues>({
    initialValues: {
      type: 'webhook',
      config: '',
    },
    validate: {
      type: (value: string) => (value.length < 1 ? 'Type is required' : null),
      config: (value: string) => {
        try {
          const parsed = JSON.parse(value);
          if (typeof parsed !== 'object' || parsed === null) {
            return 'Config must be a JSON object';
          }
          return null;
        } catch {
          return 'Config must be valid JSON';
        }
      },
    },
  });

  useEffect(() => {
    fetchActions();
  }, []);

  const fetchActions = async () => {
    try {
      const data = await getActions();
      setActions(data);
    } catch {
      notifications.show({
        title: 'Error',
        message: 'Failed to load actions',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  };

  const openCreateModal = () => {
    setEditingAction(null);
    form.reset();
    setActionModalOpen(true);
  };

   const openEditModal = useCallback((action: Action) => {
     setEditingAction(action);
     form.setValues({
       type: action.type,
       config: JSON.stringify(action.config),
     });
     setActionModalOpen(true);
   }, [form]);

   const handleCreateEdit = async (values: ActionFormValues) => {
     try {
       const parsed = JSON.parse(values.config);
       if (typeof parsed !== 'object' || parsed === null) {
         throw new Error('Config must be a JSON object');
       }
       const config = parsed as Record<string, unknown>;
       const actionData = {
         type: values.type,
         config,
       };

       if (editingAction?.id) {
         // Optimistic update
         setActions(prev => prev.map(a => a.id === editingAction.id ? { ...a, ...actionData } : a));
         try {
           await updateAction(editingAction.id, actionData);
           notifications.show({
             title: 'Success',
             message: 'Action updated successfully',
             color: 'green',
           });
         } catch (updateError) {
           // Revert
           setActions(prev => prev.map(a => a.id === editingAction.id ? editingAction : a));
           throw updateError;
         }
       } else {
         // Optimistic create
          const tempId = `temp-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
          const tempAction = { ...actionData, id: tempId } as Action;
         setActions(prev => [...prev, tempAction]);
         try {
           const newAction = await createAction(actionData);
           setActions(prev => prev.map(a => a.id === tempId ? newAction : a));
           notifications.show({
             title: 'Success',
             message: 'Action created successfully',
             color: 'green',
           });
         } catch (createError) {
           // Remove temp
           setActions(prev => prev.filter(a => a.id !== tempId));
           throw createError;
         }
       }

        setActionModalOpen(false);
      } catch (error) {
       notifications.show({
         title: 'Error',
         message: error instanceof Error ? error.message : 'Failed to save action',
         color: 'red',
       });
     }
  };

  const handleDelete = async () => {
    if (!actionToDelete?.id) return;

    // Optimistic update
    setActions(prev => prev.filter(a => a.id !== actionToDelete.id));
    setDeleteModalOpen(false);

    try {
      await deleteAction(actionToDelete.id);
      notifications.show({
        title: 'Success',
        message: 'Action deleted successfully',
        color: 'green',
      });
    } catch (error) {
      console.error('Failed to delete action:', error);
      // Revert
      setActions(prev => [...prev, actionToDelete]);
      notifications.show({
        title: 'Error',
        message: 'Failed to delete action',
        color: 'red',
      });
    }
  };

  const handleExport = useCallback((format: 'csv' | 'json') => {
    const dataToExport = selectedActions.length > 0
      ? actions.filter(action => selectedActions.includes(action.id || ''))
      : actions;

    if (format === 'csv') {
      const csvContent = [
        ['ID', 'Type', 'Config'],
        ...dataToExport.map(action => [
          action.id || '',
          action.type,
          JSON.stringify(action.config)
        ])
      ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'actions.csv';
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const jsonContent = JSON.stringify(dataToExport, null, 2);
      const blob = new Blob([jsonContent], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'actions.json';
      a.click();
      URL.revokeObjectURL(url);
    }
  }, [actions, selectedActions]);

  const handleBulkDelete = useCallback(async (actionIds: string[]) => {
    try {
      await Promise.all(actionIds.map(id => deleteAction(id)));
      setActions(prev => prev.filter(action => !actionIds.includes(action.id || '')));
      setSelectedActions([]);
      notifications.show({
        title: 'Success',
        message: `Deleted ${actionIds.length} action${actionIds.length !== 1 ? 's' : ''}`,
        color: 'green',
      });
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to delete some actions',
        color: 'red',
      });
    }
  }, []);

   const columns = useMemo(() => getActionsColumns(openEditModal, setActionToDelete, setDeleteModalOpen), [openEditModal]);

    if (loading) {
      return <Loading type="table" />;
    }

   return (
     <>
       <Group justify="space-between" mb="lg">
         <div>
           <Title order={2} className="text-text-primary">Actions</Title>
           <Text size="sm" className="text-text-secondary">Configure automated responses to security events</Text>
         </div>
         <Button leftSection={<IconPlus size="1rem" />} onClick={openCreateModal}>
           Add Action
         </Button>
       </Group>

       <Table
         records={actions}
         columns={columns}
         selectable
         getRecordId={(action) => action.id || ''}
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
         <Text>Are you sure you want to delete the action "{actionToDelete?.id}"?</Text>
         <Text size="sm" className="text-text-secondary mt-2">
           This action cannot be undone.
         </Text>
       </Modal>

       <Modal
         opened={actionModalOpen}
         onClose={() => setActionModalOpen(false)}
         title={editingAction ? 'Edit Action' : 'Create Action'}
         size="lg"
         showFooter={false}
       >
         <form onSubmit={form.onSubmit(handleCreateEdit)}>
           {editingAction?.id && (
             <TextInput
               label="ID"
               value={editingAction.id}
               readOnly
               mb="md"
             />
           )}
           <Select
             label="Action Type"
             data={ACTION_TYPES}
             {...form.getInputProps('type')}
             mb="md"
           />
           <div>
             <Text size="sm" fw={500} mb="xs" className="text-text-primary">Configuration (JSON)</Text>
             <Textarea
               placeholder='{"url": "https://example.com/webhook", "method": "POST"}'
               {...form.getInputProps('config')}
               minRows={6}
               className="font-mono text-sm"
             />
             <Text size="xs" className="text-text-secondary mt-1">
               Enter valid JSON configuration for the selected action type
             </Text>
           </div>
           <Group justify="flex-end" mt="xl">
             <Button variant="default" onClick={() => setActionModalOpen(false)}>
               Cancel
             </Button>
             <Button type="submit">
               {editingAction ? 'Update Action' : 'Create Action'}
             </Button>
           </Group>
         </form>
       </Modal>
     </>
   );
};