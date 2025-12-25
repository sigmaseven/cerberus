import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Box,
  Typography,
  Grid,
  Alert,
} from '@mui/material';
import type { Action } from '../../types';

const actionFormSchema = z.object({
  name: z.string().min(1, 'Action name is required'),
  type: z.enum(['webhook', 'jira', 'slack', 'email']),
  config: z.record(z.unknown()),
});

type ActionFormData = z.infer<typeof actionFormSchema>;

interface ActionFormProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: ActionFormData) => void;
  initialData?: Partial<Action>;
  title: string;
}

const actionTemplates = {
  webhook: {
    url: '',
    method: 'POST',
    headers: {},
  },
  jira: {
    base_url: '',
    username: '',
    token: '',
    project: '',
  },
  slack: {
    webhook_url: '',
  },
  email: {
    smtp_server: '',
    port: 587,
    username: '',
    password: '',
    from: '',
    to: '',
  },
};

export function ActionForm({ open, onClose, onSubmit, initialData, title }: ActionFormProps) {
  const [jsonPreview, setJsonPreview] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>(initialData?.type || 'webhook');

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<ActionFormData>({
    resolver: zodResolver(actionFormSchema),
    defaultValues: {
      name: initialData?.id || '',
      type: (initialData?.type as 'webhook' | 'jira' | 'slack' | 'email') || 'webhook',
      config: initialData?.config || actionTemplates.webhook,
    },
  });

  const watchedType = watch('type');
  const watchedConfig = watch('config');

  const handleFormSubmit = (data: ActionFormData) => {
    onSubmit(data);
    onClose();
  };

  const handleTypeChange = (newType: string) => {
    setSelectedType(newType);
    setValue('type', newType as 'webhook' | 'jira' | 'slack' | 'email');
    setValue('config', actionTemplates[newType as keyof typeof actionTemplates]);
  };

  const showJsonPreview = () => {
    const actionData = {
      id: initialData?.id || `action_${Date.now()}`,
      type: watchedType,
      config: watchedConfig,
    };
    setJsonPreview(JSON.stringify(actionData, null, 2));
  };

  const renderConfigFields = () => {
    switch (watchedType) {
      case 'webhook':
        return (
          <Grid container spacing={2}>
            <Grid item xs={12} sm={8}>
              <TextField
                fullWidth
                label="Webhook URL"
                {...register('config.url')}
                placeholder="https://example.com/webhook"
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <FormControl fullWidth>
                <InputLabel>Method</InputLabel>
                <Select {...register('config.method')} defaultValue="POST">
                  <MenuItem value="GET">GET</MenuItem>
                  <MenuItem value="POST">POST</MenuItem>
                  <MenuItem value="PUT">PUT</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Headers (JSON)"
                {...register('config.headers')}
                placeholder='{"Authorization": "Bearer token"}'
                multiline
                rows={2}
              />
            </Grid>
             <Grid item xs={12} sm={4}>
               <FormControl fullWidth>
                 <InputLabel>Issue Type</InputLabel>
                 <Select {...register('config.issue_type')} defaultValue="Bug">
                   <MenuItem value="Bug">Bug</MenuItem>
                   <MenuItem value="Task">Task</MenuItem>
                   <MenuItem value="Story">Story</MenuItem>
                 </Select>
               </FormControl>
             </Grid>
             <Grid item xs={12}>
               <TextField
                 fullWidth
                 label="Project Key"
                 {...register('config.project_key')}
                 placeholder="PROJ"
               />
             </Grid>
             <Grid item xs={12}>
               <TextField
                 fullWidth
                 label="Headers (JSON)"
                 {...register('config.headers')}
                 placeholder='{"Authorization": "Bearer token", "Content-Type": "application/json"}'
                 multiline
                 rows={2}
               />
             </Grid>
          </Grid>
        );

      case 'jira':
        return (
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Jira Base URL"
                {...register('config.base_url')}
                placeholder="https://your-company.atlassian.net"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Username/Email"
                {...register('config.username')}
                placeholder="your-email@company.com"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="API Token"
                {...register('config.token')}
                type="password"
                placeholder="Jira API token"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="To Email"
                {...register('config.to')}
                placeholder="admin@example.com"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Subject"
                {...register('config.subject')}
                placeholder="Security Alert"
              />
            </Grid>
            <Grid item xs={12} sm={8}>
              <TextField
                fullWidth
                label="SMTP Server"
                {...register('config.smtp_server')}
                placeholder="smtp.example.com"
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                label="SMTP Port"
                {...register('config.smtp_port')}
                placeholder="587"
                type="number"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Username"
                {...register('config.username')}
                placeholder="user@example.com"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Password"
                {...register('config.password')}
                type="password"
                placeholder="password"
              />
            </Grid>
          </Grid>
        );

      case 'slack':
        return (
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Slack Webhook URL"
                {...register('config.webhook_url')}
                placeholder="https://hooks.slack.com/services/..."
              />
            </Grid>
          </Grid>
        );

      case 'email':
        return (
          <Grid container spacing={2}>
            <Grid item xs={12} sm={8}>
              <TextField
                fullWidth
                label="SMTP Server"
                {...register('config.smtp_server')}
                placeholder="smtp.gmail.com"
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                label="Port"
                {...register('config.port')}
                placeholder="587"
                type="number"
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                label="Port"
                {...register('config.port')}
                type="number"
                defaultValue={587}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Assignee"
                {...register('config.assignee')}
                placeholder="user@example.com"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Reporter"
                {...register('config.reporter')}
                placeholder="cerberus@example.com"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Password"
                {...register('config.password')}
                type="password"
                placeholder="App password or SMTP password"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Channel"
                {...register('config.channel')}
                placeholder="#alerts"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Username"
                {...register('config.username')}
                placeholder="Cerberus"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="To Address"
                {...register('config.to')}
                placeholder="security-team@company.com"
              />
            </Grid>
          </Grid>
        );

      default:
        return null;
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Box component="form" sx={{ mt: 2 }}>
          <Grid container spacing={3}>
            <Grid item xs={12} sm={8}>
              <TextField
                fullWidth
                label="Action Name"
                {...register('name')}
                error={!!errors.name}
                helperText={errors.name?.message}
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <FormControl fullWidth>
                <InputLabel>Action Type</InputLabel>
                <Select
                  value={selectedType}
                  onChange={(e) => handleTypeChange(e.target.value)}
                >
                  <MenuItem value="webhook">Webhook</MenuItem>
                  <MenuItem value="jira">Jira Ticket</MenuItem>
                  <MenuItem value="slack">Slack Message</MenuItem>
                  <MenuItem value="email">Email Notification</MenuItem>
                </Select>
              </FormControl>
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>
              Configuration
            </Typography>
            {renderConfigFields()}
          </Box>

          <Box sx={{ mt: 3 }}>
            <Button variant="outlined" onClick={showJsonPreview} sx={{ mr: 2 }}>
              Show JSON Preview
            </Button>
            <Button variant="outlined" color="primary">
              Test Action
            </Button>
          </Box>

          {jsonPreview && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                JSON Preview:
              </Typography>
              <Box
                component="pre"
                sx={{
                  bgcolor: 'grey.900',
                  p: 2,
                  borderRadius: 1,
                  overflow: 'auto',
                  maxHeight: 200,
                  fontSize: '0.75rem',
                }}
              >
                {jsonPreview}
              </Box>
            </Box>
          )}

          <Alert severity="info" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>Note:</strong> Action configurations contain sensitive information.
              Ensure proper security measures are in place when storing and transmitting this data.
            </Typography>
          </Alert>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit(handleFormSubmit)} variant="contained">
          Save Action
        </Button>
      </DialogActions>
    </Dialog>
  );
}