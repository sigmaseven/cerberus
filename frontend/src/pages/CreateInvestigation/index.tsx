import React from 'react';
import {
  Container,
  Typography,
  Box,
  IconButton,
  Paper,
  Alert,
} from '@mui/material';
import { ArrowBack as BackIcon } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { InvestigationForm } from '../../components/forms/InvestigationForm';
import api from '../../services/api';
import type { Alert as AlertType } from '../../types';

interface CreateInvestigationData {
  title: string;
  description: string;
  priority: string;
  assignee_id?: string;
  alert_ids?: string[];
}

export const CreateInvestigation: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Fetch recent alerts that might be related
  const { data: recentAlerts, isLoading: alertsLoading } = useQuery<{ alerts: AlertType[] }>({
    queryKey: ['alerts', 'recent'],
    queryFn: async () => {
      const response = await api.get('/api/v1/alerts', {
        params: {
          limit: 50,
          status: 'new',
        },
      });
      return response.data;
    },
  });

  const createMutation = useMutation({
    mutationFn: (data: CreateInvestigationData) =>
      api.investigations.createInvestigation(data),
    onSuccess: (newInvestigation) => {
      queryClient.invalidateQueries({ queryKey: ['investigations'] });
      queryClient.invalidateQueries({ queryKey: ['investigation-stats'] });

      // Navigate to the newly created investigation
      navigate(`/investigations/${newInvestigation.investigation_id}`);
    },
  });

  const handleSubmit = async (data: CreateInvestigationData) => {
    await createMutation.mutateAsync(data);
  };

  const handleCancel = () => {
    navigate('/investigations');
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <IconButton onClick={handleCancel} sx={{ mr: 2 }}>
          <BackIcon />
        </IconButton>
        <Box>
          <Typography variant="h4" component="h1" fontWeight={600}>
            Create New Investigation
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Start a new security incident investigation
          </Typography>
        </Box>
      </Box>

      {/* Error Alert */}
      {createMutation.isError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {createMutation.error instanceof Error
            ? createMutation.error.message
            : 'Failed to create investigation'}
        </Alert>
      )}

      {/* Investigation Form */}
      <InvestigationForm
        onSubmit={handleSubmit}
        onCancel={handleCancel}
        availableAlerts={recentAlerts?.alerts || []}
        loading={alertsLoading}
      />

      {/* Help Text */}
      <Paper sx={{ mt: 3, p: 2, bgcolor: 'info.lighter' }}>
        <Typography variant="body2" color="text.secondary">
          <strong>Tip:</strong> You can link related alerts, add notes, and map MITRE ATT&CK
          techniques after creating the investigation. Start with a clear title and description
          of what you're investigating.
        </Typography>
      </Paper>
    </Container>
  );
};

export default CreateInvestigation;
