import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  FormControlLabel,
  Checkbox,
  Box,
  Typography,
  Alert,
  CircularProgress,
} from '@mui/material';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiService } from '../services/api';
import { DashboardConfig } from '../types';

interface DashboardCustomizationProps {
  open: boolean;
  onClose: () => void;
  currentConfig: DashboardConfig | null;
}

const WIDGET_DESCRIPTIONS: Record<string, string> = {
  'total-events': 'Total Events KPI Card',
  'active-alerts': 'Active Alerts KPI Card',
  'rules-fired': 'Rules Fired KPI Card',
  'system-health': 'System Health KPI Card',
  'events-chart': 'Events & Alerts Over Time Chart',
  'alerts-by-severity': 'Alerts by Severity Pie Chart',
  'recent-alerts': 'Recent Alerts Table',
  'system-status': 'System Status Panel',
};

export default function DashboardCustomization({
  open,
  onClose,
  currentConfig,
}: DashboardCustomizationProps) {
  const queryClient = useQueryClient();
  const [visibleWidgets, setVisibleWidgets] = useState<Set<string>>(
    new Set(currentConfig?.layout.map((w) => w.id) || [])
  );

  const saveMutation = useMutation({
    mutationFn: (config: DashboardConfig) => apiService.saveDashboardConfig(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboardConfig'] });
      onClose();
    },
  });

  const handleToggleWidget = (widgetId: string) => {
    setVisibleWidgets((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(widgetId)) {
        newSet.delete(widgetId);
      } else {
        newSet.add(widgetId);
      }
      return newSet;
    });
  };

  const handleSave = () => {
    if (!currentConfig) return;

    // Filter layout to only include visible widgets
    const filteredLayout = currentConfig.layout.filter((widget) =>
      visibleWidgets.has(widget.id)
    );

    const updatedConfig: DashboardConfig = {
      ...currentConfig,
      layout: filteredLayout,
    };

    saveMutation.mutate(updatedConfig);
  };

  const handleResetToDefault = () => {
    // Reset to show all widgets
    const allWidgetIds = Object.keys(WIDGET_DESCRIPTIONS);
    setVisibleWidgets(new Set(allWidgetIds));
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Customize Dashboard</DialogTitle>
      <DialogContent>
        {saveMutation.isError && (
          <Alert severity="error" sx={{ mb: 2 }}>
            Failed to save dashboard configuration
          </Alert>
        )}
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Select which widgets to display on your dashboard
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          {Object.entries(WIDGET_DESCRIPTIONS).map(([widgetId, description]) => (
            <FormControlLabel
              key={widgetId}
              control={
                <Checkbox
                  checked={visibleWidgets.has(widgetId)}
                  onChange={() => handleToggleWidget(widgetId)}
                />
              }
              label={description}
            />
          ))}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleResetToDefault} color="warning">
          Reset to Default
        </Button>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          onClick={handleSave}
          variant="contained"
          disabled={saveMutation.isPending}
        >
          {saveMutation.isPending ? (
            <>
              <CircularProgress size={20} sx={{ mr: 1 }} />
              Saving...
            </>
          ) : (
            'Save'
          )}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
