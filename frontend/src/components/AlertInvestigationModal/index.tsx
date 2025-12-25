import { Dialog, DialogContent, DialogTitle, IconButton, Box, Tabs, Tab, Chip, Typography, Button } from '@mui/material';
import { Close, ContentCopy } from '@mui/icons-material';
import { useState, memo } from 'react';
import { getSeverityColor } from '../../utils/severity';
import { AlertInvestigationModalProps, TabValue } from './types';
import OverviewTab from './OverviewTab';
import TimelineTab from './TimelineTab';
import RelatedTab from './RelatedTab';
import ActionsPanel from './ActionsPanel';

const AlertInvestigationModal = ({ alert, open, onClose, onAlertUpdated }: AlertInvestigationModalProps) => {
  const [currentTab, setCurrentTab] = useState<TabValue>('overview');

  if (!alert) return null;

  const handleTabChange = (_event: React.SyntheticEvent, newValue: TabValue) => {
    setCurrentTab(newValue);
  };

  const getStatusColor = (status: string): "warning" | "info" | "primary" | "success" | "default" => {
    switch (status.toLowerCase()) {
      case 'new':
      case 'pending':
        return 'warning';
      case 'acknowledged':
        return 'info';
      case 'investigating':
        return 'primary';
      case 'resolved':
        return 'success';
      case 'dismissed':
      case 'false_positive':
        return 'default';
      default:
        return 'default';
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      PaperProps={{
        sx: {
          height: '90vh',
          maxHeight: '90vh',
        },
      }}
    >
      {/* Modal Header */}
      <DialogTitle
        sx={{
          background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
          color: 'white',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          p: 2,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="h6">Alert Investigation</Typography>
          <Typography variant="body2" sx={{ fontFamily: 'monospace', opacity: 0.9 }}>
            {alert.alert_id}
          </Typography>
          <Chip
            label={alert.severity}
            color={getSeverityColor(alert.severity)}
            size="small"
            sx={{ fontWeight: 'bold' }}
          />
          <Chip
            label={alert.status}
            color={getStatusColor(alert.status)}
            size="small"
            sx={{ fontWeight: 'bold' }}
          />
        </Box>
        <IconButton
          onClick={onClose}
          sx={{
            color: 'white',
            '&:hover': {
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
            },
          }}
        >
          <Close />
        </IconButton>
      </DialogTitle>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={currentTab} onChange={handleTabChange} aria-label="alert investigation tabs">
          <Tab label="Overview" value="overview" />
          <Tab label="Timeline" value="timeline" />
          <Tab label="Related" value="related" />
          <Tab label="Raw Data" value="raw" />
        </Tabs>
      </Box>

      {/* Tab Content */}
       <DialogContent sx={{ p: 0, overflowX: 'hidden', overflowY: 'auto', flex: 1 }}>
        {currentTab === 'overview' && <OverviewTab alert={alert} />}
        {currentTab === 'timeline' && <TimelineTab alert={alert} />}
        {currentTab === 'related' && <RelatedTab alert={alert} />}
        {currentTab === 'raw' && (
          <Box sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Complete Alert Data</Typography>
              <Button
                variant="outlined"
                size="small"
                startIcon={<ContentCopy />}
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(alert, null, 2));
                }}
              >
                Copy All
              </Button>
            </Box>
            <Box
              component="pre"
              sx={{
                backgroundColor: '#1e1e1e',
                color: '#d4d4d4',
                padding: 3,
                borderRadius: 1,
                overflow: 'auto',
                fontSize: '0.875rem',
                fontFamily: 'monospace',
                border: '1px solid #333',
                maxHeight: '600px',
              }}
            >
              {JSON.stringify(alert, null, 2)}
            </Box>
          </Box>
        )}
      </DialogContent>

      {/* Actions Panel */}
      <ActionsPanel alert={alert} onAlertUpdated={onAlertUpdated} />
    </Dialog>
  );
};

export default memo(AlertInvestigationModal);
