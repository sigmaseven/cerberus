import React, { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
  Box,
  Alert,
  Snackbar,
  CircularProgress,
  Button,
  Stack,
} from '@mui/material';
import {
  Storage as StorageIcon,
  Router as RouterIcon,
  Security as SecurityIcon,
  Info as InfoIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Transform as TransformIcon,
  RssFeed as FeedIcon,
} from '@mui/icons-material';
import { Settings, UpdateResult, SystemInfo } from '../../types';
import apiService from '../../services/api';
import DataRetentionSettings from './DataRetentionSettings';
import ListenerSettings from './ListenerSettings';
import SystemInfoPanel from './SystemInfoPanel';
import FieldMappingSettings from './FieldMappingSettings';
import FeedSettings from './FeedSettings';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`settings-tabpanel-${index}`}
      aria-labelledby={`settings-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

export default function SettingsPage() {
  const [currentTab, setCurrentTab] = useState(0);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [pendingChanges, setPendingChanges] = useState<Record<string, unknown>>({});
  const [requiresRestart, setRequiresRestart] = useState<string[]>([]);

  useEffect(() => {
    loadSettings();
    loadSystemInfo();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const data = await apiService.getSettings();
      setSettings(data);
      setError(null);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(message || 'Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

   const loadSystemInfo = async () => {
     try {
       const data = await apiService.getSystemInfo();
       setSystemInfo(data);
     } catch {
       // Silently handle system info loading errors
     }
   };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setCurrentTab(newValue);
  };

  const handleSettingChange = (key: string, value: unknown) => {
    setPendingChanges({
      ...pendingChanges,
      [key]: value,
    });
  };

  const handleSave = async () => {
    if (Object.keys(pendingChanges).length === 0) {
      setError('No changes to save');
      return;
    }

    try {
      setSaving(true);
      const result: UpdateResult = await apiService.updateSettings(pendingChanges);

      if (result.success) {
        setSuccess(result.message);
        setPendingChanges({});
        setRequiresRestart(result.requires_restart);

        // Reload settings to get latest values
        await loadSettings();

        // Show restart notification if needed
        if (result.requires_restart.length > 0) {
          setError(
            `Settings saved successfully. The following changes require a server restart: ${result.requires_restart.join(', ')}`
          );
        }
      } else {
        setError(result.message);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(message || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setPendingChanges({});
    setSuccess('Changes discarded');
  };

  const handleExport = async () => {
    try {
      const blob = await apiService.exportSettings();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'cerberus-config.json';
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setSuccess('Settings exported successfully');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(message || 'Failed to export settings');
    }
  };

  const handleImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const result = await apiService.importSettings(file);
      if (result.success) {
        setSuccess('Settings imported successfully');
        await loadSettings();
      } else {
        setError('Failed to import settings');
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(message || 'Failed to import settings');
    }
  };

  if (loading) {
    return (
      <Container sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
        <CircularProgress />
      </Container>
    );
  }

  if (!settings) {
    return (
      <Container>
        <Alert severity="error">Failed to load settings</Alert>
      </Container>
    );
  }

  const hasChanges = Object.keys(pendingChanges).length > 0;

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" component="h1">
          Settings
        </Typography>
        <Stack direction="row" spacing={1}>
          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={handleExport}
          >
            Export
          </Button>
          <Button
            variant="outlined"
            component="label"
            startIcon={<UploadIcon />}
          >
            Import
            <input
              type="file"
              hidden
              accept=".json"
              onChange={handleImport}
            />
          </Button>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={loadSettings}
          >
            Refresh
          </Button>
        </Stack>
      </Box>

      {requiresRestart.length > 0 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          The following settings require a server restart to take effect:{' '}
          {requiresRestart.join(', ')}
        </Alert>
      )}

      <Paper sx={{ width: '100%', mb: 2 }}>
        <Tabs
          value={currentTab}
          onChange={handleTabChange}
          aria-label="settings tabs"
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab icon={<StorageIcon />} label="Data Retention" iconPosition="start" />
          <Tab icon={<RouterIcon />} label="Listeners" iconPosition="start" />
          <Tab icon={<FeedIcon />} label="Feeds" iconPosition="start" />
          <Tab icon={<TransformIcon />} label="Field Mappings" iconPosition="start" />
          <Tab icon={<SecurityIcon />} label="API & Security" iconPosition="start" />
          <Tab icon={<InfoIcon />} label="System Info" iconPosition="start" />
        </Tabs>

        <TabPanel value={currentTab} index={0}>
          <DataRetentionSettings
            settings={settings}
            pendingChanges={pendingChanges}
            onChange={handleSettingChange}
          />
        </TabPanel>

        <TabPanel value={currentTab} index={1}>
          <ListenerSettings
            settings={settings}
            pendingChanges={pendingChanges}
            onChange={handleSettingChange}
          />
        </TabPanel>

        <TabPanel value={currentTab} index={2}>
          <FeedSettings />
        </TabPanel>

        <TabPanel value={currentTab} index={3}>
          <FieldMappingSettings />
        </TabPanel>

        <TabPanel value={currentTab} index={4}>
          <Box sx={{ p: 2 }}>
            <Typography variant="body1" color="text.secondary">
              API & Security settings panel - Coming soon
            </Typography>
          </Box>
        </TabPanel>

        <TabPanel value={currentTab} index={5}>
          <SystemInfoPanel systemInfo={systemInfo} onRefresh={loadSystemInfo} />
        </TabPanel>
      </Paper>

      {currentTab !== 2 && currentTab !== 3 && currentTab !== 4 && currentTab !== 5 && (
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
          <Button
            variant="outlined"
            onClick={handleReset}
            disabled={!hasChanges || saving}
          >
            Discard Changes
          </Button>
          <Button
            variant="contained"
            startIcon={saving ? <CircularProgress size={20} /> : <SaveIcon />}
            onClick={handleSave}
            disabled={!hasChanges || saving}
          >
            {saving ? 'Saving...' : 'Save Changes'}
          </Button>
        </Box>
      )}

      <Snackbar
        open={!!success}
        autoHideDuration={6000}
        onClose={() => setSuccess(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity="success" onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      </Snackbar>

      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      </Snackbar>
    </Container>
  );
}
