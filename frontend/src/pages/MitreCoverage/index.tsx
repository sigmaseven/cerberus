import { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Tabs,
  Tab,
  CircularProgress,
  Alert,
  IconButton,
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { Refresh as RefreshIcon, Settings as SettingsIcon } from '@mui/icons-material';
import { apiService } from '../../services/api';
import MitreService, { CoverageReport } from '../../services/mitreService';
import CoverageOverview from './components/CoverageOverview';
import TacticBreakdown from './components/TacticBreakdown';
import GapAnalysisTable from './components/GapAnalysisTable';
import CoverageMatrix from './components/CoverageMatrix';
import CoverageHeatMap from './components/CoverageHeatMap';

function MitreCoverage() {
  const [activeTab, setActiveTab] = useState(0);

  // Initialize MITRE service
  const mitreService = new MitreService((apiService as any).api);

  // Fetch coverage data
  const {
    data: coverageData,
    isLoading,
    error,
    refetch,
  } = useQuery<CoverageReport>({
    queryKey: ['mitre-coverage'],
    queryFn: () => mitreService.getCoverageReport(),
    refetchInterval: 60000, // Refresh every minute
    staleTime: 30000, // Consider stale after 30 seconds
  });

  const handleRefresh = () => {
    refetch();
  };

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        Failed to load MITRE ATT&CK coverage data. Please check your connection and try again.
      </Alert>
    );
  }

  if (!coverageData) {
    return (
      <Alert severity="warning">
        No coverage data available. Please ensure detection rules are tagged with MITRE techniques.
      </Alert>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          MITRE ATT&CK Coverage Analysis
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <IconButton onClick={handleRefresh} title="Refresh Coverage Data">
            <RefreshIcon />
          </IconButton>
          <IconButton title="Settings">
            <SettingsIcon />
          </IconButton>
        </Box>
      </Box>

      {/* Coverage Overview Cards */}
      <CoverageOverview coverageData={coverageData} />

      {/* Tabs for different views */}
      <Paper sx={{ mt: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Overview" />
          <Tab label="Coverage Matrix" />
          <Tab label="Gap Analysis" />
          <Tab label="Heat Map" />
        </Tabs>

        <Box sx={{ p: 3 }}>
          {/* Tab Panel 0: Overview - Tactic Breakdown */}
          {activeTab === 0 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Coverage by Tactic
              </Typography>
              <TacticBreakdown coverageData={coverageData} />
            </Box>
          )}

          {/* Tab Panel 1: Coverage Matrix */}
          {activeTab === 1 && (
            <Box>
              <CoverageMatrix />
            </Box>
          )}

          {/* Tab Panel 2: Gap Analysis */}
          {activeTab === 2 && (
            <Box>
              <GapAnalysisTable coverageData={coverageData} />
            </Box>
          )}

          {/* Tab Panel 3: Heat Map */}
          {activeTab === 3 && (
            <Box>
              <CoverageHeatMap />
            </Box>
          )}
        </Box>
      </Paper>

      {/* Last Updated Footer */}
      <Box sx={{ mt: 2, textAlign: 'right' }}>
        <Typography variant="caption" color="text.secondary">
          Last Updated: {new Date(coverageData.last_updated).toLocaleString()}
        </Typography>
      </Box>
    </Box>
  );
}

export default MitreCoverage;
