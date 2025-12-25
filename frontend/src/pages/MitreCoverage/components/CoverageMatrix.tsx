import { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tooltip,
  CircularProgress,
  Alert,
  ToggleButtonGroup,
  ToggleButton,
  FormControlLabel,
  Switch,
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import {
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  GridView as GridViewIcon,
  ViewList as ViewListIcon,
} from '@mui/icons-material';
import { apiService } from '../../../services/api';
import MitreService, { CoverageMatrix as CoverageMatrixData } from '../../../services/mitreService';

type ViewMode = 'compact' | 'detailed';

function CoverageMatrix() {
  const [viewMode, setViewMode] = useState<ViewMode>('compact');
  const [showOnlyCovered, setShowOnlyCovered] = useState(false);

  const mitreService = new MitreService((apiService as any).api);

  const {
    data: matrixData,
    isLoading,
    error,
  } = useQuery<CoverageMatrixData>({
    queryKey: ['mitre-coverage-matrix'],
    queryFn: () => mitreService.getCoverageMatrix(),
    staleTime: 60000,
  });

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="300px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        Failed to load coverage matrix. Please try again.
      </Alert>
    );
  }

  if (!matrixData) {
    return (
      <Alert severity="warning">
        No matrix data available.
      </Alert>
    );
  }

  // Filter tactics and techniques based on showOnlyCovered
  const filteredTactics = showOnlyCovered
    ? matrixData.tactics.filter((tactic) =>
        tactic.techniques.some((tech) => tech.is_covered)
      )
    : matrixData.tactics;

  return (
    <Box>
      {/* Controls */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <ToggleButtonGroup
          value={viewMode}
          exclusive
          onChange={(_, newMode) => newMode && setViewMode(newMode)}
          size="small"
        >
          <ToggleButton value="compact">
            <GridViewIcon sx={{ mr: 1 }} />
            Compact
          </ToggleButton>
          <ToggleButton value="detailed">
            <ViewListIcon sx={{ mr: 1 }} />
            Detailed
          </ToggleButton>
        </ToggleButtonGroup>

        <FormControlLabel
          control={
            <Switch
              checked={showOnlyCovered}
              onChange={(e) => setShowOnlyCovered(e.target.checked)}
            />
          }
          label="Show only covered techniques"
        />
      </Box>

      {/* Legend */}
      <Paper sx={{ p: 2, mb: 3, bgcolor: 'background.default' }}>
        <Box sx={{ display: 'flex', gap: 3, alignItems: 'center' }}>
          <Typography variant="body2" fontWeight="medium">
            Legend:
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Box
              sx={{
                width: 20,
                height: 20,
                bgcolor: 'success.main',
                borderRadius: 1,
              }}
            />
            <Typography variant="body2">Covered</Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Box
              sx={{
                width: 20,
                height: 20,
                bgcolor: 'error.main',
                borderRadius: 1,
              }}
            />
            <Typography variant="body2">Not Covered</Typography>
          </Box>
        </Box>
      </Paper>

      {/* Matrix Grid */}
      <Box
        sx={{
          overflowX: 'auto',
          overflowY: 'auto',
          maxHeight: '50vh',
        }}
      >
        {viewMode === 'compact' ? (
          <CompactMatrix tactics={filteredTactics} />
        ) : (
          <DetailedMatrix tactics={filteredTactics} />
        )}
      </Box>
    </Box>
  );
}

interface MatrixProps {
  tactics: Array<{
    tactic_id: string;
    tactic_name: string;
    techniques: Array<{
      technique_id: string;
      technique_name: string;
      is_covered: boolean;
      rule_count: number;
    }>;
  }>;
}

function CompactMatrix({ tactics }: MatrixProps) {
  // Tactic color mapping
  const getTacticColor = (tacticName: string): string => {
    const colors: Record<string, string> = {
      'Initial Access': '#5F7A8B',
      'Execution': '#4F8A8B',
      'Persistence': '#458B74',
      'Privilege Escalation': '#8B7355',
      'Defense Evasion': '#8B5A3C',
      'Credential Access': '#8B4726',
      'Discovery': '#8B6914',
      'Lateral Movement': '#6E8B3D',
      'Collection': '#548B54',
      'Command and Control': '#2F8B87',
      'Exfiltration': '#36648B',
      'Impact': '#5D478B',
    };
    return colors[tacticName] || '#607D8B';
  };

  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: {
          xs: '1fr',
          sm: 'repeat(2, 1fr)',
          md: 'repeat(3, 1fr)',
          lg: 'repeat(4, 1fr)',
        },
        gap: 2,
      }}
    >
      {tactics.map((tactic) => (
        <Paper key={tactic.tactic_id} sx={{ display: 'flex', flexDirection: 'column' }}>
          {/* Tactic Header */}
          <Box
            sx={{
              p: 2,
              bgcolor: getTacticColor(tactic.tactic_name),
              color: 'white',
            }}
          >
            <Tooltip title={tactic.tactic_id}>
              <Typography variant="subtitle2" fontWeight="bold" noWrap>
                {tactic.tactic_name}
              </Typography>
            </Tooltip>
            <Typography variant="caption">
              {tactic.techniques.filter((t) => t.is_covered).length} /{' '}
              {tactic.techniques.length}
            </Typography>
          </Box>

          {/* Technique Cells */}
          <Box sx={{ p: 1, flexGrow: 1 }}>
            {tactic.techniques.map((technique) => (
              <Tooltip
                key={technique.technique_id}
                title={
                  <Box>
                    <Typography variant="body2" fontWeight="bold">
                      {technique.technique_id}
                    </Typography>
                    <Typography variant="body2">{technique.technique_name}</Typography>
                    <Typography variant="caption">
                      {technique.is_covered
                        ? `${technique.rule_count} rule(s)`
                        : 'No coverage'}
                    </Typography>
                  </Box>
                }
                placement="right"
              >
                <Box
                  sx={{
                    width: '100%',
                    height: 40,
                    mb: 0.5,
                    bgcolor: technique.is_covered ? 'success.main' : 'error.main',
                    borderRadius: 1,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    cursor: 'pointer',
                    transition: 'transform 0.2s',
                    '&:hover': {
                      transform: 'scale(1.05)',
                    },
                  }}
                >
                  {technique.is_covered ? (
                    <CheckCircleIcon sx={{ color: 'white', fontSize: 18 }} />
                  ) : (
                    <CancelIcon sx={{ color: 'white', fontSize: 18 }} />
                  )}
                </Box>
              </Tooltip>
            ))}
          </Box>
        </Paper>
      ))}
    </Box>
  );
}

function DetailedMatrix({ tactics }: MatrixProps) {
  return (
    <Box sx={{ minWidth: 'max-content' }}>
      {tactics.map((tactic) => (
        <Paper key={tactic.tactic_id} sx={{ mb: 2 }}>
          {/* Tactic Header */}
          <Box
            sx={{
              p: 2,
              bgcolor: 'primary.main',
              color: 'primary.contrastText',
            }}
          >
            <Typography variant="h6">{tactic.tactic_name}</Typography>
            <Typography variant="caption">
              {tactic.tactic_id} • {tactic.techniques.filter((t) => t.is_covered).length} /{' '}
              {tactic.techniques.length} covered
            </Typography>
          </Box>

          {/* Technique Rows */}
          <Box sx={{ p: 2 }}>
            {tactic.techniques.map((technique) => (
              <Box
                key={technique.technique_id}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 2,
                  p: 1.5,
                  mb: 1,
                  bgcolor: 'background.default',
                  borderRadius: 1,
                  borderLeft: 4,
                  borderLeftColor: technique.is_covered ? 'success.main' : 'error.main',
                }}
              >
                {technique.is_covered ? (
                  <CheckCircleIcon sx={{ color: 'success.main' }} />
                ) : (
                  <CancelIcon sx={{ color: 'error.main' }} />
                )}

                <Box sx={{ flexGrow: 1 }}>
                  <Typography variant="body2" fontWeight="medium">
                    {technique.technique_id}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {technique.technique_name}
                  </Typography>
                </Box>

                <Box sx={{ textAlign: 'right' }}>
                  <Typography
                    variant="body2"
                    color={technique.is_covered ? 'success.main' : 'error.main'}
                    fontWeight="medium"
                  >
                    {technique.is_covered
                      ? `${technique.rule_count} rule${technique.rule_count !== 1 ? 's' : ''}`
                      : 'No coverage'}
                  </Typography>
                </Box>
              </Box>
            ))}
          </Box>
        </Paper>
      ))}
    </Box>
  );
}

export default CoverageMatrix;
