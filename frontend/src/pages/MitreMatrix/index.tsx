import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Alert,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tooltip,
  Paper,
  Stack,
  Chip,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  ZoomIn as ZoomInIcon,
  ZoomOut as ZoomOutIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { MatrixView } from '../../services/mitreService';
import apiService from '../../services/api';

const MitreMatrix: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [matrix, setMatrix] = useState<MatrixView | null>(null);
  const [platform, setPlatform] = useState<string>('');
  const [zoom, setZoom] = useState<number>(1);

  useEffect(() => {
    loadMatrix(platform);
  }, [platform]);

  const loadMatrix = async (platformFilter: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.mitre.getMatrix(platformFilter || undefined);
      setMatrix(data || null);
    } catch (err) {
      console.error('Failed to load matrix:', err);
      setError('Failed to load ATT&CK matrix. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const getCoverageColor = (coverage: string): string => {
    switch (coverage) {
      case 'full':
        return '#4caf50'; // Green
      case 'partial':
        return '#ff9800'; // Orange
      case 'none':
      default:
        return '#f44336'; // Red
    }
  };

  const getCoverageLabel = (coverage: string): string => {
    switch (coverage) {
      case 'full':
        return 'Full Coverage (2+ rules)';
      case 'partial':
        return 'Partial Coverage (1 rule)';
      case 'none':
      default:
        return 'No Coverage';
    }
  };

  const handleZoomIn = () => {
    setZoom((prev) => Math.min(prev + 0.1, 2));
  };

  const handleZoomOut = () => {
    setZoom((prev) => Math.max(prev - 0.1, 0.5));
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box mb={3} display="flex" justifyContent="space-between" alignItems="center">
        <Box>
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/mitre')} sx={{ mb: 2 }}>
            Back to Knowledge Base
          </Button>
          <Typography variant="h4" gutterBottom>
            ATT&CK Matrix
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Visual representation of detection coverage across tactics and techniques
          </Typography>
        </Box>
        <Stack direction="row" spacing={2}>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Platform</InputLabel>
            <Select value={platform} onChange={(e) => setPlatform(e.target.value)} label="Platform">
              <MenuItem value="">All Platforms</MenuItem>
              <MenuItem value="Windows">Windows</MenuItem>
              <MenuItem value="Linux">Linux</MenuItem>
              <MenuItem value="macOS">macOS</MenuItem>
              <MenuItem value="Cloud">Cloud</MenuItem>
            </Select>
          </FormControl>
          <Button startIcon={<ZoomInIcon />} onClick={handleZoomIn} disabled={zoom >= 2}>
            Zoom In
          </Button>
          <Button startIcon={<ZoomOutIcon />} onClick={handleZoomOut} disabled={zoom <= 0.5}>
            Zoom Out
          </Button>
        </Stack>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Legend */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Coverage Legend:
        </Typography>
        <Stack direction="row" spacing={2}>
          <Chip
            key="legend-full"
            label="Full Coverage (2+ rules)"
            sx={{ backgroundColor: getCoverageColor('full'), color: 'white' }}
            size="small"
          />
          <Chip
            key="legend-partial"
            label="Partial Coverage (1 rule)"
            sx={{ backgroundColor: getCoverageColor('partial'), color: 'white' }}
            size="small"
          />
          <Chip
            key="legend-none"
            label="No Coverage"
            sx={{ backgroundColor: getCoverageColor('none'), color: 'white' }}
            size="small"
          />
        </Stack>
      </Paper>

      {/* Matrix */}
      {matrix && (
        <Box
          sx={{
            overflowX: 'auto',
            overflowY: 'auto',
            maxHeight: 'calc(100vh - 300px)',
            border: 1,
            borderColor: 'divider',
            borderRadius: 1,
          }}
        >
          <Box
            sx={{
              display: 'inline-flex',
              gap: 1,
              p: 2,
              minWidth: '100%',
              transform: `scale(${zoom})`,
              transformOrigin: 'top left',
            }}
          >
            {matrix?.tactics?.map((tactic) => (
              <Box
                key={tactic.id}
                sx={{
                  minWidth: 180,
                  maxWidth: 180,
                }}
              >
                {/* Tactic Header */}
                <Paper
                  sx={{
                    p: 1.5,
                    mb: 1,
                    backgroundColor: 'primary.main',
                    color: 'white',
                    textAlign: 'center',
                    minHeight: 60,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Typography variant="subtitle2" sx={{ fontWeight: 'bold', fontSize: '0.8rem' }}>
                    {tactic.name}
                  </Typography>
                </Paper>

                {/* Techniques */}
                <Stack spacing={0.5}>
                  {tactic.techniques.map((technique) => (
                    <Tooltip
                      key={technique.id}
                      title={
                        <Box>
                          <Typography variant="subtitle2">{technique.name}</Typography>
                          <Typography variant="caption" display="block">
                            {technique.id}
                          </Typography>
                          <Typography variant="caption" display="block">
                            {technique.rule_count} rule(s)
                          </Typography>
                          <Typography variant="caption" display="block">
                            {getCoverageLabel(technique.coverage)}
                          </Typography>
                        </Box>
                      }
                      arrow
                    >
                      <Paper
                        onClick={() => navigate(`/mitre/techniques/${technique.id}`)}
                        sx={{
                          p: 1,
                          cursor: 'pointer',
                          backgroundColor: getCoverageColor(technique.coverage),
                          color: 'white',
                          transition: 'all 0.2s',
                          minHeight: 50,
                          display: 'flex',
                          flexDirection: 'column',
                          justifyContent: 'center',
                          '&:hover': {
                            transform: 'scale(1.05)',
                            boxShadow: 4,
                            zIndex: 10,
                          },
                        }}
                      >
                        <Typography variant="caption" sx={{ fontSize: '0.65rem', fontWeight: 'medium' }}>
                          {technique.id}
                        </Typography>
                        <Typography
                          variant="caption"
                          sx={{
                            fontSize: '0.7rem',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            display: '-webkit-box',
                            WebkitLineClamp: 2,
                            WebkitBoxOrient: 'vertical',
                            lineHeight: 1.2,
                          }}
                        >
                          {technique.name}
                        </Typography>
                      </Paper>
                    </Tooltip>
                  ))}
                </Stack>
              </Box>
            ))}
          </Box>
        </Box>
      )}

      {!matrix && !loading && !error && (
        <Box textAlign="center" py={8}>
          <Typography variant="h6" color="text.secondary">
            No matrix data available
          </Typography>
        </Box>
      )}
    </Box>
  );
};

export default MitreMatrix;
