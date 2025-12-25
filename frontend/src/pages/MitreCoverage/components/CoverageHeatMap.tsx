import { useState, useMemo } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tooltip,
  CircularProgress,
  Alert,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { TrendingUp as TrendingUpIcon } from '@mui/icons-material';
import { apiService } from '../../../services/api';
import MitreService, { CoverageMatrix as CoverageMatrixData, CoverageReport } from '../../../services/mitreService';

type ColorScale = 'density' | 'coverage';

function CoverageHeatMap() {
  const [colorScale, setColorScale] = useState<ColorScale>('density');

  const mitreService = new MitreService((apiService as any).api);

  const {
    data: matrixData,
    isLoading: matrixLoading,
    error: matrixError,
  } = useQuery<CoverageMatrixData>({
    queryKey: ['mitre-coverage-matrix'],
    queryFn: () => mitreService.getCoverageMatrix(),
    staleTime: 60000,
  });

  const {
    data: coverageData,
    isLoading: coverageLoading,
    error: coverageError,
  } = useQuery<CoverageReport>({
    queryKey: ['mitre-coverage'],
    queryFn: () => mitreService.getCoverageReport(),
    staleTime: 60000,
  });

  const isLoading = matrixLoading || coverageLoading;
  const error = matrixError || coverageError;

  // Calculate statistics
  const stats = useMemo(() => {
    if (!matrixData) return null;

    let totalTechniques = 0;
    let coveredTechniques = 0;
    let totalRules = 0;
    let maxRules = 0;
    const ruleCounts: number[] = [];

    matrixData.tactics.forEach((tactic) => {
      tactic.techniques.forEach((tech) => {
        totalTechniques++;
        if (tech.is_covered) coveredTechniques++;
        totalRules += tech.rule_count;
        maxRules = Math.max(maxRules, tech.rule_count);
        if (tech.rule_count > 0) ruleCounts.push(tech.rule_count);
      });
    });

    const avgRulesPerCoveredTech = ruleCounts.length > 0
      ? ruleCounts.reduce((sum, count) => sum + count, 0) / ruleCounts.length
      : 0;

    return {
      totalTechniques,
      coveredTechniques,
      totalRules,
      maxRules,
      avgRulesPerCoveredTech,
    };
  }, [matrixData]);

  // Get color based on rule count
  const getRuleColor = (ruleCount: number): string => {
    if (ruleCount === 0) {
      return '#d32f2f'; // Red - no coverage
    } else if (ruleCount <= 2) {
      return '#f57c00'; // Orange - minimal coverage
    } else if (ruleCount <= 5) {
      return '#fbc02d'; // Yellow - low coverage
    } else if (ruleCount <= 10) {
      return '#9ccc65'; // Light green - moderate coverage
    } else if (ruleCount <= 20) {
      return '#66bb6a'; // Medium green - good coverage
    } else {
      return '#2e7d32'; // Dark green - excellent coverage
    }
  };

  // Get color based on coverage intensity (normalized)
  const getIntensityColor = (ruleCount: number): string => {
    if (!stats || stats.maxRules === 0) return '#d32f2f';

    const intensity = ruleCount / stats.maxRules;

    if (intensity === 0) {
      return '#d32f2f'; // Red - no coverage
    } else if (intensity < 0.2) {
      return '#ff6f00'; // Deep orange
    } else if (intensity < 0.4) {
      return '#fbc02d'; // Amber
    } else if (intensity < 0.6) {
      return '#c0ca33'; // Lime
    } else if (intensity < 0.8) {
      return '#7cb342'; // Light green
    } else {
      return '#2e7d32'; // Dark green
    }
  };

  const getColor = (ruleCount: number): string => {
    return colorScale === 'density' ? getRuleColor(ruleCount) : getIntensityColor(ruleCount);
  };

  // Get tactic header color (same as coverage matrix)
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
        Failed to load coverage heat map. Please try again.
      </Alert>
    );
  }

  if (!matrixData || !stats) {
    return (
      <Alert severity="warning">
        No heat map data available.
      </Alert>
    );
  }

  return (
    <Box>
      {/* Controls */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <TrendingUpIcon sx={{ color: 'primary.main', fontSize: 28 }} />
          <Typography variant="h6">Rule Density Heat Map</Typography>
        </Box>

        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Color Scale</InputLabel>
          <Select
            value={colorScale}
            onChange={(e) => setColorScale(e.target.value as ColorScale)}
            label="Color Scale"
          >
            <MenuItem value="density">Absolute Density</MenuItem>
            <MenuItem value="coverage">Relative Intensity</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {/* Statistics Summary */}
      <Paper sx={{ p: 2, mb: 3, bgcolor: 'background.default' }}>
        <Box sx={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Total Unique Rules
            </Typography>
            <Typography variant="h6" fontWeight="bold">
              {coverageData?.total_unique_rules || 0}
            </Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Total Detection Mappings
            </Typography>
            <Typography variant="h6" fontWeight="bold">
              {stats.totalRules}
            </Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Covered Techniques
            </Typography>
            <Typography variant="h6" fontWeight="bold">
              {stats.coveredTechniques} / {stats.totalTechniques}
            </Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Max Rules per Technique
            </Typography>
            <Typography variant="h6" fontWeight="bold">
              {stats.maxRules}
            </Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">
              Avg Rules per Covered Technique
            </Typography>
            <Typography variant="h6" fontWeight="bold">
              {stats.avgRulesPerCoveredTech.toFixed(1)}
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* Legend */}
      <Paper sx={{ p: 2, mb: 3, bgcolor: 'background.default' }}>
        <Typography variant="body2" fontWeight="medium" sx={{ mb: 1 }}>
          {colorScale === 'density' ? 'Rule Density Scale:' : 'Coverage Intensity Scale:'}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          {colorScale === 'density' ? (
            <>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#d32f2f', borderRadius: 0.5 }} />
                <Typography variant="caption">0 rules</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#f57c00', borderRadius: 0.5 }} />
                <Typography variant="caption">1-2 rules</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#fbc02d', borderRadius: 0.5 }} />
                <Typography variant="caption">3-5 rules</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#9ccc65', borderRadius: 0.5 }} />
                <Typography variant="caption">6-10 rules</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#66bb6a', borderRadius: 0.5 }} />
                <Typography variant="caption">11-20 rules</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#2e7d32', borderRadius: 0.5 }} />
                <Typography variant="caption">20+ rules</Typography>
              </Box>
            </>
          ) : (
            <>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#d32f2f', borderRadius: 0.5 }} />
                <Typography variant="caption">No coverage</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#ff6f00', borderRadius: 0.5 }} />
                <Typography variant="caption">Low</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#fbc02d', borderRadius: 0.5 }} />
                <Typography variant="caption">Below avg</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#c0ca33', borderRadius: 0.5 }} />
                <Typography variant="caption">Average</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#7cb342', borderRadius: 0.5 }} />
                <Typography variant="caption">Above avg</Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Box sx={{ width: 24, height: 24, bgcolor: '#2e7d32', borderRadius: 0.5 }} />
                <Typography variant="caption">Maximum</Typography>
              </Box>
            </>
          )}
        </Box>
      </Paper>

      {/* Heat Map Grid */}
      <Box
        sx={{
          overflowY: 'auto',
          maxHeight: '35vh',
        }}
      >
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
          {matrixData.tactics.map((tactic) => {
            const tacticRuleCount = tactic.techniques.reduce(
              (sum, tech) => sum + tech.rule_count,
              0
            );
            const tacticCoverage = tactic.techniques.filter((t) => t.is_covered).length;

            return (
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
                  <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
                    <Chip
                      label={`${tacticRuleCount} rules`}
                      size="small"
                      sx={{ bgcolor: 'rgba(255,255,255,0.2)', color: 'white', height: 20 }}
                    />
                    <Chip
                      label={`${tacticCoverage}/${tactic.techniques.length}`}
                      size="small"
                      sx={{ bgcolor: 'rgba(255,255,255,0.2)', color: 'white', height: 20 }}
                    />
                  </Box>
                </Box>

                {/* Technique Heat Map Cells */}
                <Box sx={{ p: 1, flexGrow: 1 }}>
                  {tactic.techniques.map((technique) => {
                    const color = getColor(technique.rule_count);

                    return (
                      <Tooltip
                        key={technique.technique_id}
                        title={
                          <Box>
                            <Typography variant="body2" fontWeight="bold">
                              {technique.technique_id}
                            </Typography>
                            <Typography variant="body2">{technique.technique_name}</Typography>
                            <Typography variant="caption" sx={{ mt: 0.5, display: 'block' }}>
                              {technique.rule_count === 0
                                ? 'No coverage'
                                : `${technique.rule_count} rule${technique.rule_count !== 1 ? 's' : ''}`}
                            </Typography>
                          </Box>
                        }
                        placement="right"
                      >
                        <Box
                          sx={{
                            width: '100%',
                            height: 50,
                            mb: 0.5,
                            bgcolor: color,
                            borderRadius: 1,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            cursor: 'pointer',
                            transition: 'transform 0.2s, box-shadow 0.2s',
                            border: '1px solid rgba(0,0,0,0.1)',
                            '&:hover': {
                              transform: 'scale(1.05)',
                              boxShadow: 2,
                            },
                          }}
                        >
                          <Typography
                            variant="caption"
                            sx={{
                              color: 'white',
                              fontWeight: 'bold',
                              textShadow: '0 1px 2px rgba(0,0,0,0.3)',
                            }}
                          >
                            {technique.rule_count}
                          </Typography>
                        </Box>
                      </Tooltip>
                    );
                  })}
                </Box>
              </Paper>
            );
          })}
        </Box>
      </Box>
    </Box>
  );
}

export default CoverageHeatMap;
