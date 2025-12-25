import { Box, Paper, Typography, LinearProgress, Grid } from '@mui/material';
import { CoverageReport } from '../../../services/mitreService';
import {
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Analytics as AnalyticsIcon,
} from '@mui/icons-material';

interface CoverageOverviewProps {
  coverageData: CoverageReport;
}

function CoverageOverview({ coverageData }: CoverageOverviewProps) {
  const {
    total_techniques,
    covered_techniques,
    coverage_percent,
  } = coverageData;

  const gapCount = total_techniques - covered_techniques;

  // Determine color based on coverage percentage
  const getCoverageColor = (percent: number) => {
    if (percent >= 70) return 'success';
    if (percent >= 40) return 'warning';
    return 'error';
  };

  const coverageColor = getCoverageColor(coverage_percent);

  return (
    <Grid container spacing={3}>
      {/* Overall Coverage Card */}
      <Grid item xs={12} md={4}>
        <Paper sx={{ p: 3, height: '100%' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <AnalyticsIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6">Overall Coverage</Typography>
          </Box>

          <Typography variant="h3" sx={{ mb: 1, color: `${coverageColor}.main` }}>
            {coverage_percent.toFixed(1)}%
          </Typography>

          <LinearProgress
            variant="determinate"
            value={coverage_percent}
            color={coverageColor}
            sx={{ mb: 2, height: 8, borderRadius: 4 }}
          />

          <Typography variant="body2" color="text.secondary">
            Detection coverage across MITRE ATT&CK framework
          </Typography>
        </Paper>
      </Grid>

      {/* Covered Techniques Card */}
      <Grid item xs={12} md={4}>
        <Paper sx={{ p: 3, height: '100%' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <CheckCircleIcon sx={{ mr: 1, color: 'success.main' }} />
            <Typography variant="h6">Covered Techniques</Typography>
          </Box>

          <Typography variant="h3" sx={{ mb: 1 }}>
            {covered_techniques} / {total_techniques}
          </Typography>

          <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
            <Box
              sx={{
                flex: covered_techniques,
                height: 8,
                bgcolor: 'success.main',
                borderRadius: 4,
              }}
            />
            <Box
              sx={{
                flex: gapCount,
                height: 8,
                bgcolor: 'grey.700',
                borderRadius: 4,
              }}
            />
          </Box>

          <Typography variant="body2" color="text.secondary">
            Techniques with at least one detection rule
          </Typography>
        </Paper>
      </Grid>

      {/* Gap Count Card */}
      <Grid item xs={12} md={4}>
        <Paper sx={{ p: 3, height: '100%' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <WarningIcon sx={{ mr: 1, color: 'warning.main' }} />
            <Typography variant="h6">Coverage Gaps</Typography>
          </Box>

          <Typography variant="h3" sx={{ mb: 1, color: 'warning.main' }}>
            {gapCount}
          </Typography>

          <Box sx={{ height: 8, mb: 2 }} /> {/* Spacer for alignment */}

          <Typography variant="body2" color="text.secondary">
            Techniques without any detection coverage
          </Typography>
        </Paper>
      </Grid>
    </Grid>
  );
}

export default CoverageOverview;
