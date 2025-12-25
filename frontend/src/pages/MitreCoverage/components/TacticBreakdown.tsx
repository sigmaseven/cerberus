import { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  LinearProgress,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tooltip,
} from '@mui/material';
import { CoverageReport } from '../../../services/mitreService';

interface TacticBreakdownProps {
  coverageData: CoverageReport;
}

type SortOption = 'name' | 'coverage';

function TacticBreakdown({ coverageData }: TacticBreakdownProps) {
  const [sortBy, setSortBy] = useState<SortOption>('coverage');

  const { tactic_coverage } = coverageData;

  // Determine color based on coverage percentage
  const getCoverageColor = (percent: number) => {
    if (percent >= 70) return 'success';
    if (percent >= 40) return 'warning';
    return 'error';
  };

  // Sort tactics based on selected option
  const sortedTactics = [...tactic_coverage].sort((a, b) => {
    if (sortBy === 'coverage') {
      return b.coverage_percent - a.coverage_percent;
    } else {
      return a.tactic_name.localeCompare(b.tactic_name);
    }
  });

  return (
    <Box>
      {/* Sort Control */}
      <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}>
        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Sort By</InputLabel>
          <Select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as SortOption)}
            label="Sort By"
          >
            <MenuItem value="coverage">Coverage Percentage</MenuItem>
            <MenuItem value="name">Tactic Name</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {/* Tactic Coverage Bars */}
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          maxHeight: '50vh',
          overflowY: 'auto',
          pr: 1,
        }}
      >
        {sortedTactics.map((tactic) => {
          const coverageColor = getCoverageColor(tactic.coverage_percent);

          return (
            <Paper
              key={tactic.tactic_id}
              sx={{
                p: 2,
                transition: 'transform 0.2s, box-shadow 0.2s',
                '&:hover': {
                  transform: 'translateX(4px)',
                  boxShadow: 3,
                },
              }}
            >
              {/* Tactic Header */}
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  mb: 1,
                }}
              >
                <Tooltip title={tactic.tactic_id} placement="top">
                  <Typography variant="subtitle1" fontWeight="medium">
                    {tactic.tactic_name}
                  </Typography>
                </Tooltip>
                <Typography
                  variant="h6"
                  sx={{ color: `${coverageColor}.main`, fontWeight: 'bold' }}
                >
                  {tactic.coverage_percent.toFixed(1)}%
                </Typography>
              </Box>

              {/* Coverage Bar */}
              <LinearProgress
                variant="determinate"
                value={tactic.coverage_percent}
                color={coverageColor}
                sx={{ height: 12, borderRadius: 6, mb: 1 }}
              />

              {/* Technique Counts */}
              <Box sx={{ display: 'flex', gap: 2, justifyContent: 'space-between' }}>
                <Typography variant="caption" color="text.secondary">
                  {tactic.covered_techniques} of {tactic.total_techniques} techniques covered
                </Typography>
                {tactic.gap_count > 0 && (
                  <Typography variant="caption" sx={{ color: 'warning.main' }}>
                    {tactic.gap_count} gaps
                  </Typography>
                )}
              </Box>
            </Paper>
          );
        })}
      </Box>

      {/* Summary Stats */}
      <Paper sx={{ p: 2, mt: 3, bgcolor: 'background.default' }}>
        <Typography variant="body2" color="text.secondary">
          <strong>Total Tactics:</strong> {tactic_coverage.length} |{' '}
          <strong>Average Coverage:</strong>{' '}
          {(
            tactic_coverage.reduce((sum, t) => sum + t.coverage_percent, 0) /
            tactic_coverage.length
          ).toFixed(1)}%
        </Typography>
      </Paper>
    </Box>
  );
}

export default TacticBreakdown;
