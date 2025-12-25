import { useState, useMemo } from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Typography,
  Chip,
  TextField,
  InputAdornment,
  Link,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tooltip,
  IconButton,
} from '@mui/material';
import {
  Search as SearchIcon,
  OpenInNew as OpenInNewIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { CoverageReport, CoverageGap } from '../../../services/mitreService';

interface GapAnalysisTableProps {
  coverageData: CoverageReport;
}

type SortField = 'technique_id' | 'technique_name' | 'tactic';
type SortOrder = 'asc' | 'desc';

function GapAnalysisTable({ coverageData }: GapAnalysisTableProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [tacticFilter, setTacticFilter] = useState('all');
  const [sortField, setSortField] = useState<SortField>('technique_id');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');

  const { coverage_gaps } = coverageData;

  // Get unique tactics for filter dropdown
  const uniqueTactics = useMemo(() => {
    const tactics = new Set<string>();
    coverage_gaps.forEach((gap) => {
      gap.tactics.forEach((tactic) => tactics.add(tactic));
    });
    return Array.from(tactics).sort();
  }, [coverage_gaps]);

  // Handle sort
  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  // Filter and sort gaps
  const filteredAndSortedGaps = useMemo(() => {
    let filtered = coverage_gaps;

    // Apply search filter
    if (searchTerm) {
      filtered = filtered.filter(
        (gap) =>
          gap.technique_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
          gap.technique_name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Apply tactic filter
    if (tacticFilter !== 'all') {
      filtered = filtered.filter((gap) => gap.tactics.includes(tacticFilter));
    }

    // Sort
    const sorted = [...filtered].sort((a, b) => {
      let comparison = 0;

      switch (sortField) {
        case 'technique_id':
          comparison = a.technique_id.localeCompare(b.technique_id);
          break;
        case 'technique_name':
          comparison = a.technique_name.localeCompare(b.technique_name);
          break;
        case 'tactic':
          comparison = a.tactics[0]?.localeCompare(b.tactics[0] || '') || 0;
          break;
      }

      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return sorted;
  }, [coverage_gaps, searchTerm, tacticFilter, sortField, sortOrder]);

  return (
    <Box>
      {/* Header with Search and Filters */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3, alignItems: 'center' }}>
        <TextField
          size="small"
          placeholder="Search techniques..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          }}
          sx={{ flexGrow: 1 }}
        />

        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Filter by Tactic</InputLabel>
          <Select
            value={tacticFilter}
            onChange={(e) => setTacticFilter(e.target.value)}
            label="Filter by Tactic"
          >
            <MenuItem value="all">All Tactics</MenuItem>
            {uniqueTactics.map((tactic) => (
              <MenuItem key={tactic} value={tactic}>
                {tactic}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>

      {/* Gap Count Alert */}
      <Paper
        sx={{
          p: 2,
          mb: 2,
          bgcolor: 'warning.light',
          color: 'warning.contrastText',
          display: 'flex',
          alignItems: 'center',
          gap: 1,
        }}
      >
        <WarningIcon />
        <Typography variant="body1">
          <strong>{filteredAndSortedGaps.length}</strong> technique(s) without detection coverage
          {searchTerm || tacticFilter !== 'all' ? ' (filtered)' : ''}
        </Typography>
      </Paper>

      {/* Gaps Table */}
      <TableContainer
        component={Paper}
        sx={{
          maxHeight: '50vh',
          overflowY: 'auto',
        }}
      >
        <Table stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell>
                <TableSortLabel
                  active={sortField === 'technique_id'}
                  direction={sortField === 'technique_id' ? sortOrder : 'asc'}
                  onClick={() => handleSort('technique_id')}
                >
                  Technique ID
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === 'technique_name'}
                  direction={sortField === 'technique_name' ? sortOrder : 'asc'}
                  onClick={() => handleSort('technique_name')}
                >
                  Technique Name
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === 'tactic'}
                  direction={sortField === 'tactic' ? sortOrder : 'asc'}
                  onClick={() => handleSort('tactic')}
                >
                  Tactics
                </TableSortLabel>
              </TableCell>
              <TableCell align="center">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredAndSortedGaps.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} align="center" sx={{ py: 4 }}>
                  <Typography variant="body2" color="text.secondary">
                    {searchTerm || tacticFilter !== 'all'
                      ? 'No gaps found matching your filters'
                      : 'No coverage gaps found - excellent detection coverage!'}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              filteredAndSortedGaps.map((gap) => (
                <TableRow
                  key={gap.technique_id}
                  sx={{
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                >
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {gap.technique_id}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">{gap.technique_name}</Typography>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {gap.tactics.map((tactic) => (
                        <Chip
                          key={tactic}
                          label={tactic}
                          size="small"
                          variant="outlined"
                          sx={{ height: 24 }}
                        />
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell align="center">
                    <Tooltip title="View on MITRE ATT&CK">
                      <IconButton
                        size="small"
                        component={Link}
                        href={`https://attack.mitre.org/techniques/${gap.technique_id}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        <OpenInNewIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Footer Stats */}
      {filteredAndSortedGaps.length > 0 && (
        <Box sx={{ mt: 2, textAlign: 'right' }}>
          <Typography variant="caption" color="text.secondary">
            Showing {filteredAndSortedGaps.length} of {coverage_gaps.length} total gaps
          </Typography>
        </Box>
      )}
    </Box>
  );
}

export default GapAnalysisTable;
