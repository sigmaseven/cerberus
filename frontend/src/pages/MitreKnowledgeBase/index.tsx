import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Grid,
  Chip,
  Button,
  CircularProgress,
  Alert,
  InputAdornment,
  Stack,
  Paper,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Search as SearchIcon,
  ViewModule as MatrixIcon,
  Assessment as CoverageIcon,
  ArrowForward as ArrowForwardIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { MitreTechnique, MitreTactic } from '../../services/mitreService';
import apiService from '../../services/api';
import MitreTechniqueModal from '../../components/MitreTechniqueModal';

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
      id={`mitre-tabpanel-${index}`}
      aria-labelledby={`mitre-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

const MitreKnowledgeBase: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [tabValue, setTabValue] = useState(0);
  const [statistics, setStatistics] = useState<any>(null);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string | null>(null);

  // Tactics state
  const [tactics, setTactics] = useState<MitreTactic[]>([]);
  const [filteredTactics, setFilteredTactics] = useState<MitreTactic[]>([]);
  const [tacticsPage, setTacticsPage] = useState(0);
  const [tacticsRowsPerPage, setTacticsRowsPerPage] = useState(10);

  // Techniques state
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [techniquesTotal, setTechniquesTotal] = useState(0);
  const [techniquesPage, setTechniquesPage] = useState(0);
  const [techniquesRowsPerPage, setTechniquesRowsPerPage] = useState(10);

  // Threat Groups state
  const [groups, setGroups] = useState<any[]>([]);
  const [groupsTotal, setGroupsTotal] = useState(0);
  const [groupsPage, setGroupsPage] = useState(0);
  const [groupsRowsPerPage, setGroupsRowsPerPage] = useState(10);

  // Load initial data
  useEffect(() => {
    loadStatistics();
  }, []);

  // Load data when tab changes
  useEffect(() => {
    if (tabValue === 0 && tactics.length === 0) {
      loadTactics();
    } else if (tabValue === 1) {
      loadTechniques();
    } else if (tabValue === 2 && groups.length === 0) {
      loadGroups();
    }
  }, [tabValue]);

  // Load techniques when pagination changes
  useEffect(() => {
    if (tabValue === 1) {
      loadTechniques();
    }
  }, [techniquesPage, techniquesRowsPerPage]);

  // Load groups when pagination changes
  useEffect(() => {
    if (tabValue === 2) {
      loadGroups();
    }
  }, [groupsPage, groupsRowsPerPage]);

  // Filter tactics when search changes
  useEffect(() => {
    if (!tactics) return;
    if (searchQuery && tabValue === 0) {
      const query = searchQuery.toLowerCase();
      const filtered = tactics.filter(
        (tactic) =>
          tactic.name.toLowerCase().includes(query) ||
          tactic.id.toLowerCase().includes(query) ||
          tactic.description.toLowerCase().includes(query)
      );
      setFilteredTactics(filtered);
    } else {
      setFilteredTactics(tactics);
    }
  }, [searchQuery, tactics, tabValue]);

  const loadStatistics = async () => {
    try {
      const stats = await apiService.mitre.getStatistics();
      setStatistics(stats);
    } catch (err) {
      console.error('Failed to load statistics:', err);
    }
  };

  const loadTactics = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.mitre.getTactics();
      setTactics(data || []);
      setFilteredTactics(data || []);
    } catch (err) {
      console.error('Failed to load tactics:', err);
      setError('Failed to load MITRE tactics. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const loadTechniques = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.mitre.getTechniques({
        limit: techniquesRowsPerPage,
        offset: techniquesPage * techniquesRowsPerPage,
      });
      setTechniques(data?.items || []);
      setTechniquesTotal(data?.total || 0);
    } catch (err) {
      console.error('Failed to load techniques:', err);
      setError('Failed to load MITRE techniques. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const loadGroups = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.mitre.getGroups({
        limit: groupsRowsPerPage,
        offset: groupsPage * groupsRowsPerPage,
      });
      setGroups(data?.groups || []);
      setGroupsTotal(data?.total || 0);
    } catch (err) {
      console.error('Failed to load threat groups:', err);
      setError('Failed to load threat groups. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
    setSearchQuery('');
    setError(null);
  };

  const handleTacticsChangePage = (event: unknown, newPage: number) => {
    setTacticsPage(newPage);
  };

  const handleTacticsChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setTacticsRowsPerPage(parseInt(event.target.value, 10));
    setTacticsPage(0);
  };

  const handleTechniquesChangePage = (event: unknown, newPage: number) => {
    setTechniquesPage(newPage);
  };

  const handleTechniquesChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setTechniquesRowsPerPage(parseInt(event.target.value, 10));
    setTechniquesPage(0);
  };

  const handleGroupsChangePage = (event: unknown, newPage: number) => {
    setGroupsPage(newPage);
  };

  const handleGroupsChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setGroupsRowsPerPage(parseInt(event.target.value, 10));
    setGroupsPage(0);
  };

  const handleRefresh = () => {
    if (tabValue === 0) {
      loadTactics();
    } else if (tabValue === 1) {
      loadTechniques();
    } else if (tabValue === 2) {
      loadGroups();
    }
  };

  const handleOpenTechniqueModal = (techniqueId: string) => {
    setSelectedTechniqueId(techniqueId);
    setModalOpen(true);
  };

  const handleCloseTechniqueModal = () => {
    setModalOpen(false);
    setSelectedTechniqueId(null);
  };

  return (
    <Box>
      {/* Header */}
      <Box mb={3}>
        <Typography variant="h4" gutterBottom>
          MITRE ATT&CK Knowledge Base
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Explore tactics, techniques, and threat groups from the MITRE ATT&CK framework
        </Typography>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Statistics Cards */}
      {statistics && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid key="stat-tactics" xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h4" color="primary">
                {statistics.total_tactics || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Tactics
              </Typography>
            </Paper>
          </Grid>
          <Grid key="stat-techniques" xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h4" color="primary">
                {statistics.total_techniques || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Techniques
              </Typography>
            </Paper>
          </Grid>
          <Grid key="stat-groups" xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h4" color="primary">
                {statistics.total_groups || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Threat Groups
              </Typography>
            </Paper>
          </Grid>
          <Grid key="stat-version" xs={12} sm={6} md={3}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h4" color="primary">
                {statistics.framework_version || 'N/A'}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Framework Version
              </Typography>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Quick Actions */}
      <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
        <Button
          variant="outlined"
          startIcon={<MatrixIcon />}
          onClick={() => navigate('/mitre/matrix')}
        >
          ATT&CK Matrix
        </Button>
        <Button
          variant="outlined"
          startIcon={<CoverageIcon />}
          onClick={() => navigate('/mitre/coverage')}
        >
          Coverage Dashboard
        </Button>
      </Stack>

      {/* Main Content Card */}
      <Card>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={handleTabChange}>
            <Tab label={`Tactics (${statistics?.total_tactics || 0})`} />
            <Tab label={`Techniques (${statistics?.total_techniques || 0})`} />
            <Tab label={`Threat Groups (${statistics?.total_groups || 0})`} />
          </Tabs>
        </Box>

        {/* Search and Actions */}
        <CardContent>
          <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
            <TextField
              fullWidth
              placeholder={`Search ${tabValue === 0 ? 'tactics' : tabValue === 1 ? 'techniques' : 'threat groups'}...`}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
              size="small"
            />
            <Tooltip title="Refresh">
              <IconButton onClick={handleRefresh} color="primary">
                <RefreshIcon />
              </IconButton>
            </Tooltip>
          </Stack>

          {/* Tactics Tab */}
          <TabPanel value={tabValue} index={0}>
            {loading ? (
              <Box display="flex" justifyContent="center" py={4}>
                <CircularProgress />
              </Box>
            ) : (
              <>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>ID</TableCell>
                        <TableCell>Name</TableCell>
                        <TableCell>Description</TableCell>
                        <TableCell align="center">Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {filteredTactics
                        .slice(tacticsPage * tacticsRowsPerPage, tacticsPage * tacticsRowsPerPage + tacticsRowsPerPage)
                        .map((tactic) => (
                          <TableRow key={tactic.id} hover>
                            <TableCell>
                              <Chip label={tactic.id} size="small" color="primary" variant="outlined" />
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" fontWeight="medium">
                                {tactic.name}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" color="text.secondary">
                                {tactic.description?.substring(0, 150)}
                                {tactic.description?.length > 150 ? '...' : ''}
                              </Typography>
                            </TableCell>
                            <TableCell align="center">
                              <Tooltip title="Tactic detail page coming soon">
                                <span>
                                  <IconButton
                                    size="small"
                                    disabled
                                    color="primary"
                                  >
                                    <ArrowForwardIcon fontSize="small" />
                                  </IconButton>
                                </span>
                              </Tooltip>
                            </TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                <TablePagination
                  rowsPerPageOptions={[5, 10, 25, 50]}
                  component="div"
                  count={filteredTactics.length}
                  rowsPerPage={tacticsRowsPerPage}
                  page={tacticsPage}
                  onPageChange={handleTacticsChangePage}
                  onRowsPerPageChange={handleTacticsChangeRowsPerPage}
                />
              </>
            )}
          </TabPanel>

          {/* Techniques Tab */}
          <TabPanel value={tabValue} index={1}>
            {loading ? (
              <Box display="flex" justifyContent="center" py={4}>
                <CircularProgress />
              </Box>
            ) : (
              <>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>ID</TableCell>
                        <TableCell>Name</TableCell>
                        <TableCell>Tactics</TableCell>
                        <TableCell>Platforms</TableCell>
                        <TableCell align="center">Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {techniques.map((technique) => (
                        <TableRow key={technique.id} hover>
                          <TableCell>
                            <Chip label={technique.id} size="small" color="primary" variant="outlined" />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" fontWeight="medium">
                              {technique.name}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                              {technique.tactics?.slice(0, 3).map((tacticId) => (
                                <Chip key={tacticId} label={tacticId} size="small" variant="outlined" />
                              ))}
                              {technique.tactics && technique.tactics.length > 3 && (
                                <Chip label={`+${technique.tactics.length - 3}`} size="small" />
                              )}
                            </Stack>
                          </TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                              {technique.platforms?.slice(0, 2).map((platform) => (
                                <Chip key={platform} label={platform} size="small" variant="outlined" />
                              ))}
                              {technique.platforms && technique.platforms.length > 2 && (
                                <Chip label={`+${technique.platforms.length - 2}`} size="small" />
                              )}
                            </Stack>
                          </TableCell>
                          <TableCell align="center">
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                handleOpenTechniqueModal(technique.id);
                              }}
                              color="primary"
                            >
                              <ArrowForwardIcon fontSize="small" />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                <TablePagination
                  rowsPerPageOptions={[5, 10, 25, 50, 100]}
                  component="div"
                  count={techniquesTotal}
                  rowsPerPage={techniquesRowsPerPage}
                  page={techniquesPage}
                  onPageChange={handleTechniquesChangePage}
                  onRowsPerPageChange={handleTechniquesChangeRowsPerPage}
                />
              </>
            )}
          </TabPanel>

          {/* Threat Groups Tab */}
          <TabPanel value={tabValue} index={2}>
            {loading ? (
              <Box display="flex" justifyContent="center" py={4}>
                <CircularProgress />
              </Box>
            ) : (
              <>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>ID</TableCell>
                        <TableCell>Name</TableCell>
                        <TableCell>Aliases</TableCell>
                        <TableCell>Description</TableCell>
                        <TableCell align="center">Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {groups.map((group) => (
                        <TableRow key={group.id} hover>
                          <TableCell>
                            <Chip label={group.id} size="small" color="secondary" variant="outlined" />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" fontWeight="medium">
                              {group.name}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {group.aliases && group.aliases.length > 0 ? (
                              <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                                {group.aliases.slice(0, 2).map((alias: string) => (
                                  <Chip key={alias} label={alias} size="small" />
                                ))}
                                {group.aliases.length > 2 && (
                                  <Chip label={`+${group.aliases.length - 2}`} size="small" />
                                )}
                              </Stack>
                            ) : (
                              <Typography variant="body2" color="text.secondary">
                                -
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" color="text.secondary">
                              {group.description?.substring(0, 100)}
                              {group.description?.length > 100 ? '...' : ''}
                            </Typography>
                          </TableCell>
                          <TableCell align="center">
                            <Tooltip title="Group detail page coming soon">
                              <span>
                                <IconButton
                                  size="small"
                                  disabled
                                  color="primary"
                                >
                                  <ArrowForwardIcon fontSize="small" />
                                </IconButton>
                              </span>
                            </Tooltip>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                <TablePagination
                  rowsPerPageOptions={[5, 10, 25, 50]}
                  component="div"
                  count={groupsTotal}
                  rowsPerPage={groupsRowsPerPage}
                  page={groupsPage}
                  onPageChange={handleGroupsChangePage}
                  onRowsPerPageChange={handleGroupsChangeRowsPerPage}
                />
              </>
            )}
          </TabPanel>
        </CardContent>
      </Card>

      {/* Technique Detail Modal */}
      <MitreTechniqueModal
        open={modalOpen}
        techniqueId={selectedTechniqueId}
        onClose={handleCloseTechniqueModal}
      />
    </Box>
  );
};

export default MitreKnowledgeBase;
