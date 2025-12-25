import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  List,
  Typography,
  Divider,
  IconButton,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Warning as AlertsIcon,
  Event as EventsIcon,
  Search as SearchIcon,
  Rule as RulesIcon,
  Link as CorrelationRulesIcon,
  Settings as ActionsIcon,
  Router as ListenersIcon,
  AccountCircle as AccountIcon,
  Brightness4 as ThemeIcon,
  Transform as FieldMappingsIcon,
  Gavel as InvestigationsIcon,
  Security as MitreIcon,
  GridOn as MitreMatrixIcon,
  MenuBook as MitreKBIcon,
  Psychology as MLIcon,
  Settings as SettingsIcon,
} from '@mui/icons-material';
import { useUiStore } from '../../stores/ui';
import { useAuth } from '../../contexts/AuthContext';
import { hasPermission, getRoleDisplayName, Permission } from '../../utils/permissions';
import { Chip } from '@mui/material';

const drawerWidth = 280;

interface NavigationItem {
  text: string;
  icon: React.ReactNode;
  path: string;
  permission?: Permission; // TASK 3.6: Optional permission requirement
}

const navigationItems: NavigationItem[] = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/dashboard' },
  { text: 'Alerts', icon: <AlertsIcon />, path: '/alerts' },
  { text: 'Events', icon: <EventsIcon />, path: '/events' },
  { text: 'Event Search', icon: <SearchIcon />, path: '/event-search' },
  { text: 'Rules', icon: <RulesIcon />, path: '/rules' },
  { text: 'Correlation Rules', icon: <CorrelationRulesIcon />, path: '/correlation-rules' },
  { text: 'Actions', icon: <ActionsIcon />, path: '/actions' },
  { text: 'Listeners', icon: <ListenersIcon />, path: '/listeners', permission: 'read:listeners' },
  { text: 'Field Mappings', icon: <FieldMappingsIcon />, path: '/field-mappings' },
  { text: 'Investigations', icon: <InvestigationsIcon />, path: '/investigations' },
  { text: 'MITRE Coverage', icon: <MitreIcon />, path: '/mitre-coverage' },
  { text: 'MITRE Matrix', icon: <MitreMatrixIcon />, path: '/mitre-matrix' },
  { text: 'MITRE Knowledge Base', icon: <MitreKBIcon />, path: '/mitre-kb' },
  { text: 'ML', icon: <MLIcon />, path: '/ml' },
  // TASK 3.6: User Management requires write:users permission
  { text: 'User Management', icon: <AccountIcon />, path: '/users', permission: 'write:users' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
];

function Layout({ page }: { page: React.ReactNode }) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const { sidebarOpen, setSidebarOpen } = useUiStore();
  const { permissions, roleName, authEnabled, username } = useAuth(); // TASK 3.6: Get permissions

  const handleDrawerToggle = () => {
    setSidebarOpen(!sidebarOpen);
  };

  // TASK 3.6: Filter navigation items based on permissions
  const visibleNavigationItems = navigationItems.filter((item) => {
    // If auth is disabled, show all items
    if (!authEnabled) {
      return true;
    }
    // If no permission required, show item
    if (!item.permission) {
      return true;
    }
    // Check if user has required permission
    return hasPermission(permissions, item.permission);
  });

  const drawer = (
    <div>
      <Toolbar>
        <Typography variant="h6" noWrap component="div">
          Cerberus SIEM
        </Typography>
      </Toolbar>
      <Divider />
      <List>
        {visibleNavigationItems.map((item) => (
          <ListItem key={item.text} disablePadding>
            <ListItemButton component={Link} to={item.path}>
              <ListItemIcon>
                {item.icon}
              </ListItemIcon>
              <ListItemText primary={item.text} />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </div>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          ml: { sm: `${drawerWidth}px` },
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { sm: 'none' } }}
          >
            <MenuIcon />
          </IconButton>
          <Typography
            variant="h6"
            noWrap
            component="div"
            sx={{
              flexGrow: 1,
              display: { xs: 'none', sm: 'block' },
              fontSize: { xs: '1rem', sm: '1.25rem' }
            }}
          >
            Cerberus SIEM
          </Typography>
          <Typography
            variant="h6"
            noWrap
            component="div"
            sx={{
              flexGrow: 1,
              display: { xs: 'block', sm: 'none' },
              fontSize: '1.1rem'
            }}
          >
            Cerberus
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
            {/* TASK 3.6: Display user role badge if authenticated */}
            {authEnabled && roleName && (
              <Chip
                label={getRoleDisplayName(roleName)}
                size="small"
                color="default"
                sx={{ color: 'inherit', borderColor: 'rgba(255, 255, 255, 0.3)' }}
                variant="outlined"
              />
            )}
            {authEnabled && username && (
              <Typography variant="body2" sx={{ display: { xs: 'none', sm: 'block' } }}>
                {username}
              </Typography>
            )}
            <IconButton color="inherit" size="small">
              <ThemeIcon />
            </IconButton>
            <IconButton color="inherit" size="small">
              <AccountIcon />
            </IconButton>
          </Box>
        </Toolbar>
      </AppBar>
      <Box
        component="nav"
        sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
        aria-label="navigation menu"
      >
        <Drawer
          variant="temporary"
          open={sidebarOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true, // Better open performance on mobile.
          }}
          sx={{
            display: { xs: 'block', sm: 'none' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', sm: 'block' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: { xs: 2, sm: 3 },
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          minHeight: '100vh',
        }}
      >
        <Toolbar />
        {page}
      </Box>
    </Box>
  );
}

export default Layout;