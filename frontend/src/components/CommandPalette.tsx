import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Command } from 'cmdk';
import {
  Dialog,
  Box,
  Typography,
  Chip,
  styled,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Event as EventIcon,
  Gavel as AlertIcon,
  Rule as RuleIcon,
  CompareArrows as CorrelationIcon,
  NotificationsActive as ActionIcon,
  Sensors as ListenerIcon,
  Settings as SettingsIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  FileUpload as ImportIcon,
  FileDownload as ExportIcon,
} from '@mui/icons-material';

// Styled components for cmdk
const StyledCommand = styled(Command)`
  background: ${({ theme }) => theme.palette.background.paper};
  border-radius: 8px;
  overflow: hidden;
  box-shadow: ${({ theme }) => theme.shadows[8]};
`;

const StyledCommandInput = styled(Command.Input)`
  font-family: inherit;
  border: none;
  padding: 16px;
  font-size: 16px;
  outline: none;
  width: 100%;
  background: ${({ theme }) => theme.palette.background.paper};
  color: ${({ theme }) => theme.palette.text.primary};
  border-bottom: 1px solid ${({ theme }) => theme.palette.divider};

  &::placeholder {
    color: ${({ theme }) => theme.palette.text.secondary};
  }
`;

const StyledCommandList = styled(Command.List)`
  max-height: 400px;
  overflow-y: auto;
  padding: 8px;
`;

const StyledCommandEmpty = styled(Command.Empty)`
  padding: 32px;
  text-align: center;
  color: ${({ theme }) => theme.palette.text.secondary};
`;

const StyledCommandGroup = styled(Command.Group)`
  margin-bottom: 8px;

  &:last-child {
    margin-bottom: 0;
  }
`;

const StyledCommandGroupHeading = styled('div')`
  padding: 8px 12px;
  font-size: 12px;
  font-weight: 600;
  color: ${({ theme }) => theme.palette.text.secondary};
  text-transform: uppercase;
  letter-spacing: 0.5px;
`;

const StyledCommandItem = styled(Command.Item)`
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  color: ${({ theme }) => theme.palette.text.primary};

  &[data-selected='true'] {
    background: ${({ theme }) => theme.palette.action.selected};
  }

  &:hover {
    background: ${({ theme }) => theme.palette.action.hover};
  }

  svg {
    width: 18px;
    height: 18px;
    color: ${({ theme }) => theme.palette.text.secondary};
  }
`;

const StyledCommandSeparator = styled(Command.Separator)`
  height: 1px;
  background: ${({ theme }) => theme.palette.divider};
  margin: 4px 0;
`;

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onRefresh?: () => void;
  onNew?: () => void;
}

interface CommandItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  action: () => void;
  shortcut?: string;
  keywords?: string[];
}

const CommandPalette: React.FC<CommandPaletteProps> = ({ open, onClose, onRefresh, onNew }) => {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');

  useEffect(() => {
    if (!open) {
      setSearch('');
    }
  }, [open]);

  // Navigation commands
  const navigationCommands: CommandItem[] = [
    {
      id: 'nav-dashboard',
      label: 'Go to Dashboard',
      icon: <DashboardIcon />,
      action: () => {
        navigate('/dashboard');
        onClose();
      },
      shortcut: 'Ctrl+Shift+D',
      keywords: ['home', 'main', 'overview'],
    },
    {
      id: 'nav-events',
      label: 'Go to Events',
      icon: <EventIcon />,
      action: () => {
        navigate('/events');
        onClose();
      },
      shortcut: 'Ctrl+Shift+E',
      keywords: ['logs', 'search'],
    },
    {
      id: 'nav-alerts',
      label: 'Go to Alerts',
      icon: <AlertIcon />,
      action: () => {
        navigate('/alerts');
        onClose();
      },
      shortcut: 'Ctrl+Shift+A',
      keywords: ['notifications', 'warnings'],
    },
    {
      id: 'nav-rules',
      label: 'Go to Rules',
      icon: <RuleIcon />,
      action: () => {
        navigate('/rules');
        onClose();
      },
      shortcut: 'Ctrl+Shift+R',
      keywords: ['detection', 'policies'],
    },
    {
      id: 'nav-correlation',
      label: 'Go to Correlation Rules',
      icon: <CorrelationIcon />,
      action: () => {
        navigate('/correlation-rules');
        onClose();
      },
      shortcut: 'Ctrl+Shift+C',
      keywords: ['correlation', 'sequence'],
    },
    {
      id: 'nav-actions',
      label: 'Go to Actions',
      icon: <ActionIcon />,
      action: () => {
        navigate('/actions');
        onClose();
      },
      keywords: ['response', 'automation'],
    },
    {
      id: 'nav-listeners',
      label: 'Go to Listeners',
      icon: <ListenerIcon />,
      action: () => {
        navigate('/listeners');
        onClose();
      },
      shortcut: 'Ctrl+Shift+L',
      keywords: ['ingest', 'sources', 'inputs'],
    },
    {
      id: 'nav-settings',
      label: 'Go to Settings',
      icon: <SettingsIcon />,
      action: () => {
        navigate('/settings');
        onClose();
      },
      keywords: ['config', 'preferences'],
    },
  ];

  // Action commands
  const actionCommands: CommandItem[] = [
    ...(onRefresh ? [{
      id: 'action-refresh',
      label: 'Refresh Current Page',
      icon: <RefreshIcon />,
      action: () => {
        onRefresh();
        onClose();
      },
      shortcut: 'R',
      keywords: ['reload', 'update'],
    }] : []),
    ...(onNew ? [{
      id: 'action-new',
      label: 'Create New Item',
      icon: <AddIcon />,
      action: () => {
        onNew();
        onClose();
      },
      shortcut: 'N',
      keywords: ['add', 'create'],
    }] : []),
  ];

  // Quick actions based on current page
  const getPageSpecificCommands = (): CommandItem[] => {
    const path = window.location.pathname;
    const commands: CommandItem[] = [];

    if (path === '/listeners') {
      commands.push(
        {
          id: 'listener-import',
          label: 'Import Listeners',
          icon: <ImportIcon />,
          action: () => {
            // This would trigger the import dialog
            onClose();
          },
          keywords: ['upload'],
        },
        {
          id: 'listener-export',
          label: 'Export Listeners',
          icon: <ExportIcon />,
          action: () => {
            // This would trigger the export action
            onClose();
          },
          keywords: ['download', 'backup'],
        }
      );
    }

    if (path === '/rules') {
      commands.push(
        {
          id: 'rules-import',
          label: 'Import Rules',
          icon: <ImportIcon />,
          action: () => {
            onClose();
          },
          keywords: ['upload'],
        },
        {
          id: 'rules-export',
          label: 'Export Rules',
          icon: <ExportIcon />,
          action: () => {
            onClose();
          },
          keywords: ['download', 'backup'],
        }
      );
    }

    return commands;
  };

  const pageSpecificCommands = getPageSpecificCommands();

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      PaperProps={{
        sx: {
          overflow: 'visible',
          background: 'transparent',
          boxShadow: 'none',
        },
      }}
    >
      <StyledCommand shouldFilter>
        <StyledCommandInput
          placeholder="Type a command or search..."
          value={search}
          onValueChange={setSearch}
          autoFocus
        />
        <StyledCommandList>
          <StyledCommandEmpty>No results found.</StyledCommandEmpty>

          {navigationCommands.length > 0 && (
            <StyledCommandGroup>
              <StyledCommandGroupHeading>Navigation</StyledCommandGroupHeading>
              {navigationCommands.map((cmd) => (
                <StyledCommandItem
                  key={cmd.id}
                  value={`${cmd.label} ${cmd.keywords?.join(' ') || ''}`}
                  onSelect={cmd.action}
                >
                  {cmd.icon}
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="body2">{cmd.label}</Typography>
                  </Box>
                  {cmd.shortcut && (
                    <Chip
                      label={cmd.shortcut}
                      size="small"
                      sx={{
                        height: 20,
                        fontSize: '11px',
                        bgcolor: 'action.hover',
                      }}
                    />
                  )}
                </StyledCommandItem>
              ))}
            </StyledCommandGroup>
          )}

          {(actionCommands.length > 0 || pageSpecificCommands.length > 0) && (
            <>
              <StyledCommandSeparator />
              <StyledCommandGroup>
                <StyledCommandGroupHeading>Actions</StyledCommandGroupHeading>
                {[...actionCommands, ...pageSpecificCommands].map((cmd) => (
                  <StyledCommandItem
                    key={cmd.id}
                    value={`${cmd.label} ${cmd.keywords?.join(' ') || ''}`}
                    onSelect={cmd.action}
                  >
                    {cmd.icon}
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="body2">{cmd.label}</Typography>
                    </Box>
                    {cmd.shortcut && (
                      <Chip
                        label={cmd.shortcut}
                        size="small"
                        sx={{
                          height: 20,
                          fontSize: '11px',
                          bgcolor: 'action.hover',
                        }}
                      />
                    )}
                  </StyledCommandItem>
                ))}
              </StyledCommandGroup>
            </>
          )}
        </StyledCommandList>
      </StyledCommand>
    </Dialog>
  );
};

export default CommandPalette;
