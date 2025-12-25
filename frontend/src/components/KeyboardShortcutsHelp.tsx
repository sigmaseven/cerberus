import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  Chip,
  Divider,
  Paper,
} from '@mui/material';
import {
  Keyboard as KeyboardIcon,
} from '@mui/icons-material';

interface ShortcutGroup {
  title: string;
  shortcuts: Array<{
    keys: string[];
    description: string;
  }>;
}

interface KeyboardShortcutsHelpProps {
  open: boolean;
  onClose: () => void;
}

const KeyboardShortcutsHelp: React.FC<KeyboardShortcutsHelpProps> = ({ open, onClose }) => {
  const shortcutGroups: ShortcutGroup[] = [
    {
      title: 'Global Shortcuts',
      shortcuts: [
        { keys: ['Ctrl', 'K'], description: 'Open command palette' },
        { keys: ['Ctrl', 'P'], description: 'Open command palette' },
        { keys: ['?'], description: 'Show keyboard shortcuts (this dialog)' },
      ],
    },
    {
      title: 'Navigation',
      shortcuts: [
        { keys: ['Ctrl', 'Shift', 'D'], description: 'Go to Dashboard' },
        { keys: ['Ctrl', 'Shift', 'E'], description: 'Go to Events' },
        { keys: ['Ctrl', 'Shift', 'A'], description: 'Go to Alerts' },
        { keys: ['Ctrl', 'Shift', 'R'], description: 'Go to Rules' },
        { keys: ['Ctrl', 'Shift', 'C'], description: 'Go to Correlation Rules' },
        { keys: ['Ctrl', 'Shift', 'L'], description: 'Go to Listeners' },
      ],
    },
    {
      title: 'Page Actions (Context-Specific)',
      shortcuts: [
        { keys: ['R'], description: 'Refresh current page' },
        { keys: ['N'], description: 'Create new item' },
        { keys: ['Ctrl', 'F'], description: 'Search (when available)' },
      ],
    },
  ];

  const renderKey = (key: string) => (
    <Chip
      label={key}
      size="small"
      sx={{
        height: 24,
        fontSize: '12px',
        fontWeight: 600,
        bgcolor: 'action.selected',
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 1,
        fontFamily: 'monospace',
      }}
    />
  );

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <KeyboardIcon />
          <Typography variant="h6">Keyboard Shortcuts</Typography>
        </Box>
      </DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Use keyboard shortcuts to navigate and perform actions quickly in Cerberus SIEM.
        </Typography>

        {shortcutGroups.map((group) => (
          <Box key={group.title} sx={{ mb: 3 }}>
            <Typography variant="subtitle2" color="primary" sx={{ mb: 2, fontWeight: 600 }}>
              {group.title}
            </Typography>
            <Paper variant="outlined" sx={{ p: 0 }}>
              {group.shortcuts.map((shortcut, index) => (
                <React.Fragment key={shortcut.keys.join('-') + `-${shortcut.description}`}>
                  <Box
                    sx={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      p: 1.5,
                      '&:hover': {
                        bgcolor: 'action.hover',
                      },
                    }}
                  >
                    <Typography variant="body2">{shortcut.description}</Typography>
                    <Box sx={{ display: 'flex', gap: 0.5 }}>
                      {shortcut.keys.map((key, keyIndex) => (
                        <React.Fragment key={keyIndex}>
                          {renderKey(key)}
                          {keyIndex < shortcut.keys.length - 1 && (
                            <Typography variant="body2" sx={{ mx: 0.5 }}>+</Typography>
                          )}
                        </React.Fragment>
                      ))}
                    </Box>
                  </Box>
                  {index < group.shortcuts.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </Paper>
          </Box>
        ))}

        <Box sx={{ mt: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
          <Typography variant="caption" color="text.secondary">
            <strong>Note:</strong> Context-specific shortcuts (R, N, Ctrl+F) only work when you're not typing in an input field.
            Global shortcuts work everywhere.
          </Typography>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default KeyboardShortcutsHelp;
