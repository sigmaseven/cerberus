import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  Box,
  Alert,
  CircularProgress,
} from '@mui/material';
import { Download as DownloadIcon } from '@mui/icons-material';

interface ExportDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  onExport: (format: 'json' | 'yaml') => Promise<void>;
  loading?: boolean;
  error?: string | null;
}

const ExportDialog: React.FC<ExportDialogProps> = ({
  open,
  onClose,
  title,
  onExport,
  loading = false,
  error = null,
}) => {
  const [format, setFormat] = useState<'json' | 'yaml'>('json');

  const handleExport = async () => {
    try {
      await onExport(format);
      onClose();
    } catch {
      // Error is handled by parent component
    }
  };

  const handleClose = () => {
    if (!loading) {
      setFormat('json');
      onClose();
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Box sx={{ mb: 3 }}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Export rules in your preferred format. The exported file will be downloaded automatically.
          </Typography>
        </Box>

        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel>Export Format</InputLabel>
          <Select
            value={format}
            label="Export Format"
            onChange={(e) => setFormat(e.target.value as 'json' | 'yaml')}
            disabled={loading}
          >
            <MenuItem value="json">JSON</MenuItem>
            <MenuItem value="yaml">YAML</MenuItem>
          </Select>
        </FormControl>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="body2" color="text.secondary">
            File format:
          </Typography>
          <Typography variant="body2" fontWeight="medium">
            .{format}
          </Typography>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          onClick={handleExport}
          variant="contained"
          startIcon={loading ? <CircularProgress size={16} /> : <DownloadIcon />}
          disabled={loading}
        >
          {loading ? 'Exporting...' : 'Export'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ExportDialog;