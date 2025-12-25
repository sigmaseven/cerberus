import React, { useState, useRef } from 'react';
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
  LinearProgress,
} from '@mui/material';
import { Upload as UploadIcon, CloudUpload as CloudUploadIcon } from '@mui/icons-material';

interface ImportDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  onImport: (file: File, conflictResolution: 'skip' | 'overwrite' | 'merge') => Promise<void>;
  loading?: boolean;
  error?: string | null;
  progress?: {
    current: number;
    total: number;
    message: string;
  } | null;
}

const ImportDialog: React.FC<ImportDialogProps> = ({
  open,
  onClose,
  title,
  onImport,
  loading = false,
  error = null,
  progress = null,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [conflictResolution, setConflictResolution] = useState<'skip' | 'overwrite' | 'merge'>('overwrite');
  const [dragOver, setDragOver] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (file: File) => {
    // Clear previous validation errors
    setValidationError(null);

    // Validate file type
    const allowedExtensions = ['.json', '.yaml', '.yml'];
    const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));

    if (!allowedExtensions.includes(fileExtension)) {
      setValidationError('Please select a valid JSON or YAML file.');
      return;
    }

    // Validate file size (max 10MB)
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      setValidationError('File size must be less than 10MB.');
      return;
    }

    setSelectedFile(file);
  };

  const handleFileInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragOver(false);

    const file = event.dataTransfer.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragOver(false);
  };

  const handleImport = async () => {
    if (!selectedFile) return;

    try {
      await onImport(selectedFile, conflictResolution);
      handleClose();
    } catch {
      // Error is handled by parent component
    }
  };

  const handleClose = () => {
    if (!loading) {
      setSelectedFile(null);
      setConflictResolution('overwrite');
      setDragOver(false);
      onClose();
    }
  };

  const openFileDialog = () => {
    fileInputRef.current?.click();
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Box sx={{ mb: 3 }}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Import rules from a JSON or YAML file. Choose how to handle conflicts with existing rules.
          </Typography>
        </Box>

        {/* File Upload Area */}
        <Box
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={openFileDialog}
          sx={{
            border: '2px dashed',
            borderColor: dragOver ? 'primary.main' : selectedFile ? 'success.main' : 'grey.400',
            borderRadius: 2,
            p: 3,
            textAlign: 'center',
            cursor: loading ? 'default' : 'pointer',
            backgroundColor: dragOver ? 'action.hover' : 'background.paper',
            transition: 'all 0.2s ease',
            mb: 3,
            '&:hover': {
              borderColor: selectedFile ? 'success.main' : 'primary.main',
              backgroundColor: 'action.hover',
            },
          }}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,.yaml,.yml"
            onChange={handleFileInputChange}
            style={{ display: 'none' }}
            disabled={loading}
          />

          {selectedFile ? (
            <Box>
              <CloudUploadIcon sx={{ fontSize: 48, color: 'success.main', mb: 1 }} />
              <Typography variant="h6" gutterBottom>
                File Selected
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
              </Typography>
            </Box>
          ) : (
            <Box>
              <CloudUploadIcon sx={{ fontSize: 48, color: 'action.disabled', mb: 1 }} />
              <Typography variant="h6" gutterBottom>
                Drop file here or click to browse
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Supports JSON and YAML files (max 10MB)
              </Typography>
            </Box>
          )}
        </Box>

        {/* Conflict Resolution */}
        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel>Conflict Resolution</InputLabel>
          <Select
            value={conflictResolution}
            label="Conflict Resolution"
            onChange={(e) => setConflictResolution(e.target.value as 'skip' | 'overwrite' | 'merge')}
            disabled={loading}
          >
            <MenuItem value="overwrite">Overwrite existing rules</MenuItem>
            <MenuItem value="skip">Skip conflicting rules</MenuItem>
            <MenuItem value="merge">Merge with existing rules</MenuItem>
          </Select>
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>
            {conflictResolution === 'overwrite' && 'Replace existing rules with imported ones'}
            {conflictResolution === 'skip' && 'Keep existing rules and skip duplicates'}
            {conflictResolution === 'merge' && 'Update existing rules and add new ones'}
          </Typography>
        </FormControl>

        {/* Progress Bar */}
        {progress && (
          <Box sx={{ mb: 2 }}>
            <Typography variant="body2" gutterBottom>
              {progress.message}
            </Typography>
            <LinearProgress
              variant="determinate"
              value={(progress.current / progress.total) * 100}
              sx={{ height: 8, borderRadius: 4 }}
            />
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>
              {progress.current} of {progress.total} rules processed
            </Typography>
          </Box>
        )}

        {/* Error Display */}
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {/* Validation Error Display */}
        {validationError && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {validationError}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          onClick={handleImport}
          variant="contained"
          startIcon={loading ? <CircularProgress size={16} /> : <UploadIcon />}
          disabled={loading || !selectedFile}
        >
          {loading ? 'Importing...' : 'Import'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ImportDialog;