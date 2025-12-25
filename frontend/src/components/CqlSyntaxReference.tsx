import {
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton,
  Typography,
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Divider,
  Chip
} from '@mui/material';
import { Close as CloseIcon } from '@mui/icons-material';

interface CqlSyntaxReferenceProps {
  open: boolean;
  onClose: () => void;
}

export function CqlSyntaxReference({ open, onClose }: CqlSyntaxReferenceProps) {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        CQL Syntax Reference
        <IconButton onClick={onClose} size="small">
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      <DialogContent dividers>
        {/* Overview */}
        <Typography variant="h6" gutterBottom>
          Overview
        </Typography>
        <Typography variant="body2" paragraph>
          Cerberus Query Language (CQL) allows you to write powerful detection logic using field comparisons and logical operators.
        </Typography>

        <Divider sx={{ my: 3 }} />

        {/* Basic Syntax */}
        <Typography variant="h6" gutterBottom>
          Basic Syntax
        </Typography>
        <Box sx={{ mb: 3, p: 2, bgcolor: 'background.paper', borderRadius: 1, border: '1px solid', borderColor: 'divider' }}>
          <Typography variant="body2" component="code" sx={{ fontFamily: 'monospace' }}>
            field_name operator value [AND|OR field_name operator value]
          </Typography>
        </Box>

        <Divider sx={{ my: 3 }} />

        {/* Comparison Operators */}
        <Typography variant="h6" gutterBottom>
          Comparison Operators
        </Typography>
        <TableContainer component={Paper} variant="outlined" sx={{ mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell><strong>Operator</strong></TableCell>
                <TableCell><strong>Description</strong></TableCell>
                <TableCell><strong>Example</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              <TableRow>
                <TableCell><code>=</code></TableCell>
                <TableCell>Equal to</TableCell>
                <TableCell><code>severity = "high"</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>!=</code></TableCell>
                <TableCell>Not equal to</TableCell>
                <TableCell><code>status != "success"</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>&gt;</code></TableCell>
                <TableCell>Greater than</TableCell>
                <TableCell><code>fields.count &gt; 100</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>&lt;</code></TableCell>
                <TableCell>Less than</TableCell>
                <TableCell><code>fields.port &lt; 1024</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>&gt;=</code></TableCell>
                <TableCell>Greater than or equal</TableCell>
                <TableCell><code>fields.size &gt;= 1000</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>&lt;=</code></TableCell>
                <TableCell>Less than or equal</TableCell>
                <TableCell><code>fields.age &lt;= 30</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>contains</code></TableCell>
                <TableCell>String contains substring</TableCell>
                <TableCell><code>fields.command_line contains "powershell"</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>startswith</code></TableCell>
                <TableCell>String starts with</TableCell>
                <TableCell><code>fields.user startswith "admin"</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>endswith</code></TableCell>
                <TableCell>String ends with</TableCell>
                <TableCell><code>fields.file_path endswith ".exe"</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>matches</code></TableCell>
                <TableCell>Regex pattern match</TableCell>
                <TableCell><code>fields.ip matches "192\\.168\\..*"</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>in</code></TableCell>
                <TableCell>Value in list</TableCell>
                <TableCell><code>event_type in ["login", "logout"]</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>exists</code></TableCell>
                <TableCell>Field exists</TableCell>
                <TableCell><code>fields.error exists</code></TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </TableContainer>

        <Divider sx={{ my: 3 }} />

        {/* Logical Operators */}
        <Typography variant="h6" gutterBottom>
          Logical Operators
        </Typography>
        <TableContainer component={Paper} variant="outlined" sx={{ mb: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell><strong>Operator</strong></TableCell>
                <TableCell><strong>Description</strong></TableCell>
                <TableCell><strong>Example</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              <TableRow>
                <TableCell><code>AND</code></TableCell>
                <TableCell>Both conditions must be true</TableCell>
                <TableCell><code>event_type = "login" AND severity = "high"</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>OR</code></TableCell>
                <TableCell>Either condition must be true</TableCell>
                <TableCell><code>source = "firewall" OR source = "ids"</code></TableCell>
              </TableRow>
              <TableRow>
                <TableCell><code>NOT</code></TableCell>
                <TableCell>Negates a condition</TableCell>
                <TableCell><code>NOT event_type = "heartbeat"</code></TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </TableContainer>

        <Divider sx={{ my: 3 }} />

        {/* Common Fields */}
        <Typography variant="h6" gutterBottom>
          Common Event Fields
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Typography variant="body2" gutterBottom>
            <strong>Core Fields:</strong>
          </Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
            <Chip label="event_type" size="small" />
            <Chip label="event_id" size="small" />
            <Chip label="timestamp" size="small" />
            <Chip label="severity" size="small" />
            <Chip label="source" size="small" />
            <Chip label="source_format" size="small" />
            <Chip label="listener_id" size="small" />
            <Chip label="listener_name" size="small" />
          </Box>
          <Typography variant="body2" gutterBottom>
            <strong>Custom Fields (use <code>fields.</code> prefix):</strong>
          </Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            <Chip label="fields.user" size="small" />
            <Chip label="fields.ip" size="small" />
            <Chip label="fields.port" size="small" />
            <Chip label="fields.host" size="small" />
            <Chip label="fields.process_name" size="small" />
            <Chip label="fields.command_line" size="small" />
            <Chip label="fields.file_path" size="small" />
          </Box>
        </Box>

        <Divider sx={{ my: 3 }} />

        {/* Examples */}
        <Typography variant="h6" gutterBottom>
          Examples
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Typography variant="subtitle2" gutterBottom>
            Detect PowerShell execution:
          </Typography>
          <Box sx={{ mb: 2, p: 1.5, bgcolor: 'background.default', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
            event_type = "process_creation" AND fields.command_line contains "powershell"
          </Box>

          <Typography variant="subtitle2" gutterBottom>
            High severity events from specific source:
          </Typography>
          <Box sx={{ mb: 2, p: 1.5, bgcolor: 'background.default', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
            severity = "high" AND source = "firewall-01"
          </Box>

          <Typography variant="subtitle2" gutterBottom>
            Failed login attempts from external IPs:
          </Typography>
          <Box sx={{ mb: 2, p: 1.5, bgcolor: 'background.default', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
            event_type = "login" AND fields.status = "failed" AND NOT fields.ip startswith "192.168"
          </Box>

          <Typography variant="subtitle2" gutterBottom>
            Suspicious file extensions:
          </Typography>
          <Box sx={{ mb: 2, p: 1.5, bgcolor: 'background.default', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
            fields.file_path endswith ".exe" OR fields.file_path endswith ".dll" OR fields.file_path endswith ".ps1"
          </Box>

          <Typography variant="subtitle2" gutterBottom>
            Multiple event types:
          </Typography>
          <Box sx={{ p: 1.5, bgcolor: 'background.default', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
            event_type in ["process_creation", "network_connection", "file_modification"]
          </Box>
        </Box>
      </DialogContent>
    </Dialog>
  );
}
