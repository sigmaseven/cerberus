import { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Alert,
  TextField,
  IconButton,
  Tooltip,
  Tabs,
  Tab,
  Paper,
} from '@mui/material';
import {
  ContentCopy as CopyIcon,
  Check as CheckIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import yaml from 'js-yaml';

interface SigmaDetectionEditorProps {
  detection: Record<string, unknown> | undefined;
  logsource: Record<string, unknown> | undefined;
  onChange: (detection: Record<string, unknown>, logsource: Record<string, unknown>) => void;
  readOnly?: boolean;
}

/**
 * YAML editor for SIGMA detection rules.
 * Converts JSON detection/logsource to YAML for editing and back to JSON on save.
 */
export function SigmaDetectionEditor({
  detection,
  logsource,
  onChange,
  readOnly = false,
}: SigmaDetectionEditorProps) {
  const [detectionYaml, setDetectionYaml] = useState('');
  const [logsourceYaml, setLogsourceYaml] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState(0);

  // Convert detection object to YAML on mount or when detection changes
  useEffect(() => {
    try {
      if (detection && Object.keys(detection).length > 0) {
        const yamlStr = yaml.dump(detection, {
          indent: 2,
          lineWidth: -1, // Don't wrap lines
          quotingType: '"',
          forceQuotes: false,
        });
        setDetectionYaml(yamlStr);
      } else {
        // Default SIGMA detection template
        setDetectionYaml(`selection:
  EventID: 4625
condition: selection
`);
      }
    } catch (err) {
      console.error('Failed to convert detection to YAML:', err);
      setDetectionYaml(JSON.stringify(detection, null, 2));
    }
  }, [detection]);

  // Convert logsource object to YAML
  useEffect(() => {
    try {
      if (logsource && Object.keys(logsource).length > 0) {
        const yamlStr = yaml.dump(logsource, {
          indent: 2,
          lineWidth: -1,
          quotingType: '"',
          forceQuotes: false,
        });
        setLogsourceYaml(yamlStr);
      } else {
        // Default SIGMA logsource template
        setLogsourceYaml(`category: process_creation
product: windows
`);
      }
    } catch (err) {
      console.error('Failed to convert logsource to YAML:', err);
      setLogsourceYaml(JSON.stringify(logsource, null, 2));
    }
  }, [logsource]);

  // Validate and update parent when YAML changes
  const handleDetectionChange = useCallback((value: string) => {
    setDetectionYaml(value);
    setParseError(null);

    try {
      const parsed = yaml.load(value) as Record<string, unknown>;
      if (typeof parsed === 'object' && parsed !== null) {
        // Parse logsource as well
        let parsedLogsource = {};
        try {
          parsedLogsource = yaml.load(logsourceYaml) as Record<string, unknown> || {};
        } catch {
          // Ignore logsource parse errors when updating detection
        }
        onChange(parsed, parsedLogsource);
      } else {
        setParseError('Detection must be a valid YAML object');
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Invalid YAML syntax';
      setParseError(message);
    }
  }, [logsourceYaml, onChange]);

  const handleLogsourceChange = useCallback((value: string) => {
    setLogsourceYaml(value);
    setParseError(null);

    try {
      const parsed = yaml.load(value) as Record<string, unknown>;
      if (typeof parsed === 'object' && parsed !== null) {
        // Parse detection as well
        let parsedDetection = {};
        try {
          parsedDetection = yaml.load(detectionYaml) as Record<string, unknown> || {};
        } catch {
          // Ignore detection parse errors when updating logsource
        }
        onChange(parsedDetection, parsed);
      } else {
        setParseError('Logsource must be a valid YAML object');
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Invalid YAML syntax';
      setParseError(message);
    }
  }, [detectionYaml, onChange]);

  const handleCopy = async () => {
    const fullYaml = `logsource:\n${logsourceYaml.split('\n').map(l => '  ' + l).join('\n')}\ndetection:\n${detectionYaml.split('\n').map(l => '  ' + l).join('\n')}`;
    await navigator.clipboard.writeText(fullYaml);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
        <Typography variant="subtitle2" color="text.secondary">
          SIGMA Detection (YAML)
        </Typography>
        <Tooltip title={copied ? 'Copied!' : 'Copy full YAML'}>
          <IconButton size="small" onClick={handleCopy}>
            {copied ? <CheckIcon fontSize="small" color="success" /> : <CopyIcon fontSize="small" />}
          </IconButton>
        </Tooltip>
      </Box>

      <Paper variant="outlined" sx={{ mb: 2 }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          sx={{ borderBottom: 1, borderColor: 'divider', bgcolor: 'background.default' }}
        >
          <Tab label="Detection" sx={{ textTransform: 'none' }} />
          <Tab label="Logsource" sx={{ textTransform: 'none' }} />
        </Tabs>

        <Box sx={{ p: 0 }}>
          {activeTab === 0 && (
            <TextField
              fullWidth
              multiline
              rows={12}
              value={detectionYaml}
              onChange={(e) => handleDetectionChange(e.target.value)}
              disabled={readOnly}
              placeholder={`selection:
  EventID: 4625
  LogonType: 10
filter:
  TargetUserName|endswith: '$'
condition: selection and not filter`}
              sx={{
                '& .MuiInputBase-root': {
                  fontFamily: 'monospace',
                  fontSize: '0.875rem',
                  bgcolor: 'grey.900',
                  borderRadius: 0,
                },
                '& .MuiOutlinedInput-notchedOutline': {
                  border: 'none',
                },
              }}
            />
          )}
          {activeTab === 1 && (
            <TextField
              fullWidth
              multiline
              rows={12}
              value={logsourceYaml}
              onChange={(e) => handleLogsourceChange(e.target.value)}
              disabled={readOnly}
              placeholder={`category: process_creation
product: windows
service: security`}
              sx={{
                '& .MuiInputBase-root': {
                  fontFamily: 'monospace',
                  fontSize: '0.875rem',
                  bgcolor: 'grey.900',
                  borderRadius: 0,
                },
                '& .MuiOutlinedInput-notchedOutline': {
                  border: 'none',
                },
              }}
            />
          )}
        </Box>
      </Paper>

      {parseError && (
        <Alert severity="error" icon={<ErrorIcon />} sx={{ mb: 2 }}>
          {parseError}
        </Alert>
      )}

      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
        Use standard SIGMA YAML syntax. The detection section should contain selection patterns and a condition.
        See <a href="https://sigmahq.io/docs/basics/rules.html" target="_blank" rel="noopener noreferrer" style={{ color: '#90caf9' }}>SIGMA documentation</a> for syntax reference.
      </Typography>
    </Box>
  );
}
