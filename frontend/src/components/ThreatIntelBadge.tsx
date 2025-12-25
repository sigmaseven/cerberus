import { Box, Chip, Tooltip, Typography } from '@mui/material';
import { Warning as WarningIcon, Shield as ShieldIcon } from '@mui/icons-material';
import { ThreatIntel } from '../types';

interface ThreatIntelBadgeProps {
  threatIntel: ThreatIntel[];
}

export default function ThreatIntelBadge({ threatIntel }: ThreatIntelBadgeProps) {
  if (!threatIntel || threatIntel.length === 0) {
    return null;
  }

  const getConfidenceColor = (confidence: number): string => {
    if (confidence >= 0.8) return '#f44336'; // Red for high confidence
    if (confidence >= 0.6) return '#ff9800'; // Orange for medium confidence
    return '#ffeb3b'; // Yellow for low confidence
  };

  const getConfidenceLabel = (confidence: number): string => {
    if (confidence >= 0.8) return 'High';
    if (confidence >= 0.6) return 'Medium';
    return 'Low';
  };

  return (
    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
      {threatIntel.map((intel, index) => (
        <Tooltip
          key={intel.source + `-${index}-${intel.severity}`}
          title={
            <Box>
              <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                {intel.description || 'Threat Detected'}
              </Typography>
              <Typography variant="caption" sx={{ display: 'block', mt: 1 }}>
                IOC: {intel.ioc}
              </Typography>
              <Typography variant="caption" sx={{ display: 'block' }}>
                Type: {intel.type}
              </Typography>
              <Typography variant="caption" sx={{ display: 'block' }}>
                Confidence: {(intel.confidence * 100).toFixed(0)}%
              </Typography>
              {intel.tags && intel.tags.length > 0 && (
                <Typography variant="caption" sx={{ display: 'block', mt: 1 }}>
                  Tags: {intel.tags.join(', ')}
                </Typography>
              )}
            </Box>
          }
        >
          <Chip
            icon={intel.is_malicious ? <WarningIcon /> : <ShieldIcon />}
            label={`${intel.type.toUpperCase()}: ${getConfidenceLabel(intel.confidence)}`}
            size="small"
            sx={{
              bgcolor: getConfidenceColor(intel.confidence),
              color: 'white',
              fontWeight: 'bold',
            }}
          />
        </Tooltip>
      ))}
    </Box>
  );
}
