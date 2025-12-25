import React from 'react';
import {
  Card,
  CardContent,
  CardActions,
  Typography,
  Chip,
  Box,
  IconButton,
  Tooltip,
  Stack,
} from '@mui/material';
import {
  OpenInNew as OpenIcon,
  Assignment as InvestigationIcon,
  Person as PersonIcon,
  Schedule as ClockIcon,
  Warning as AlertIcon,
} from '@mui/icons-material';
import { Investigation, InvestigationPriority, InvestigationStatus } from '../../types';
import { MitreBadge } from '../MitreBadge';

interface InvestigationCardProps {
  investigation: Investigation;
  onOpen?: (id: string) => void;
  onStatusChange?: (id: string, status: InvestigationStatus) => void;
}

/**
 * InvestigationCard displays a compact summary of an investigation
 * Used in investigation lists and dashboards
 */
export const InvestigationCard: React.FC<InvestigationCardProps> = ({
  investigation,
  onOpen,
}) => {
  const getPriorityColor = (priority: InvestigationPriority): string => {
    const colors: Record<InvestigationPriority, string> = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#22c55e',
    };
    return colors[priority];
  };

  const getStatusColor = (status: InvestigationStatus): string => {
    const colors: Record<InvestigationStatus, string> = {
      open: '#3b82f6',
      in_progress: '#8b5cf6',
      awaiting_review: '#f59e0b',
      closed: '#6b7280',
      resolved: '#10b981',
      false_positive: '#64748b',
    };
    return colors[status];
  };

  const getStatusLabel = (status: InvestigationStatus): string => {
    const labels: Record<InvestigationStatus, string> = {
      open: 'Open',
      in_progress: 'In Progress',
      awaiting_review: 'Awaiting Review',
      closed: 'Closed',
      resolved: 'Resolved',
      false_positive: 'False Positive',
    };
    return labels[status];
  };

  const formatTimestamp = (timestamp: string): string => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  return (
    <Card
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        transition: 'all 0.2s ease-in-out',
        borderLeft: `4px solid ${getPriorityColor(investigation.priority)}`,
        '&:hover': {
          transform: 'translateY(-2px)',
          boxShadow: 4,
        },
      }}
    >
      <CardContent sx={{ flexGrow: 1, pb: 1 }}>
        {/* Header with ID and Status */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <InvestigationIcon sx={{ color: 'text.secondary', fontSize: 20 }} />
            <Typography variant="caption" color="text.secondary" fontWeight="medium">
              {investigation.investigation_id}
            </Typography>
          </Box>
          <Chip
            label={getStatusLabel(investigation.status)}
            size="small"
            sx={{
              backgroundColor: getStatusColor(investigation.status),
              color: '#ffffff',
              fontWeight: 500,
              fontSize: '0.7rem',
              height: 20,
            }}
          />
        </Box>

        {/* Title */}
        <Typography
          variant="h6"
          component="h3"
          gutterBottom
          sx={{
            fontSize: '1rem',
            fontWeight: 600,
            lineHeight: 1.3,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
            mb: 1,
          }}
        >
          {investigation.title}
        </Typography>

        {/* Description */}
        <Typography
          variant="body2"
          color="text.secondary"
          sx={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
            mb: 2,
            fontSize: '0.875rem',
          }}
        >
          {investigation.description}
        </Typography>

        {/* MITRE Tags */}
        {(investigation.mitre_tactics || investigation.mitre_techniques) && (
          <Box sx={{ mb: 2 }}>
            <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
              {investigation.mitre_tactics?.slice(0, 3).map((tacticId) => (
                <MitreBadge
                  key={tacticId}
                  id={tacticId}
                  type="tactic"
                  size="small"
                  showTooltip={false}
                />
              ))}
              {investigation.mitre_techniques?.slice(0, 2).map((techniqueId) => (
                <MitreBadge
                  key={techniqueId}
                  id={techniqueId}
                  type="technique"
                  size="small"
                  showTooltip={false}
                />
              ))}
              {((investigation.mitre_tactics?.length || 0) + (investigation.mitre_techniques?.length || 0) > 5) && (
                <Chip
                  label={`+${(investigation.mitre_tactics?.length || 0) + (investigation.mitre_techniques?.length || 0) - 5} more`}
                  size="small"
                  sx={{ fontSize: '0.7rem', height: 20 }}
                />
              )}
            </Stack>
          </Box>
        )}

        {/* Metadata */}
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, fontSize: '0.75rem' }}>
          {/* Priority */}
          <Tooltip title="Priority">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  backgroundColor: getPriorityColor(investigation.priority),
                }}
              />
              <Typography variant="caption" sx={{ textTransform: 'capitalize' }}>
                {investigation.priority}
              </Typography>
            </Box>
          </Tooltip>

          {/* Alert Count */}
          <Tooltip title="Number of alerts">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <AlertIcon sx={{ fontSize: 14, color: 'text.secondary' }} />
              <Typography variant="caption">
                {investigation.alert_ids.length} alert{investigation.alert_ids.length !== 1 ? 's' : ''}
              </Typography>
            </Box>
          </Tooltip>

          {/* Assignee */}
          {investigation.assignee_id && (
            <Tooltip title="Assigned to">
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <PersonIcon sx={{ fontSize: 14, color: 'text.secondary' }} />
                <Typography variant="caption">
                  {investigation.assignee_id}
                </Typography>
              </Box>
            </Tooltip>
          )}

          {/* Updated */}
          <Tooltip title={`Updated: ${new Date(investigation.updated_at).toLocaleString()}`}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <ClockIcon sx={{ fontSize: 14, color: 'text.secondary' }} />
              <Typography variant="caption">
                {formatTimestamp(investigation.updated_at)}
              </Typography>
            </Box>
          </Tooltip>
        </Box>
      </CardContent>

      <CardActions sx={{ pt: 0, px: 2, pb: 2, justifyContent: 'flex-end' }}>
        <Tooltip title="Open investigation">
          <IconButton
            size="small"
            onClick={() => onOpen?.(investigation.investigation_id)}
            sx={{
              color: 'primary.main',
              '&:hover': {
                backgroundColor: 'primary.light',
                color: 'primary.contrastText',
              },
            }}
          >
            <OpenIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </CardActions>
    </Card>
  );
};

export default InvestigationCard;
