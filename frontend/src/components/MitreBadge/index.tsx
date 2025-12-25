import React from 'react';
import { Chip, Tooltip, Box } from '@mui/material';
import { Shield as ShieldIcon } from '@mui/icons-material';
import apiService from '../../services/api';

interface MitreBadgeProps {
  /**
   * MITRE tactic or technique ID (e.g., "TA0001" or "T1055")
   */
  id: string;

  /**
   * Type of MITRE item
   */
  type: 'tactic' | 'technique';

  /**
   * Optional label to display (defaults to ID)
   */
  label?: string;

  /**
   * Size of the badge
   */
  size?: 'small' | 'medium';

  /**
   * Whether to show the tooltip with details
   */
  showTooltip?: boolean;

  /**
   * Optional click handler
   */
  onClick?: (id: string) => void;

  /**
   * Whether the badge should be deletable
   */
  onDelete?: () => void;
}

/**
 * MitreBadge component displays MITRE ATT&CK tactics and techniques as color-coded badges
 * with tooltips showing additional information.
 */
export const MitreBadge: React.FC<MitreBadgeProps> = ({
  id,
  type,
  label,
  size = 'small',
  showTooltip = true,
  onClick,
  onDelete,
}) => {
  const [name, setName] = React.useState<string>(label || id);
  const [description, setDescription] = React.useState<string>('');
  const [loading, setLoading] = React.useState(false);

  // Fetch MITRE data on mount if label not provided
  React.useEffect(() => {
    if (!label && id) {
      setLoading(true);
      const fetchData = async () => {
        try {
          if (type === 'tactic') {
            const tactic = await apiService.mitre.getTactic(id);
            setName(tactic.name || id);
            setDescription(tactic.description || '');
          } else {
            const technique = await apiService.mitre.getTechnique(id);
            setName(technique.name || id);
            setDescription(technique.description || '');
          }
        } catch (error) {
          console.error(`Failed to fetch MITRE ${type}:`, error);
          setName(id);
        } finally {
          setLoading(false);
        }
      };
      fetchData();
    }
  }, [id, type, label]);

  // Get color based on tactic name (for tactics) or default for techniques
  const getColor = (): string => {
    if (type === 'tactic') {
      // Convert tactic name to short name format
      const shortName = name.toLowerCase().replace(/\s+/g, '-');
      return apiService.mitre.getTacticColor(shortName);
    }
    // Techniques get a standard blue color
    return '#3b82f6';
  };

  const badge = (
    <Chip
      icon={<ShieldIcon sx={{ fontSize: size === 'small' ? 14 : 18 }} />}
      label={loading ? id : `${id}: ${name}`}
      size={size}
      onClick={onClick ? () => onClick(id) : undefined}
      onDelete={onDelete}
      sx={{
        backgroundColor: getColor(),
        color: '#ffffff',
        fontWeight: 500,
        fontSize: size === 'small' ? '0.75rem' : '0.8125rem',
        '&:hover': onClick ? {
          backgroundColor: getColor(),
          filter: 'brightness(1.2)',
          cursor: 'pointer',
        } : undefined,
        '& .MuiChip-icon': {
          color: '#ffffff',
        },
        '& .MuiChip-deleteIcon': {
          color: 'rgba(255, 255, 255, 0.7)',
          '&:hover': {
            color: '#ffffff',
          },
        },
      }}
    />
  );

  if (!showTooltip || loading || !description) {
    return badge;
  }

  return (
    <Tooltip
      title={
        <Box>
          <Box sx={{ fontWeight: 'bold', mb: 0.5 }}>
            {id}: {name}
          </Box>
          <Box sx={{ fontSize: '0.75rem', opacity: 0.9 }}>
            {description.length > 200 ? `${description.substring(0, 200)}...` : description}
          </Box>
        </Box>
      }
      arrow
      placement="top"
    >
      {badge}
    </Tooltip>
  );
};

export default MitreBadge;
