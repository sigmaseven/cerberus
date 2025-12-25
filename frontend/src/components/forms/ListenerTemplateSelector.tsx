import { useState, useMemo, useCallback, useEffect } from 'react';
import {
  Box,
  Card,
  CardActionArea,
  CardContent,
  Typography,
  Chip,
  Grid,
  TextField,
  InputAdornment,
  Tabs,
  Tab,
  Skeleton,
  Alert,
} from '@mui/material';
import {
  Search as SearchIcon,
  Security as SecurityIcon,
  Computer as ComputerIcon,
  Cloud as CloudIcon,
  Public as PublicIcon,
  DesktopWindows as DesktopWindowsIcon,
  Settings as SettingsIcon,
  CheckCircle as CheckCircleIcon,
} from '@mui/icons-material';
import DOMPurify from 'dompurify';
import type { ListenerTemplate } from '../../types';

// ============================================================================
// Security: Text Sanitization
// ============================================================================

/**
 * Maximum field length for search filtering to prevent DoS attacks
 * BLOCKING-4 FIX: Limit field processing length
 */
const MAX_FIELD_LENGTH = 10000;

/**
 * Sanitize text content to prevent XSS attacks
 * BLOCKING-3 FIX: Templates come from backend storage which could be compromised
 *
 * @param text - Text to sanitize
 * @returns Sanitized text safe for rendering
 */
const sanitizeText = (text: unknown): string => {
  if (typeof text !== 'string') {
    return '';
  }
  // Strip ALL HTML tags, keep only text content
  return DOMPurify.sanitize(text, { ALLOWED_TAGS: [], KEEP_CONTENT: true });
};

/**
 * Truncate string to safe length for search processing
 * BLOCKING-4 FIX: Prevent DoS via giant field values
 */
const safeSlice = (text: unknown, maxLength: number = MAX_FIELD_LENGTH): string => {
  if (typeof text !== 'string') {
    return '';
  }
  return text.slice(0, maxLength);
};

// ============================================================================
// Types
// ============================================================================

interface ListenerTemplateSelectorProps {
  templates: ListenerTemplate[];
  selectedTemplateId: string;
  onSelectTemplate: (templateId: string) => void;
  loading?: boolean;
  error?: string;
}

// ============================================================================
// Icon Mapping
// ============================================================================

/**
 * Maps icon names from backend to MUI icon components
 * Falls back to SettingsIcon if icon name is not recognized
 * BLOCKING-2 FIX: Add null/undefined guards
 */
const getIconComponent = (iconName: string) => {
  // BLOCKING-2: Defensive guard for invalid input
  if (!iconName || typeof iconName !== 'string') {
    return <SettingsIcon />;
  }

  const iconMap: Record<string, React.ReactNode> = {
    security: <SecurityIcon />,
    computer: <ComputerIcon />,
    cloud: <CloudIcon />,
    public: <PublicIcon />,
    desktop_windows: <DesktopWindowsIcon />,
    settings: <SettingsIcon />,
  };

  try {
    return iconMap[iconName.toLowerCase()] || <SettingsIcon />;
  } catch {
    return <SettingsIcon />;
  }
};

/**
 * Get category color for visual differentiation
 * BLOCKING-3 FIX: Add warning for unknown categories
 */
const getCategoryColor = (category: string): 'primary' | 'secondary' | 'success' | 'info' | 'warning' => {
  const colorMap: Record<string, 'primary' | 'secondary' | 'success' | 'info' | 'warning'> = {
    Firewall: 'primary',
    Endpoint: 'secondary',
    Cloud: 'info',
    'Web Server': 'success',
  };

  // BLOCKING-3: Log warning for unknown categories
  if (!colorMap[category]) {
    console.warn(`Unknown template category: "${category}", defaulting to 'primary'`);
  }

  return colorMap[category] || 'primary';
};

// ============================================================================
// Component
// ============================================================================

/**
 * ListenerTemplateSelector - Visual template selection with cards
 *
 * Displays templates as clickable cards organized by category.
 * Features search filtering and category tabs for easy navigation.
 */
export function ListenerTemplateSelector({
  templates,
  selectedTemplateId,
  onSelectTemplate,
  loading = false,
  error,
}: ListenerTemplateSelectorProps) {
  // ============================================================================
  // BLOCKING-7 FIX: ALL HOOKS MUST BE AT TOP - BEFORE ANY CONDITIONAL RETURNS
  // React Rules of Hooks: Hooks must be called in the same order on every render
  // ============================================================================

  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState<string>('All');

  // CRITICAL-1 FIX: Debounce search query to prevent performance issues
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearchQuery(searchQuery);
    }, 300); // 300ms debounce

    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Extract unique categories from templates with validation
  // BLOCKING-7 FIX: Use optional chaining to handle invalid templates prop safely
  const categories = useMemo(() => {
    const cats = new Set<string>();
    if (Array.isArray(templates)) {
      templates.forEach(t => {
        if (t?.category && typeof t.category === 'string') {
          cats.add(t.category.trim());
        }
      });
    }
    return ['All', ...Array.from(cats).sort()];
  }, [templates]);

  // Filter templates by search and category with runtime validation (BLOCKING-4 fix)
  // BLOCKING-7 FIX: Return empty array if templates is invalid
  const filteredTemplates = useMemo(() => {
    if (!Array.isArray(templates)) {
      return [];
    }
    return templates.filter(template => {
      // Category filter
      if (activeCategory !== 'All' && template.category !== activeCategory) {
        return false;
      }

      // BLOCKING-4: Search filter with runtime type validation AND field length limits
      if (debouncedSearchQuery) {
        const query = debouncedSearchQuery.toLowerCase().trim().slice(0, 100); // Limit query length

        // Truncate fields before processing to prevent DoS via giant strings
        const safeName = safeSlice(template.name).toLowerCase();
        const safeDescription = safeSlice(template.description).toLowerCase();

        return (
          safeName.includes(query) ||
          safeDescription.includes(query) ||
          (Array.isArray(template.tags) && template.tags.some(tag =>
            typeof tag === 'string' && safeSlice(tag).toLowerCase().includes(query)
          ))
        );
      }

      return true;
    });
  }, [templates, activeCategory, debouncedSearchQuery]);

  // Handle category tab change
  const handleCategoryChange = useCallback((_: React.SyntheticEvent, newValue: string) => {
    setActiveCategory(newValue);
  }, []);

  // Handle search input change
  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  }, []);

  // Handle template selection
  // BLOCKING-7 FIX: Handle case where onSelectTemplate might not be a function
  const handleTemplateSelect = useCallback((templateId: string) => {
    if (typeof onSelectTemplate !== 'function') {
      return;
    }
    // Toggle selection - clicking same template deselects it
    if (selectedTemplateId === templateId) {
      onSelectTemplate('');
    } else {
      onSelectTemplate(templateId);
    }
  }, [selectedTemplateId, onSelectTemplate]);

  // ============================================================================
  // PROP VALIDATION - AFTER ALL HOOKS (BLOCKING-7 FIX)
  // ============================================================================

  // BLOCKING-6: Defensive prop validation - now AFTER all hooks
  if (!Array.isArray(templates)) {
    console.error('ListenerTemplateSelector: templates prop must be an array');
    return <Alert severity="error">Invalid component configuration: templates must be an array</Alert>;
  }

  if (typeof onSelectTemplate !== 'function') {
    console.error('ListenerTemplateSelector: onSelectTemplate must be a function');
    return <Alert severity="error">Invalid component configuration: callback required</Alert>;
  }

  // Loading state
  if (loading) {
    return (
      <Box>
        <Skeleton variant="rectangular" height={48} sx={{ mb: 2 }} />
        <Grid container spacing={2}>
          {[1, 2, 3, 4].map(i => (
            <Grid item xs={12} sm={6} key={i}>
              <Skeleton variant="rectangular" height={140} sx={{ borderRadius: 1 }} />
            </Grid>
          ))}
        </Grid>
      </Box>
    );
  }

  // Error state
  if (error) {
    return (
      <Alert severity="error" sx={{ mb: 2 }}>
        {error}
      </Alert>
    );
  }

  // No templates state
  if (templates.length === 0) {
    return (
      <Alert severity="info" sx={{ mb: 2 }}>
        No templates available. You can configure your listener manually below.
      </Alert>
    );
  }

  return (
    <Box>
      {/* Search bar */}
      <TextField
        fullWidth
        placeholder="Search templates by name, description, or tags..."
        value={searchQuery}
        onChange={handleSearchChange}
        size="small"
        sx={{ mb: 2 }}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              <SearchIcon color="action" />
            </InputAdornment>
          ),
        }}
        inputProps={{
          'aria-label': 'Search listener templates',
        }}
      />

      {/* Category tabs */}
      <Tabs
        value={activeCategory}
        onChange={handleCategoryChange}
        variant="scrollable"
        scrollButtons="auto"
        sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}
        aria-label="Template categories"
      >
        {categories.map(category => (
          <Tab
            key={category}
            label={category}
            value={category}
            id={`template-tab-${category}`}
            aria-controls={`template-tabpanel-${category}`}
          />
        ))}
      </Tabs>

      {/* Manual configuration option */}
      <Card
        variant="outlined"
        sx={{
          mb: 2,
          borderColor: selectedTemplateId === '' ? 'primary.main' : 'divider',
          borderWidth: selectedTemplateId === '' ? 2 : 1,
          bgcolor: selectedTemplateId === '' ? 'action.selected' : 'background.paper',
        }}
      >
        <CardActionArea
          onClick={() => onSelectTemplate('')}
          sx={{ p: 2 }}
          aria-pressed={selectedTemplateId === ''}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <SettingsIcon color={selectedTemplateId === '' ? 'primary' : 'action'} />
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="subtitle1" fontWeight="medium">
                Manual Configuration
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Configure all listener settings from scratch
              </Typography>
            </Box>
            {selectedTemplateId === '' && (
              <CheckCircleIcon color="primary" />
            )}
          </Box>
        </CardActionArea>
      </Card>

      {/* Template cards grid - BLOCKING-1 FIX: Uses role="list"/role="listitem" */}
      {filteredTemplates.length === 0 ? (
        <Alert severity="info">
          No templates match your search criteria.
        </Alert>
      ) : (
        <Grid container spacing={2} role="list" aria-label="Listener templates">
          {filteredTemplates.map(template => {
            const isSelected = selectedTemplateId === template.id;
            return (
              <Grid item xs={12} sm={6} key={template.id} role="listitem">
                {/* BLOCKING-5 FIX: Removed role="option" - invalid inside role="list" */}
                <Card
                  variant="outlined"
                  aria-selected={isSelected}
                  sx={{
                    height: '100%',
                    borderColor: isSelected ? 'primary.main' : 'divider',
                    borderWidth: isSelected ? 2 : 1,
                    bgcolor: isSelected ? 'action.selected' : 'background.paper',
                    transition: 'all 0.2s ease-in-out',
                    '&:hover': {
                      borderColor: 'primary.light',
                      boxShadow: 1,
                    },
                  }}
                >
                  <CardActionArea
                    onClick={() => handleTemplateSelect(template.id)}
                    sx={{ height: '100%', p: 0 }}
                    aria-pressed={isSelected}
                  >
                    <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                      {/* Header with icon and selection indicator */}
                      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5, mb: 1 }}>
                        <Box
                          sx={{
                            p: 1,
                            borderRadius: 1,
                            bgcolor: `${getCategoryColor(template.category)}.main`,
                            color: 'white',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                        >
                          {getIconComponent(template.icon)}
                        </Box>
                        <Box sx={{ flexGrow: 1 }}>
                          {/* BLOCKING-3 FIX: Sanitize template content to prevent XSS */}
                          <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                            {sanitizeText(template.name)}
                          </Typography>
                          <Chip
                            label={sanitizeText(template.category)}
                            size="small"
                            color={getCategoryColor(template.category)}
                            variant="outlined"
                          />
                        </Box>
                        {isSelected && (
                          <CheckCircleIcon color="primary" />
                        )}
                      </Box>

                      {/* Description - BLOCKING-3 FIX: Sanitized */}
                      <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{
                          mb: 1.5,
                          flexGrow: 1,
                          display: '-webkit-box',
                          WebkitLineClamp: 2,
                          WebkitBoxOrient: 'vertical',
                          overflow: 'hidden',
                        }}
                      >
                        {sanitizeText(template.description)}
                      </Typography>

                      {/* Tags - BLOCKING-3 FIX: Sanitized */}
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {(Array.isArray(template.tags) ? template.tags : []).slice(0, 3).map((tag, index) => (
                          <Chip
                            key={`${sanitizeText(tag)}-${index}`}
                            label={sanitizeText(tag)}
                            size="small"
                            variant="outlined"
                            sx={{ fontSize: '0.7rem', height: 20 }}
                          />
                        ))}
                        {Array.isArray(template.tags) && template.tags.length > 3 && (
                          <Chip
                            label={`+${template.tags.length - 3}`}
                            size="small"
                            variant="outlined"
                            sx={{ fontSize: '0.7rem', height: 20 }}
                          />
                        )}
                      </Box>
                    </CardContent>
                  </CardActionArea>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}
    </Box>
  );
}

export default ListenerTemplateSelector;
