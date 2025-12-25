import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  FormControl,
  FormLabel,
  RadioGroup,
  FormControlLabel,
  Radio,
  Box,
  Typography,
  Divider,
  Checkbox,
  Alert,
  Chip,
  Stack,
} from '@mui/material';
import {
  CheckCircle as TruePositiveIcon,
  Cancel as FalsePositiveIcon,
  Help as InconclusiveIcon,
} from '@mui/icons-material';
import type { InvestigationVerdict, MLFeedback } from '../../types';

interface VerdictModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (verdict: VerdictModalData) => Promise<void>;
  investigationId: string;
  investigationTitle: string;
}

export interface VerdictModalData {
  verdict: InvestigationVerdict;
  resolution_category: string;
  summary: string;
  affected_assets?: string[];
  ml_feedback?: MLFeedback;
}

/**
 * VerdictModal allows analysts to close an investigation with a verdict
 * Includes ML feedback collection for continuous improvement
 */
export const VerdictModal: React.FC<VerdictModalProps> = ({
  open,
  onClose,
  onSubmit,
  investigationId,
  investigationTitle,
}) => {
  const [verdict, setVerdict] = React.useState<InvestigationVerdict>('true_positive');
  const [resolutionCategory, setResolutionCategory] = React.useState('');
  const [summary, setSummary] = React.useState('');
  const [affectedAssets, setAffectedAssets] = React.useState('');
  const [provideMlFeedback, setProvideMlFeedback] = React.useState(false);
  const [mlWasCorrect, setMlWasCorrect] = React.useState(true);
  const [mlFeedbackNotes, setMlFeedbackNotes] = React.useState('');
  const [falsePositiveReason, setFalsePositiveReason] = React.useState('');
  const [missedIndicators, setMissedIndicators] = React.useState('');
  const [suggestedImprovements, setSuggestedImprovements] = React.useState('');
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const resolutionCategories = [
    'Malware Infection',
    'Unauthorized Access',
    'Data Exfiltration',
    'Phishing Attack',
    'Insider Threat',
    'Misconfiguration',
    'Policy Violation',
    'False Positive',
    'Other',
  ];

  const handleSubmit = async () => {
    if (!summary.trim()) {
      setError('Summary is required');
      return;
    }

    if (!resolutionCategory) {
      setError('Resolution category is required');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const data: VerdictModalData = {
        verdict,
        resolution_category: resolutionCategory,
        summary: summary.trim(),
      };

      // Parse affected assets
      if (affectedAssets.trim()) {
        data.affected_assets = affectedAssets
          .split('\n')
          .map(asset => asset.trim())
          .filter(asset => asset.length > 0);
      }

      // Include ML feedback if provided
      if (provideMlFeedback) {
        data.ml_feedback = {
          was_correct: mlWasCorrect,
          feedback_notes: mlFeedbackNotes.trim() || undefined,
          false_positive_reason: verdict === 'false_positive' ? falsePositiveReason.trim() : undefined,
          missed_indicators: missedIndicators.trim() ? missedIndicators.split('\n').map(i => i.trim()).filter(i => i.length > 0) : undefined,
          suggested_improvements: suggestedImprovements.trim() || undefined,
        };
      }

      await onSubmit(data);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit verdict');
    } finally {
      setSubmitting(false);
    }
  };

  const handleClose = () => {
    // Reset form
    setVerdict('true_positive');
    setResolutionCategory('');
    setSummary('');
    setAffectedAssets('');
    setProvideMlFeedback(false);
    setMlWasCorrect(true);
    setMlFeedbackNotes('');
    setFalsePositiveReason('');
    setMissedIndicators('');
    setSuggestedImprovements('');
    setError(null);
    onClose();
  };

  const getVerdictIcon = (v: InvestigationVerdict) => {
    switch (v) {
      case 'true_positive':
        return <TruePositiveIcon sx={{ color: '#ef4444' }} />;
      case 'false_positive':
        return <FalsePositiveIcon sx={{ color: '#22c55e' }} />;
      case 'inconclusive':
        return <InconclusiveIcon sx={{ color: '#f59e0b' }} />;
    }
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="md"
      fullWidth
      PaperProps={{
        sx: { maxHeight: '90vh' },
      }}
    >
      <DialogTitle>
        Close Investigation
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          {investigationId}: {investigationTitle}
        </Typography>
      </DialogTitle>

      <DialogContent dividers>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {/* Verdict Selection */}
        <FormControl component="fieldset" fullWidth sx={{ mb: 3 }}>
          <FormLabel component="legend" sx={{ mb: 1, fontWeight: 600 }}>
            Investigation Verdict *
          </FormLabel>
          <RadioGroup
            value={verdict}
            onChange={(e) => setVerdict(e.target.value as InvestigationVerdict)}
          >
            <FormControlLabel
              value="true_positive"
              control={<Radio />}
              label={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {getVerdictIcon('true_positive')}
                  <Box>
                    <Typography variant="body2" fontWeight={500}>True Positive</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Confirmed security incident
                    </Typography>
                  </Box>
                </Box>
              }
            />
            <FormControlLabel
              value="false_positive"
              control={<Radio />}
              label={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {getVerdictIcon('false_positive')}
                  <Box>
                    <Typography variant="body2" fontWeight={500}>False Positive</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Benign activity incorrectly flagged
                    </Typography>
                  </Box>
                </Box>
              }
            />
            <FormControlLabel
              value="inconclusive"
              control={<Radio />}
              label={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {getVerdictIcon('inconclusive')}
                  <Box>
                    <Typography variant="body2" fontWeight={500}>Inconclusive</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Insufficient evidence to determine
                    </Typography>
                  </Box>
                </Box>
              }
            />
          </RadioGroup>
        </FormControl>

        {/* Resolution Category */}
        <FormControl fullWidth sx={{ mb: 3 }}>
          <FormLabel sx={{ mb: 1, fontWeight: 600 }}>
            Resolution Category *
          </FormLabel>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {resolutionCategories.map((category) => (
              <Chip
                key={category}
                label={category}
                onClick={() => setResolutionCategory(category)}
                color={resolutionCategory === category ? 'primary' : 'default'}
                variant={resolutionCategory === category ? 'filled' : 'outlined'}
                sx={{ mb: 1 }}
              />
            ))}
          </Stack>
        </FormControl>

        {/* Summary */}
        <TextField
          label="Investigation Summary *"
          multiline
          rows={4}
          fullWidth
          value={summary}
          onChange={(e) => setSummary(e.target.value)}
          placeholder="Provide a detailed summary of the investigation findings, actions taken, and resolution..."
          sx={{ mb: 3 }}
        />

        {/* Affected Assets */}
        <TextField
          label="Affected Assets (optional)"
          multiline
          rows={3}
          fullWidth
          value={affectedAssets}
          onChange={(e) => setAffectedAssets(e.target.value)}
          placeholder="List affected assets (one per line)&#10;Examples:&#10;server-web-01&#10;192.168.1.100&#10;john.doe@company.com"
          sx={{ mb: 3 }}
        />

        <Divider sx={{ my: 3 }} />

        {/* ML Feedback Section */}
        <Box>
          <FormControlLabel
            control={
              <Checkbox
                checked={provideMlFeedback}
                onChange={(e) => setProvideMlFeedback(e.target.checked)}
              />
            }
            label={
              <Box>
                <Typography variant="body2" fontWeight={600}>
                  Provide ML Feedback (Optional)
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Help improve detection accuracy by providing feedback
                </Typography>
              </Box>
            }
          />

          {provideMlFeedback && (
            <Box sx={{ mt: 2, pl: 4 }}>
              <FormControl component="fieldset" fullWidth sx={{ mb: 2 }}>
                <FormLabel component="legend" sx={{ fontSize: '0.875rem' }}>
                  Was the ML detection correct?
                </FormLabel>
                <RadioGroup
                  row
                  value={mlWasCorrect ? 'yes' : 'no'}
                  onChange={(e) => setMlWasCorrect(e.target.value === 'yes')}
                >
                  <FormControlLabel value="yes" control={<Radio size="small" />} label="Yes" />
                  <FormControlLabel value="no" control={<Radio size="small" />} label="No" />
                </RadioGroup>
              </FormControl>

              {verdict === 'false_positive' && (
                <TextField
                  label="False Positive Reason"
                  multiline
                  rows={2}
                  fullWidth
                  size="small"
                  value={falsePositiveReason}
                  onChange={(e) => setFalsePositiveReason(e.target.value)}
                  placeholder="Explain why this was a false positive..."
                  sx={{ mb: 2 }}
                />
              )}

              <TextField
                label="Missed Indicators"
                multiline
                rows={2}
                fullWidth
                size="small"
                value={missedIndicators}
                onChange={(e) => setMissedIndicators(e.target.value)}
                placeholder="List any indicators that should have been detected (one per line)..."
                sx={{ mb: 2 }}
              />

              <TextField
                label="Suggested Improvements"
                multiline
                rows={2}
                fullWidth
                size="small"
                value={suggestedImprovements}
                onChange={(e) => setSuggestedImprovements(e.target.value)}
                placeholder="Suggest improvements to detection logic..."
                sx={{ mb: 2 }}
              />

              <TextField
                label="Additional Feedback"
                multiline
                rows={2}
                fullWidth
                size="small"
                value={mlFeedbackNotes}
                onChange={(e) => setMlFeedbackNotes(e.target.value)}
                placeholder="Any other feedback for the ML system..."
              />
            </Box>
          )}
        </Box>
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={handleClose} disabled={submitting}>
          Cancel
        </Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={submitting || !summary.trim() || !resolutionCategory}
        >
          {submitting ? 'Closing...' : 'Close Investigation'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default VerdictModal;
