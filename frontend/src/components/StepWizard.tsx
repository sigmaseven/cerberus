/**
 * Step Wizard Component
 *
 * Generic multi-step wizard with progress indicator, navigation,
 * and validation support.
 */

import React from 'react';
import {
  Box,
  Stepper,
  Step,
  StepLabel,
  Button,
  Typography,
  Paper,
  Divider,
  LinearProgress
} from '@mui/material';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import NavigateBeforeIcon from '@mui/icons-material/NavigateBefore';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

export interface WizardStep {
  /** Step label */
  label: string;

  /** Step description */
  description?: string;

  /** Step content component */
  content: React.ReactNode;

  /** Validation function - return error message or null if valid */
  validate?: () => string | null;

  /** Optional flag - if true, validation is skipped */
  optional?: boolean;

  /** Icon for the step */
  icon?: React.ReactNode;
}

export interface StepWizardProps {
  /** Array of wizard steps */
  steps: WizardStep[];

  /** Current active step (0-indexed) */
  activeStep: number;

  /** Callback when step changes */
  onStepChange: (step: number) => void;

  /** Callback when wizard is completed */
  onComplete: () => void;

  /** Callback when wizard is cancelled */
  onCancel: () => void;

  /** Complete button text */
  completeButtonText?: string;

  /** Cancel button text */
  cancelButtonText?: string;

  /** Show linear progress */
  showProgress?: boolean;

  /** Disable navigation while processing */
  loading?: boolean;

  /** Custom footer actions */
  customFooter?: React.ReactNode;
}

export function StepWizard({
  steps,
  activeStep,
  onStepChange,
  onComplete,
  onCancel,
  completeButtonText = 'Create Rule',
  cancelButtonText = 'Cancel',
  showProgress = true,
  loading = false,
  customFooter
}: StepWizardProps) {
  const [validationError, setValidationError] = React.useState<string | null>(null);

  const currentStep = steps[activeStep];
  const isFirstStep = activeStep === 0;
  const isLastStep = activeStep === steps.length - 1;

  const handleNext = () => {
    // Validate current step
    if (currentStep.validate && !currentStep.optional) {
      const error = currentStep.validate();
      if (error) {
        setValidationError(error);
        return;
      }
    }

    setValidationError(null);

    if (isLastStep) {
      onComplete();
    } else {
      onStepChange(activeStep + 1);
    }
  };

  const handleBack = () => {
    setValidationError(null);
    onStepChange(activeStep - 1);
  };

  const handleStepClick = (step: number) => {
    // Allow clicking on previous steps only
    if (step < activeStep) {
      setValidationError(null);
      onStepChange(step);
    }
  };

  const progressPercentage = ((activeStep + 1) / steps.length) * 100;

  return (
    <Box sx={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Progress Bar */}
      {showProgress && (
        <LinearProgress
          variant="determinate"
          value={progressPercentage}
          sx={{ mb: 2 }}
        />
      )}

      {/* Stepper */}
      <Stepper activeStep={activeStep} sx={{ mb: 3 }}>
        {steps.map((step, index) => {
          const stepProps: { completed?: boolean } = {};
          const labelProps: {
            optional?: React.ReactNode;
            error?: boolean;
          } = {};

          if (step.optional) {
            labelProps.optional = (
              <Typography variant="caption">Optional</Typography>
            );
          }

          if (index < activeStep) {
            stepProps.completed = true;
          }

          return (
            <Step
              key={step.label}
              {...stepProps}
              sx={{
                cursor: index < activeStep ? 'pointer' : 'default',
                '& .MuiStepLabel-root': {
                  cursor: index < activeStep ? 'pointer' : 'default'
                }
              }}
              onClick={() => handleStepClick(index)}
            >
              <StepLabel
                {...labelProps}
                StepIconComponent={
                  step.icon && index === activeStep
                    ? () => <>{step.icon}</>
                    : undefined
                }
              >
                <Typography variant="body2" fontWeight={index === activeStep ? 'bold' : 'normal'}>
                  {step.label}
                </Typography>
                {step.description && index === activeStep && (
                  <Typography variant="caption" color="text.secondary" display="block">
                    {step.description}
                  </Typography>
                )}
              </StepLabel>
            </Step>
          );
        })}
      </Stepper>

      {/* Step Content */}
      <Paper
        variant="outlined"
        sx={{
          flex: 1,
          p: 3,
          mb: 2,
          overflowY: 'auto',
          bgcolor: 'background.default'
        }}
      >
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
            <Typography>Loading...</Typography>
          </Box>
        ) : (
          currentStep.content
        )}
      </Paper>

      {/* Validation Error */}
      {validationError && (
        <Paper
          sx={{
            p: 2,
            mb: 2,
            bgcolor: 'error.light',
            color: 'error.contrastText'
          }}
        >
          <Typography variant="body2">{validationError}</Typography>
        </Paper>
      )}

      <Divider sx={{ mb: 2 }} />

      {/* Navigation Buttons */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Button
          onClick={onCancel}
          disabled={loading}
          variant="outlined"
        >
          {cancelButtonText}
        </Button>

        <Box sx={{ flex: 1, display: 'flex', justifyContent: 'center' }}>
          {customFooter}
        </Box>

        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            onClick={handleBack}
            disabled={isFirstStep || loading}
            startIcon={<NavigateBeforeIcon />}
          >
            Back
          </Button>
          <Button
            onClick={handleNext}
            disabled={loading}
            variant="contained"
            endIcon={isLastStep ? <CheckCircleIcon /> : <NavigateNextIcon />}
          >
            {isLastStep ? completeButtonText : 'Next'}
          </Button>
        </Box>
      </Box>

      {/* Step Progress Text */}
      <Box sx={{ mt: 1, textAlign: 'center' }}>
        <Typography variant="caption" color="text.secondary">
          Step {activeStep + 1} of {steps.length}
        </Typography>
      </Box>
    </Box>
  );
}

/**
 * Compact Step Wizard for smaller modals
 */
export interface CompactStepWizardProps extends StepWizardProps {
  /** Hide step descriptions */
  hideDescriptions?: boolean;
}

export function CompactStepWizard({
  hideDescriptions = true,
  ...props
}: CompactStepWizardProps) {
  const modifiedSteps = hideDescriptions
    ? props.steps.map(step => ({ ...step, description: undefined }))
    : props.steps;

  return (
    <StepWizard
      {...props}
      steps={modifiedSteps}
      showProgress={true}
    />
  );
}
