/**
 * RuleTestPanel Usage Examples
 *
 * This file demonstrates how to use the RuleTestPanel component
 * in various scenarios.
 */

import { useState } from 'react';
import { Box, Button, Dialog, DialogContent } from '@mui/material';
import { RuleTestPanel } from './RuleTestPanel';

// =============================================================================
// Example 1: Basic Usage in a Modal
// =============================================================================

export function RuleTestModalExample() {
  const [open, setOpen] = useState(false);
  const ruleId = 'rule-123'; // Your rule ID

  return (
    <Box>
      <Button variant="contained" onClick={() => setOpen(true)}>
        Test Rule
      </Button>

      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogContent>
          <RuleTestPanel
            ruleId={ruleId}
            onClose={() => setOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </Box>
  );
}

// =============================================================================
// Example 2: Inline Usage in Rule Details Page
// =============================================================================

export function RuleDetailsWithTestPanel({ ruleId }: { ruleId: string }) {
  const [showTestPanel, setShowTestPanel] = useState(false);

  return (
    <Box>
      {/* Rule details content */}
      <Box mb={2}>
        <h2>Rule Details</h2>
        <p>Rule ID: {ruleId}</p>
      </Box>

      {/* Toggle button */}
      <Button
        variant="outlined"
        onClick={() => setShowTestPanel(!showTestPanel)}
      >
        {showTestPanel ? 'Hide Test Panel' : 'Show Test Panel'}
      </Button>

      {/* Test panel */}
      {showTestPanel && (
        <Box mt={3}>
          <RuleTestPanel
            ruleId={ruleId}
            onClose={() => setShowTestPanel(false)}
          />
        </Box>
      )}
    </Box>
  );
}

// =============================================================================
// Example 3: Usage in Rule Creation Workflow
// =============================================================================

export function RuleCreationWizardExample() {
  const [currentStep, setCurrentStep] = useState<'create' | 'test'>('create');
  const [ruleId, setRuleId] = useState<string | null>(null);

  const handleRuleCreated = (newRuleId: string) => {
    setRuleId(newRuleId);
    setCurrentStep('test');
  };

  return (
    <Box>
      {currentStep === 'create' && (
        <Box>
          {/* Rule creation form */}
          <h2>Create New Rule</h2>
          <Button
            variant="contained"
            onClick={() => handleRuleCreated('new-rule-456')}
          >
            Create Rule
          </Button>
        </Box>
      )}

      {currentStep === 'test' && ruleId && (
        <Box>
          <h2>Test Your New Rule</h2>
          <RuleTestPanel
            ruleId={ruleId}
            onClose={() => setCurrentStep('create')}
          />
        </Box>
      )}
    </Box>
  );
}

// =============================================================================
// Example 4: Standalone Page
// =============================================================================

export function RuleTestPage() {
  const [selectedRuleId, setSelectedRuleId] = useState<string>('');

  return (
    <Box p={3}>
      <h1>Rule Testing</h1>

      {/* Rule selector */}
      <Box mb={3}>
        <input
          type="text"
          placeholder="Enter Rule ID"
          value={selectedRuleId}
          onChange={(e) => setSelectedRuleId(e.target.value)}
          style={{ padding: '8px', width: '300px' }}
        />
      </Box>

      {/* Test panel */}
      {selectedRuleId && (
        <RuleTestPanel ruleId={selectedRuleId} />
      )}
    </Box>
  );
}

// =============================================================================
// Example 5: Sample JSON Events for Testing
// =============================================================================

/**
 * Example events to use with the RuleTestPanel
 * Copy these into the JSON editor to test rules
 */

// Failed login events (for authentication rules)
export const FAILED_LOGIN_EVENTS = [
  {
    event_type: 'authentication_failure',
    timestamp: '2024-01-15T10:30:00Z',
    source_ip: '192.168.1.100',
    username: 'admin',
    result: 'failed',
    reason: 'invalid_password'
  },
  {
    event_type: 'authentication_failure',
    timestamp: '2024-01-15T10:30:05Z',
    source_ip: '192.168.1.100',
    username: 'admin',
    result: 'failed',
    reason: 'invalid_password'
  },
  {
    event_type: 'authentication_failure',
    timestamp: '2024-01-15T10:30:10Z',
    source_ip: '192.168.1.100',
    username: 'admin',
    result: 'failed',
    reason: 'invalid_password'
  }
];

// Suspicious file access (for file monitoring rules)
export const FILE_ACCESS_EVENTS = [
  {
    event_type: 'file_access',
    timestamp: '2024-01-15T10:30:00Z',
    source_ip: '10.0.0.50',
    username: 'user1',
    file_path: '/etc/passwd',
    action: 'read',
    process_name: 'cat'
  }
];

// Network connection events (for network rules)
export const NETWORK_EVENTS = [
  {
    event_type: 'network_connection',
    timestamp: '2024-01-15T10:30:00Z',
    source_ip: '192.168.1.50',
    destination_ip: '8.8.8.8',
    destination_port: 53,
    protocol: 'DNS',
    bytes_sent: 1024,
    bytes_received: 2048
  }
];

// Process execution events (for process monitoring rules)
export const PROCESS_EVENTS = [
  {
    event_type: 'process_creation',
    timestamp: '2024-01-15T10:30:00Z',
    process_name: 'powershell.exe',
    command_line: 'powershell.exe -ExecutionPolicy Bypass -File malicious.ps1',
    parent_process: 'cmd.exe',
    username: 'admin',
    source_ip: '192.168.1.100'
  }
];

// =============================================================================
// Example 6: Integration with Rule List
// =============================================================================

export function RuleListWithTestPanel() {
  const [testingRuleId, setTestingRuleId] = useState<string | null>(null);

  const rules = [
    { id: 'rule-1', name: 'Failed Login Detection' },
    { id: 'rule-2', name: 'Suspicious File Access' },
    { id: 'rule-3', name: 'Network Anomaly Detection' }
  ];

  return (
    <Box>
      {/* Rule list */}
      <Box mb={3}>
        <h2>Rules</h2>
        {rules.map((rule) => (
          <Box
            key={rule.id}
            display="flex"
            justifyContent="space-between"
            alignItems="center"
            mb={1}
            p={2}
            sx={{ border: '1px solid #ccc', borderRadius: '4px' }}
          >
            <span>{rule.name}</span>
            <Button
              variant="outlined"
              size="small"
              onClick={() => setTestingRuleId(rule.id)}
            >
              Test
            </Button>
          </Box>
        ))}
      </Box>

      {/* Test panel modal */}
      {testingRuleId && (
        <Dialog
          open={true}
          onClose={() => setTestingRuleId(null)}
          maxWidth="lg"
          fullWidth
        >
          <DialogContent>
            <RuleTestPanel
              ruleId={testingRuleId}
              onClose={() => setTestingRuleId(null)}
            />
          </DialogContent>
        </Dialog>
      )}
    </Box>
  );
}
