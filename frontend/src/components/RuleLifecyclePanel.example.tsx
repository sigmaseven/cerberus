/**
 * RuleLifecyclePanel Usage Examples
 *
 * This file demonstrates various ways to use the RuleLifecyclePanel component
 * in different contexts within the Cerberus SIEM application.
 */

import React, { useState } from 'react';
import {
  Box,
  Card,
  CardHeader,
  CardContent,
  Dialog,
  DialogContent,
  Tabs,
  Tab,
  Button,
} from '@mui/material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { RuleLifecyclePanel } from './RuleLifecyclePanel';
import { apiService } from '../services/api';
import type { LifecycleStatus, UnifiedRuleResponse } from '../types';

/**
 * Example 1: Basic Usage in Rule Detail Page
 */
export function RuleDetailPageExample() {
  const ruleId = 'rule-12345';

  // Fetch rule data
  const { data: ruleData, isLoading } = useQuery<UnifiedRuleResponse>({
    queryKey: ['rule', ruleId],
    queryFn: () => apiService.getUnifiedRule(ruleId),
  });

  if (isLoading) return <div>Loading...</div>;
  if (!ruleData) return <div>Rule not found</div>;

  const rule = ruleData.rule as { lifecycle_status?: LifecycleStatus };
  const currentStatus = rule.lifecycle_status || 'experimental';

  return (
    <Box sx={{ p: 3 }}>
      <Card>
        <CardHeader title={rule.name} subheader={rule.description} />
        <CardContent>
          <RuleLifecyclePanel
            ruleId={ruleId}
            currentStatus={currentStatus}
            onStatusChange={(newStatus) => {
              console.log('Status changed to:', newStatus);
            }}
          />
        </CardContent>
      </Card>
    </Box>
  );
}

/**
 * Example 2: In a Tabbed Modal Dialog
 */
export function RuleDetailModalExample() {
  const [open, setOpen] = useState(false);
  const [activeTab, setActiveTab] = useState(0);
  const ruleId = 'rule-12345';

  const { data: ruleData } = useQuery<UnifiedRuleResponse>({
    queryKey: ['rule', ruleId],
    queryFn: () => apiService.getUnifiedRule(ruleId),
    enabled: open, // Only fetch when modal is open
  });

  const rule = ruleData?.rule;
  const currentStatus = (rule as { lifecycle_status?: LifecycleStatus })?.lifecycle_status || 'experimental';

  return (
    <>
      <Button onClick={() => setOpen(true)}>View Rule Details</Button>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="lg" fullWidth>
        <Tabs value={activeTab} onChange={(_, val) => setActiveTab(val)}>
          <Tab label="Overview" />
          <Tab label="Detection" />
          <Tab label="Lifecycle" />
          <Tab label="History" />
        </Tabs>

        <DialogContent>
          {activeTab === 2 && rule && (
            <RuleLifecyclePanel
              ruleId={ruleId}
              currentStatus={currentStatus}
            />
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

/**
 * Example 3: With Local State Management
 */
export function RuleLifecycleWithStateExample() {
  const ruleId = 'rule-12345';
  const [currentStatus, setCurrentStatus] = useState<LifecycleStatus>('experimental');
  const queryClient = useQueryClient();

  const handleStatusChange = (newStatus: LifecycleStatus) => {
    // Update local state
    setCurrentStatus(newStatus);

    // Invalidate related queries to refresh data
    queryClient.invalidateQueries({ queryKey: ['rule', ruleId] });
    queryClient.invalidateQueries({ queryKey: ['rules'] });

    // Show success notification
    console.log(`Rule lifecycle updated to: ${newStatus}`);
  };

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto', p: 3 }}>
      <RuleLifecyclePanel
        ruleId={ruleId}
        currentStatus={currentStatus}
        onStatusChange={handleStatusChange}
      />
    </Box>
  );
}

/**
 * Example 4: Integration with Permission System
 */
export function RuleLifecycleWithPermissionsExample() {
  const ruleId = 'rule-12345';
  const currentStatus: LifecycleStatus = 'stable';

  // Example permission check (would use actual RBAC system)
  const canManageLifecycle = true; // usePermission('rules.lifecycle.manage');

  if (!canManageLifecycle) {
    return (
      <Box sx={{ p: 3 }}>
        <Card>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <div>Current Status: <strong>{currentStatus}</strong></div>
              <div>You do not have permission to manage rule lifecycle</div>
            </Box>
          </CardContent>
        </Card>
      </Box>
    );
  }

  return (
    <RuleLifecyclePanel
      ruleId={ruleId}
      currentStatus={currentStatus}
    />
  );
}

/**
 * Example 5: Side-by-Side with Rule Information
 */
export function RuleOverviewWithLifecycleExample() {
  const ruleId = 'rule-12345';
  const { data: ruleData } = useQuery<UnifiedRuleResponse>({
    queryKey: ['rule', ruleId],
    queryFn: () => apiService.getUnifiedRule(ruleId),
  });

  const rule = ruleData?.rule;
  const currentStatus = (rule as { lifecycle_status?: LifecycleStatus })?.lifecycle_status || 'experimental';

  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 3, p: 3 }}>
      {/* Rule Information */}
      <Card>
        <CardHeader title="Rule Information" />
        <CardContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <div>
              <strong>Name:</strong> {rule?.name}
            </div>
            <div>
              <strong>Description:</strong> {rule?.description}
            </div>
            <div>
              <strong>Severity:</strong> {rule?.severity}
            </div>
            <div>
              <strong>Enabled:</strong> {rule?.enabled ? 'Yes' : 'No'}
            </div>
          </Box>
        </CardContent>
      </Card>

      {/* Lifecycle Management */}
      <Box>
        <RuleLifecyclePanel
          ruleId={ruleId}
          currentStatus={currentStatus}
        />
      </Box>
    </Box>
  );
}

/**
 * Example 6: Standalone Lifecycle Manager
 */
export function StandaloneLifecycleManagerExample() {
  const [ruleId, setRuleId] = useState('rule-12345');

  const { data: ruleData } = useQuery<UnifiedRuleResponse>({
    queryKey: ['rule', ruleId],
    queryFn: () => apiService.getUnifiedRule(ruleId),
    enabled: !!ruleId,
  });

  const rule = ruleData?.rule;
  const currentStatus = (rule as { lifecycle_status?: LifecycleStatus })?.lifecycle_status || 'experimental';

  return (
    <Box sx={{ p: 3 }}>
      <Card sx={{ mb: 3 }}>
        <CardHeader title="Rule Lifecycle Manager" />
        <CardContent>
          <Box sx={{ mb: 3 }}>
            <label htmlFor="rule-select">Select Rule: </label>
            <select
              id="rule-select"
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              style={{ marginLeft: 8, padding: 8 }}
            >
              <option value="rule-12345">Suspicious Login Rule</option>
              <option value="rule-67890">Malware Detection Rule</option>
              <option value="rule-11111">Data Exfiltration Rule</option>
            </select>
          </Box>

          {rule && (
            <RuleLifecyclePanel
              ruleId={ruleId}
              currentStatus={currentStatus}
            />
          )}
        </CardContent>
      </Card>
    </Box>
  );
}

/**
 * Example 7: With Error Handling
 */
export function RuleLifecycleWithErrorHandlingExample() {
  const ruleId = 'rule-12345';
  const [error, setError] = useState<string | null>(null);

  const { data: ruleData, error: fetchError } = useQuery<UnifiedRuleResponse>({
    queryKey: ['rule', ruleId],
    queryFn: () => apiService.getUnifiedRule(ruleId),
  });

  const rule = ruleData?.rule;
  const currentStatus = (rule as { lifecycle_status?: LifecycleStatus })?.lifecycle_status || 'experimental';

  if (fetchError) {
    return (
      <Box sx={{ p: 3, color: 'error.main' }}>
        Error loading rule: {(fetchError as Error).message}
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {error && (
        <Box sx={{ mb: 2, p: 2, bgcolor: 'error.light', color: 'error.contrastText' }}>
          {error}
        </Box>
      )}

      {rule && (
        <RuleLifecyclePanel
          ruleId={ruleId}
          currentStatus={currentStatus}
          onStatusChange={(newStatus) => {
            setError(null);
            console.log('Successfully changed to:', newStatus);
          }}
        />
      )}
    </Box>
  );
}

/**
 * Example 8: Batch Lifecycle Management (Future Enhancement)
 */
export function BatchLifecycleExample() {
  const [selectedRules] = useState(['rule-1', 'rule-2', 'rule-3']);

  return (
    <Box sx={{ p: 3 }}>
      <Card>
        <CardHeader
          title="Batch Lifecycle Management"
          subheader={`${selectedRules.length} rules selected`}
        />
        <CardContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {selectedRules.map((ruleId) => (
              <Box key={ruleId} sx={{ borderBottom: 1, borderColor: 'divider', pb: 3 }}>
                <RuleLifecyclePanel
                  ruleId={ruleId}
                  currentStatus="experimental"
                />
              </Box>
            ))}
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}

// Export all examples
export default {
  RuleDetailPageExample,
  RuleDetailModalExample,
  RuleLifecycleWithStateExample,
  RuleLifecycleWithPermissionsExample,
  RuleOverviewWithLifecycleExample,
  StandaloneLifecycleManagerExample,
  RuleLifecycleWithErrorHandlingExample,
  BatchLifecycleExample,
};
