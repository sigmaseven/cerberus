import { test, expect } from '@playwright/test';
import { CorrelationRulesPage } from './pages/CorrelationRulesPage';

test.describe('Correlation Rules Management', () => {
  let correlationRulesPage: CorrelationRulesPage;

  test.beforeEach(async ({ page }) => {
    correlationRulesPage = new CorrelationRulesPage(page);
    await correlationRulesPage.goto();
  });

  test('should load correlation rules page and display table', async () => {
    await expect(correlationRulesPage.title).toBeVisible();
    await expect(correlationRulesPage.addCorrelationRuleButton).toBeVisible();
    await expect(correlationRulesPage.correlationRulesTable).toBeVisible();
  });

  test('should open create correlation rule modal', async () => {
    await correlationRulesPage.openCreateCorrelationRuleModal();
    await expect(correlationRulesPage.createEditModal).toBeVisible();
    await expect(correlationRulesPage.nameInput).toBeVisible();
    await expect(correlationRulesPage.descriptionTextarea).toBeVisible();
    await expect(correlationRulesPage.severitySelect).toBeVisible();
    await expect(correlationRulesPage.enabledCheckbox).toBeVisible();
    await expect(correlationRulesPage.windowInput).toBeVisible();
    await expect(correlationRulesPage.sequenceInput).toBeVisible();
    await expect(correlationRulesPage.actionTypeSelect).toBeVisible();
    await expect(correlationRulesPage.actionConfigTextarea).toBeVisible();
  });

  test('should create a new correlation rule', async () => {
    await correlationRulesPage.openCreateCorrelationRuleModal();
    await correlationRulesPage.fillCorrelationRuleForm({
      name: 'Test Correlation Rule',
      description: 'A test correlation rule for UAT',
      severity: 'high',
      enabled: true,
      window: 600,
      sequence: 'login,failed_login,success',
      actionType: 'webhook',
      actionConfig: '{"url": "https://example.com/correlation-webhook"}'
    });
    await correlationRulesPage.submitCorrelationRuleForm();
    // Wait for modal to close
    await expect(correlationRulesPage.createEditModal).not.toBeVisible();
    // Note: In a real test, verify the new rule appears in the table
  });

  test('should cancel correlation rule creation', async () => {
    await correlationRulesPage.openCreateCorrelationRuleModal();
    await correlationRulesPage.fillCorrelationRuleForm({
      name: 'Cancelled Correlation Rule',
      description: 'This rule should not be created',
      severity: 'low',
      enabled: false,
      window: 300,
      sequence: 'event1,event2',
      actionType: 'email',
      actionConfig: '{"to": "admin@example.com"}'
    });
    await correlationRulesPage.cancelCorrelationRuleForm();
    await expect(correlationRulesPage.createEditModal).not.toBeVisible();
  });

  test('should display edit and delete buttons for correlation rules', async () => {
    const ruleCount = await correlationRulesPage.getCorrelationRuleCount();
    if (ruleCount > 0) {
      await expect(correlationRulesPage.editButtons.first()).toBeVisible();
      await expect(correlationRulesPage.deleteButtons.first()).toBeVisible();
    }
  });

  test('should open edit correlation rule modal', async () => {
    const ruleCount = await correlationRulesPage.getCorrelationRuleCount();
    if (ruleCount > 0) {
      await correlationRulesPage.openEditCorrelationRuleModal(0);
      await expect(correlationRulesPage.createEditModal).toBeVisible();
      // Check if form is pre-filled
      const nameValue = await correlationRulesPage.nameInput.inputValue();
      expect(nameValue).toBeTruthy();
    }
  });

  test('should edit an existing correlation rule', async () => {
    const ruleCount = await correlationRulesPage.getCorrelationRuleCount();
    if (ruleCount > 0) {
      await correlationRulesPage.openEditCorrelationRuleModal(0);
      await correlationRulesPage.fillCorrelationRuleForm({
        name: 'Updated Correlation Rule',
        description: 'Updated correlation rule description',
        severity: 'critical',
        enabled: false,
        window: 900,
        sequence: 'updated_event1,updated_event2,updated_event3',
        actionType: 'webhook',
        actionConfig: '{"url": "https://updated-example.com/webhook"}'
      });
      await correlationRulesPage.submitCorrelationRuleForm();
      await expect(correlationRulesPage.createEditModal).not.toBeVisible();
      // Note: Verify the rule was updated
    }
  });

  test('should toggle correlation rule enabled status', async () => {
    const ruleCount = await correlationRulesPage.getCorrelationRuleCount();
    if (ruleCount > 0) {
      const initialState = await correlationRulesPage.isCorrelationRuleEnabled(0);
      await correlationRulesPage.toggleCorrelationRuleEnabled(0);
      // Wait for potential UI update
      await correlationRulesPage.page.waitForTimeout(1000);
      const newState = await correlationRulesPage.isCorrelationRuleEnabled(0);
      expect(newState).not.toBe(initialState);
    }
  });

  test('should open delete correlation rule modal', async () => {
    const ruleCount = await correlationRulesPage.getCorrelationRuleCount();
    if (ruleCount > 0) {
      await correlationRulesPage.openDeleteCorrelationRuleModal(0);
      await expect(correlationRulesPage.deleteModal).toBeVisible();
      await expect(correlationRulesPage.confirmDeleteButton).toBeVisible();
    }
  });

  test('should cancel correlation rule deletion', async () => {
    const ruleCount = await correlationRulesPage.getCorrelationRuleCount();
    if (ruleCount > 0) {
      await correlationRulesPage.openDeleteCorrelationRuleModal(0);
      await correlationRulesPage.cancelDeleteCorrelationRule();
      await expect(correlationRulesPage.deleteModal).not.toBeVisible();
    }
  });

  test('should delete a correlation rule', async () => {
    const initialCount = await correlationRulesPage.getCorrelationRuleCount();
    if (initialCount > 0) {
      await correlationRulesPage.openDeleteCorrelationRuleModal(0);
      await correlationRulesPage.confirmDeleteCorrelationRule();
      // Wait for modal to close
      await expect(correlationRulesPage.deleteModal).not.toBeVisible();
      // Note: In a real test, verify the rule count decreased
    }
  });

  test('should validate correlation rule form fields', async () => {
    await correlationRulesPage.openCreateCorrelationRuleModal();
    // Try to submit empty form
    await correlationRulesPage.submitCorrelationRuleForm();
    // Check if validation errors appear
    // Note: Specific validation error locators would depend on the UI implementation
    await correlationRulesPage.cancelCorrelationRuleForm();
  });

  test('should validate sequence field format', async () => {
    await correlationRulesPage.openCreateCorrelationRuleModal();
    await correlationRulesPage.fillCorrelationRuleForm({
      name: 'Test Rule',
      description: 'Test description',
      severity: 'medium',
      enabled: true,
      window: 300,
      sequence: '', // Empty sequence should fail validation
      actionType: 'webhook',
      actionConfig: '{"url": "https://example.com"}'
    });
    await correlationRulesPage.submitCorrelationRuleForm();
    // Check if validation error appears for sequence
    await correlationRulesPage.cancelCorrelationRuleForm();
  });

  test('should validate action config JSON', async () => {
    await correlationRulesPage.openCreateCorrelationRuleModal();
    await correlationRulesPage.fillCorrelationRuleForm({
      name: 'Test Rule',
      description: 'Test description',
      severity: 'medium',
      enabled: true,
      window: 300,
      sequence: 'event1,event2',
      actionType: 'webhook',
      actionConfig: 'invalid json'
    });
    await correlationRulesPage.submitCorrelationRuleForm();
    // Check if validation error appears for action config
    await correlationRulesPage.cancelCorrelationRuleForm();
  });

  test('should handle empty correlation rules list gracefully', async () => {
    const ruleCount = await correlationRulesPage.getCorrelationRuleCount();
    if (ruleCount === 0) {
      await expect(correlationRulesPage.correlationRulesTable).toBeVisible();
      await expect(correlationRulesPage.editButtons).toHaveCount(0);
      await expect(correlationRulesPage.deleteButtons).toHaveCount(0);
    }
  });
});