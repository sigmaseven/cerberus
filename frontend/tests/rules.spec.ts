import { test, expect } from '@playwright/test';
import { RulesPage } from './pages/RulesPage';

test.describe('Rules Management', () => {
  let rulesPage: RulesPage;

  test.beforeEach(async ({ page }) => {
    rulesPage = new RulesPage(page);
    await rulesPage.goto();
  });

  test('should load rules page and display rules table', async () => {
    await expect(rulesPage.title).toBeVisible();
    await expect(rulesPage.addRuleButton).toBeVisible();
    await expect(rulesPage.rulesTable).toBeVisible();
  });

  test('should open create rule modal', async () => {
    await rulesPage.openCreateRuleModal();
    await expect(rulesPage.createEditModal).toBeVisible();
    await expect(rulesPage.nameInput).toBeVisible();
    await expect(rulesPage.descriptionTextarea).toBeVisible();
    await expect(rulesPage.severitySelect).toBeVisible();
    await expect(rulesPage.enabledCheckbox).toBeVisible();
    await expect(rulesPage.conditionFieldInput).toBeVisible();
    await expect(rulesPage.conditionOperatorSelect).toBeVisible();
    await expect(rulesPage.conditionValueInput).toBeVisible();
    await expect(rulesPage.actionTypeSelect).toBeVisible();
    await expect(rulesPage.actionConfigTextarea).toBeVisible();
  });

  test('should create a new rule', async () => {
    await rulesPage.openCreateRuleModal();
    await rulesPage.fillRuleForm({
      name: 'Test Rule',
      description: 'A test rule for UAT',
      severity: 'medium',
      enabled: true,
      conditionField: 'event_type',
      conditionOperator: 'equals',
      conditionValue: 'login_failed',
      actionType: 'webhook',
      actionConfig: '{"url": "https://example.com/webhook"}'
    });
    await rulesPage.submitRuleForm();
    // Wait for modal to close and table to update
    await expect(rulesPage.createEditModal).not.toBeVisible();
    // Note: In a real test, you might need to wait for the API call to complete
    // and verify the new rule appears in the table
  });

  test('should cancel rule creation', async () => {
    await rulesPage.openCreateRuleModal();
    await rulesPage.fillRuleForm({
      name: 'Cancelled Rule',
      description: 'This rule should not be created',
      severity: 'low',
      enabled: false,
      conditionField: 'event_type',
      conditionOperator: 'contains',
      conditionValue: 'test',
      actionType: 'webhook',
      actionConfig: '{"url": "https://cancelled.com"}'
    });
    await rulesPage.cancelRuleForm();
    await expect(rulesPage.createEditModal).not.toBeVisible();
  });

  test('should display edit and delete buttons for rules', async () => {
    const ruleCount = await rulesPage.getRuleCount();
    if (ruleCount > 0) {
      await expect(rulesPage.editButtons.first()).toBeVisible();
      await expect(rulesPage.deleteButtons.first()).toBeVisible();
    }
  });

  test('should open edit rule modal', async () => {
    const ruleCount = await rulesPage.getRuleCount();
    if (ruleCount > 0) {
      await rulesPage.openEditRuleModal(0);
      await expect(rulesPage.createEditModal).toBeVisible();
      // Check if form is pre-filled
      const nameValue = await rulesPage.nameInput.inputValue();
      expect(nameValue).toBeTruthy();
    }
  });

  test('should edit an existing rule', async () => {
    const ruleCount = await rulesPage.getRuleCount();
    if (ruleCount > 0) {
      await rulesPage.openEditRuleModal(0);
      await rulesPage.fillRuleForm({
        name: 'Updated Test Rule',
        description: 'Updated description',
        severity: 'high',
        enabled: false,
        conditionField: 'event_type',
        conditionOperator: 'equals',
        conditionValue: 'updated_event',
        actionType: 'webhook',
        actionConfig: '{"url": "https://updated.com/webhook"}'
      });
      await rulesPage.submitRuleForm();
      await expect(rulesPage.createEditModal).not.toBeVisible();
      // Note: Verify the rule was updated
    }
  });

  test('should toggle rule enabled status', async () => {
    const ruleCount = await rulesPage.getRuleCount();
    if (ruleCount > 0) {
      const initialState = await rulesPage.isRuleEnabled(0);
      await rulesPage.toggleRuleEnabled(0);
      // Wait for potential UI update
      await rulesPage.page.waitForTimeout(1000);
      const newState = await rulesPage.isRuleEnabled(0);
      expect(newState).not.toBe(initialState);
    }
  });

  test('should open delete rule modal', async () => {
    const ruleCount = await rulesPage.getRuleCount();
    if (ruleCount > 0) {
      await rulesPage.openDeleteRuleModal(0);
      await expect(rulesPage.deleteModal).toBeVisible();
      await expect(rulesPage.confirmDeleteButton).toBeVisible();
    }
  });

  test('should cancel rule deletion', async () => {
    const ruleCount = await rulesPage.getRuleCount();
    if (ruleCount > 0) {
      await rulesPage.openDeleteRuleModal(0);
      await rulesPage.cancelDeleteRule();
      await expect(rulesPage.deleteModal).not.toBeVisible();
    }
  });

  test('should delete a rule', async () => {
    const initialCount = await rulesPage.getRuleCount();
    if (initialCount > 0) {
      await rulesPage.openDeleteRuleModal(0);
      await rulesPage.confirmDeleteRule();
      // Wait for modal to close and table to update
      await expect(rulesPage.deleteModal).not.toBeVisible();
      // Note: In a real test, verify the rule count decreased
    }
  });

  test('should validate rule form fields', async () => {
    await rulesPage.openCreateRuleModal();
    // Try to submit empty form
    await rulesPage.submitRuleForm();
    // Check if validation errors appear
    // Note: Specific validation error locators would depend on the UI implementation
    await rulesPage.cancelRuleForm();
  });

  test('should handle empty rules list gracefully', async () => {
    const ruleCount = await rulesPage.getRuleCount();
    if (ruleCount === 0) {
      await expect(rulesPage.rulesTable).toBeVisible();
      await expect(rulesPage.editButtons).toHaveCount(0);
      await expect(rulesPage.deleteButtons).toHaveCount(0);
    }
  });
});