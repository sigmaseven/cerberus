import { Page, Locator } from '@playwright/test';

export class CorrelationRulesPage {
  readonly page: Page;
  readonly title: Locator;
  readonly addCorrelationRuleButton: Locator;
  readonly correlationRulesTable: Locator;
  readonly ruleEnabledSwitches: Locator;
  readonly editButtons: Locator;
  readonly deleteButtons: Locator;
  readonly createEditModal: Locator;
  readonly deleteModal: Locator;
  readonly nameInput: Locator;
  readonly descriptionTextarea: Locator;
  readonly severitySelect: Locator;
  readonly enabledCheckbox: Locator;
  readonly windowInput: Locator;
  readonly sequenceInput: Locator;
  readonly actionTypeSelect: Locator;
  readonly actionConfigTextarea: Locator;
  readonly submitButton: Locator;
  readonly cancelButton: Locator;
  readonly confirmDeleteButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.title = page.locator('h2').filter({ hasText: 'Correlation Rules' });
    this.addCorrelationRuleButton = page.locator('button').filter({ hasText: 'Add Correlation Rule' });
    this.correlationRulesTable = page.locator('table');
    this.ruleEnabledSwitches = page.locator('input[type="checkbox"]').filter({ hasText: 'Enabled' });
    this.editButtons = page.locator('button[aria-label="Edit correlation rule"]');
    this.deleteButtons = page.locator('button[aria-label="Delete correlation rule"]');
    this.createEditModal = page.locator('div[role="dialog"]').filter({ hasText: /^Add Correlation Rule|Edit Correlation Rule$/ });
    this.deleteModal = page.locator('div[role="dialog"]').filter({ hasText: 'Delete Correlation Rule' });
    this.nameInput = page.locator('input[label="Name"]');
    this.descriptionTextarea = page.locator('textarea[label="Description"]');
    this.severitySelect = page.locator('select[label="Severity"]');
    this.enabledCheckbox = page.locator('input[type="checkbox"][label="Enabled"]');
    this.windowInput = page.locator('input[label="Time Window (seconds)"]');
    this.sequenceInput = page.locator('input[label="Event Sequence (comma-separated)"]');
    this.actionTypeSelect = page.locator('select[label="Action Type"]');
    this.actionConfigTextarea = page.locator('textarea[label="Action Config (JSON)"]');
    this.submitButton = page.locator('button[type="submit"]');
    this.cancelButton = page.locator('button').filter({ hasText: 'Cancel' });
    this.confirmDeleteButton = page.locator('button').filter({ hasText: 'Delete' });
  }

  async goto() {
    await this.page.goto('/correlation-rules');
  }

  async openCreateCorrelationRuleModal() {
    await this.addCorrelationRuleButton.click();
  }

  async openEditCorrelationRuleModal(index: number = 0) {
    await this.editButtons.nth(index).click();
  }

  async openDeleteCorrelationRuleModal(index: number = 0) {
    await this.deleteButtons.nth(index).click();
  }

  async fillCorrelationRuleForm(data: {
    name: string;
    description: string;
    severity: string;
    enabled: boolean;
    window: number;
    sequence: string;
    actionType: string;
    actionConfig: string;
  }) {
    await this.nameInput.fill(data.name);
    await this.descriptionTextarea.fill(data.description);
    await this.severitySelect.selectOption(data.severity);
    if (data.enabled) {
      await this.enabledCheckbox.check();
    } else {
      await this.enabledCheckbox.uncheck();
    }
    await this.windowInput.fill(data.window.toString());
    await this.sequenceInput.fill(data.sequence);
    await this.actionTypeSelect.selectOption(data.actionType);
    await this.actionConfigTextarea.fill(data.actionConfig);
  }

  async submitCorrelationRuleForm() {
    await this.submitButton.click();
  }

  async cancelCorrelationRuleForm() {
    await this.cancelButton.first().click();
  }

  async confirmDeleteCorrelationRule() {
    await this.confirmDeleteButton.click();
  }

  async cancelDeleteCorrelationRule() {
    await this.cancelButton.nth(1).click();
  }

  async getCorrelationRuleCount() {
    return await this.correlationRulesTable.locator('tbody tr').count();
  }

  async toggleCorrelationRuleEnabled(index: number = 0) {
    await this.ruleEnabledSwitches.nth(index).click();
  }

  async getCorrelationRuleName(index: number = 0) {
    return await this.correlationRulesTable.locator('tbody tr').nth(index).locator('td').nth(0).textContent();
  }

  async getCorrelationRuleDescription(index: number = 0) {
    return await this.correlationRulesTable.locator('tbody tr').nth(index).locator('td').nth(1).textContent();
  }

  async getCorrelationRuleSeverity(index: number = 0) {
    return await this.correlationRulesTable.locator('tbody tr').nth(index).locator('td').nth(2).textContent();
  }

  async isCorrelationRuleEnabled(index: number = 0) {
    return await this.ruleEnabledSwitches.nth(index).isChecked();
  }
}