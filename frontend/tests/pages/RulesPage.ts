import { Page, Locator } from '@playwright/test';

export class RulesPage {
  readonly page: Page;
  readonly title: Locator;
  readonly addRuleButton: Locator;
  readonly rulesTable: Locator;
  readonly ruleNameInputs: Locator;
  readonly ruleDescriptionInputs: Locator;
  readonly ruleSeveritySelects: Locator;
  readonly ruleEnabledSwitches: Locator;
  readonly editButtons: Locator;
  readonly deleteButtons: Locator;
  readonly createEditModal: Locator;
  readonly deleteModal: Locator;
  readonly nameInput: Locator;
  readonly descriptionTextarea: Locator;
  readonly severitySelect: Locator;
  readonly enabledCheckbox: Locator;
  readonly conditionFieldInput: Locator;
  readonly conditionOperatorSelect: Locator;
  readonly conditionValueInput: Locator;
  readonly actionTypeSelect: Locator;
  readonly actionConfigTextarea: Locator;
  readonly submitButton: Locator;
  readonly cancelButton: Locator;
  readonly confirmDeleteButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.title = page.locator('h2').filter({ hasText: 'Rules' });
    this.addRuleButton = page.locator('button').filter({ hasText: 'Add Rule' });
    this.rulesTable = page.locator('table');
    this.ruleNameInputs = page.locator('input[placeholder="Rule name"]');
    this.ruleDescriptionInputs = page.locator('textarea[placeholder="Rule description"]');
    this.ruleSeveritySelects = page.locator('select').filter({ hasText: 'Severity' });
    this.ruleEnabledSwitches = page.locator('input[type="checkbox"]').filter({ hasText: 'Enabled' });
    this.editButtons = page.locator('button[aria-label="Edit rule"]');
    this.deleteButtons = page.locator('button[aria-label="Delete rule"]');
    this.createEditModal = page.locator('div[role="dialog"]').filter({ hasText: /^Create Rule|Edit Rule$/ });
    this.deleteModal = page.locator('div[role="dialog"]').filter({ hasText: 'Confirm Delete' });
    this.nameInput = page.locator('input[label="Name"]');
    this.descriptionTextarea = page.locator('textarea[label="Description"]');
    this.severitySelect = page.locator('select[label="Severity"]');
    this.enabledCheckbox = page.locator('input[type="checkbox"][label="Enabled"]');
    this.conditionFieldInput = page.locator('input[placeholder="Field"]');
    this.conditionOperatorSelect = page.locator('select[placeholder="Operator"]');
    this.conditionValueInput = page.locator('input[placeholder="Value"]');
    this.actionTypeSelect = page.locator('select[placeholder="Action Type"]');
    this.actionConfigTextarea = page.locator('textarea[placeholder*="config"]');
    this.submitButton = page.locator('button[type="submit"]');
    this.cancelButton = page.locator('button').filter({ hasText: 'Cancel' });
    this.confirmDeleteButton = page.locator('button').filter({ hasText: 'Delete' });
  }

  async goto() {
    await this.page.goto('/rules');
  }

  async openCreateRuleModal() {
    await this.addRuleButton.click();
  }

  async openEditRuleModal(index: number = 0) {
    await this.editButtons.nth(index).click();
  }

  async openDeleteRuleModal(index: number = 0) {
    await this.deleteButtons.nth(index).click();
  }

  async fillRuleForm(data: {
    name: string;
    description: string;
    severity: string;
    enabled: boolean;
    conditionField: string;
    conditionOperator: string;
    conditionValue: string;
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
    await this.conditionFieldInput.fill(data.conditionField);
    await this.conditionOperatorSelect.selectOption(data.conditionOperator);
    await this.conditionValueInput.fill(data.conditionValue);
    await this.actionTypeSelect.selectOption(data.actionType);
    await this.actionConfigTextarea.fill(data.actionConfig);
  }

  async submitRuleForm() {
    await this.submitButton.click();
  }

  async cancelRuleForm() {
    await this.cancelButton.first().click();
  }

  async confirmDeleteRule() {
    await this.confirmDeleteButton.click();
  }

  async cancelDeleteRule() {
    await this.cancelButton.nth(1).click();
  }

  async getRuleCount() {
    return await this.rulesTable.locator('tbody tr').count();
  }

  async toggleRuleEnabled(index: number = 0) {
    await this.ruleEnabledSwitches.nth(index).click();
  }

  async getRuleName(index: number = 0) {
    return await this.rulesTable.locator('tbody tr').nth(index).locator('td').nth(0).textContent();
  }

  async getRuleDescription(index: number = 0) {
    return await this.rulesTable.locator('tbody tr').nth(index).locator('td').nth(1).textContent();
  }

  async getRuleSeverity(index: number = 0) {
    return await this.rulesTable.locator('tbody tr').nth(index).locator('td').nth(2).textContent();
  }

  async isRuleEnabled(index: number = 0) {
    return await this.ruleEnabledSwitches.nth(index).isChecked();
  }
}