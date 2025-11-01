import { Page, Locator } from '@playwright/test';

export class ActionsPage {
  readonly page: Page;
  readonly title: Locator;
  readonly addActionButton: Locator;
  readonly actionsTable: Locator;
  readonly editButtons: Locator;
  readonly deleteButtons: Locator;
  readonly createEditModal: Locator;
  readonly deleteModal: Locator;
  readonly idInput: Locator;
  readonly typeSelect: Locator;
  readonly configTextarea: Locator;
  readonly submitButton: Locator;
  readonly cancelButton: Locator;
  readonly confirmDeleteButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.title = page.locator('h2').filter({ hasText: 'Actions' });
    this.addActionButton = page.locator('button').filter({ hasText: 'Add Action' });
    this.actionsTable = page.locator('table');
    this.editButtons = page.locator('button[aria-label="Edit action"]');
    this.deleteButtons = page.locator('button[aria-label="Delete action"]');
    this.createEditModal = page.locator('div[role="dialog"]').filter({ hasText: /^Create Action|Edit Action$/ });
    this.deleteModal = page.locator('div[role="dialog"]').filter({ hasText: 'Confirm Delete' });
    this.idInput = page.locator('input[label="ID"]');
    this.typeSelect = page.locator('select[label="Type"]');
    this.configTextarea = page.locator('textarea[label="Config (JSON)"]');
    this.submitButton = page.locator('button[type="submit"]');
    this.cancelButton = page.locator('button').filter({ hasText: 'Cancel' });
    this.confirmDeleteButton = page.locator('button').filter({ hasText: 'Delete' });
  }

  async goto() {
    await this.page.goto('/actions');
  }

  async openCreateActionModal() {
    await this.addActionButton.click();
  }

  async openEditActionModal(index: number = 0) {
    await this.editButtons.nth(index).click();
  }

  async openDeleteActionModal(index: number = 0) {
    await this.deleteButtons.nth(index).click();
  }

  async fillActionForm(data: { type: string; config: string }) {
    await this.typeSelect.selectOption(data.type);
    await this.configTextarea.fill(data.config);
  }

  async submitActionForm() {
    await this.submitButton.click();
  }

  async cancelActionForm() {
    await this.cancelButton.first().click();
  }

  async confirmDeleteAction() {
    await this.confirmDeleteButton.click();
  }

  async cancelDeleteAction() {
    await this.cancelButton.nth(1).click();
  }

  async getActionCount() {
    return await this.actionsTable.locator('tbody tr').count();
  }

  async getActionId(index: number = 0) {
    return await this.actionsTable.locator('tbody tr').nth(index).locator('td').nth(0).textContent();
  }

  async getActionType(index: number = 0) {
    return await this.actionsTable.locator('tbody tr').nth(index).locator('td').nth(1).textContent();
  }

  async getActionConfig(index: number = 0) {
    return await this.actionsTable.locator('tbody tr').nth(index).locator('td').nth(2).textContent();
  }
}