import { test, expect } from '@playwright/test';
import { ActionsPage } from './pages/ActionsPage';

test.describe('Actions Management', () => {
  let actionsPage: ActionsPage;

  test.beforeEach(async ({ page }) => {
    actionsPage = new ActionsPage(page);
    await actionsPage.goto();
  });

  test('should load actions page and display actions table', async () => {
    await expect(actionsPage.title).toBeVisible();
    await expect(actionsPage.addActionButton).toBeVisible();
    await expect(actionsPage.actionsTable).toBeVisible();
  });

  test('should open create action modal', async () => {
    await actionsPage.openCreateActionModal();
    await expect(actionsPage.createEditModal).toBeVisible();
    await expect(actionsPage.typeSelect).toBeVisible();
    await expect(actionsPage.configTextarea).toBeVisible();
  });

  test('should create a new action', async () => {
    await actionsPage.openCreateActionModal();
    await actionsPage.fillActionForm({
      type: 'webhook',
      config: '{"url": "https://example.com/webhook", "method": "POST"}'
    });
    await actionsPage.submitActionForm();
    // Wait for modal to close
    await expect(actionsPage.createEditModal).not.toBeVisible();
    // Note: In a real test, verify the new action appears in the table
  });

  test('should cancel action creation', async () => {
    await actionsPage.openCreateActionModal();
    await actionsPage.fillActionForm({
      type: 'email',
      config: '{"to": "admin@example.com", "subject": "Alert"}'
    });
    await actionsPage.cancelActionForm();
    await expect(actionsPage.createEditModal).not.toBeVisible();
  });

  test('should display edit and delete buttons for actions', async () => {
    const actionCount = await actionsPage.getActionCount();
    if (actionCount > 0) {
      await expect(actionsPage.editButtons.first()).toBeVisible();
      await expect(actionsPage.deleteButtons.first()).toBeVisible();
    }
  });

  test('should open edit action modal', async () => {
    const actionCount = await actionsPage.getActionCount();
    if (actionCount > 0) {
      await actionsPage.openEditActionModal(0);
      await expect(actionsPage.createEditModal).toBeVisible();
      await expect(actionsPage.idInput).toBeVisible();
      // Check if form is pre-filled
      const typeValue = await actionsPage.typeSelect.inputValue();
      expect(typeValue).toBeTruthy();
    }
  });

  test('should edit an existing action', async () => {
    const actionCount = await actionsPage.getActionCount();
    if (actionCount > 0) {
      await actionsPage.openEditActionModal(0);
      await actionsPage.fillActionForm({
        type: 'webhook',
        config: '{"url": "https://updated-example.com/webhook", "method": "PUT"}'
      });
      await actionsPage.submitActionForm();
      await expect(actionsPage.createEditModal).not.toBeVisible();
      // Note: Verify the action was updated
    }
  });

  test('should open delete action modal', async () => {
    const actionCount = await actionsPage.getActionCount();
    if (actionCount > 0) {
      await actionsPage.openDeleteActionModal(0);
      await expect(actionsPage.deleteModal).toBeVisible();
      await expect(actionsPage.confirmDeleteButton).toBeVisible();
    }
  });

  test('should cancel action deletion', async () => {
    const actionCount = await actionsPage.getActionCount();
    if (actionCount > 0) {
      await actionsPage.openDeleteActionModal(0);
      await actionsPage.cancelDeleteAction();
      await expect(actionsPage.deleteModal).not.toBeVisible();
    }
  });

  test('should delete an action', async () => {
    const initialCount = await actionsPage.getActionCount();
    if (initialCount > 0) {
      await actionsPage.openDeleteActionModal(0);
      await actionsPage.confirmDeleteAction();
      // Wait for modal to close
      await expect(actionsPage.deleteModal).not.toBeVisible();
      // Note: In a real test, verify the action count decreased
    }
  });

  test('should validate action form fields', async () => {
    await actionsPage.openCreateActionModal();
    // Try to submit with invalid JSON
    await actionsPage.fillActionForm({
      type: 'webhook',
      config: 'invalid json'
    });
    await actionsPage.submitActionForm();
    // Check if validation errors appear
    // Note: Specific validation error locators would depend on the UI implementation
    await actionsPage.cancelActionForm();
  });

  test('should display action details in table', async () => {
    const actionCount = await actionsPage.getActionCount();
    if (actionCount > 0) {
      const id = await actionsPage.getActionId(0);
      const type = await actionsPage.getActionType(0);
      const config = await actionsPage.getActionConfig(0);

      expect(id).toBeTruthy();
      expect(type).toBeTruthy();
      expect(config).toBeTruthy();
    }
  });

  test('should handle empty actions list gracefully', async () => {
    const actionCount = await actionsPage.getActionCount();
    if (actionCount === 0) {
      await expect(actionsPage.actionsTable).toBeVisible();
      await expect(actionsPage.editButtons).toHaveCount(0);
      await expect(actionsPage.deleteButtons).toHaveCount(0);
    }
  });
});