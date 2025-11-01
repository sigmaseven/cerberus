import { Modal as MantineModal, Button, Group } from '@mantine/core';
import type { ModalProps as MantineModalProps } from '@mantine/core';
import type { ReactNode } from 'react';

interface ModalProps extends Omit<MantineModalProps, 'opened' | 'onClose'> {
  opened: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'auto';
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm?: () => void;
  loading?: boolean;
  showFooter?: boolean;
}

export const Modal = ({
  opened,
  onClose,
  title,
  children,
  size = 'lg',
  confirmLabel = 'Save',
  cancelLabel = 'Cancel',
  onConfirm,
  loading = false,
  showFooter = true,
  ...props
}: ModalProps) => {
  return (
    <MantineModal
      opened={opened}
      onClose={onClose}
      title={title}
      size={size}
      centered
      classNames={{
        content: 'bg-background-secondary border border-border',
        header: 'bg-background border-b border-border',
        body: 'bg-background-secondary',
      }}
      {...props}
    >
      <div className="p-4">
        {children}
      </div>
      {showFooter && (
        <div className="border-t border-border p-4 bg-background">
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose} disabled={loading}>
              {cancelLabel}
            </Button>
            {onConfirm && (
              <Button onClick={onConfirm} loading={loading}>
                {confirmLabel}
              </Button>
            )}
          </Group>
        </div>
      )}
    </MantineModal>
  );
};