import { Card as MantineCard, Text, Group } from '@mantine/core';
import type { CardProps as MantineCardProps } from '@mantine/core';
import type { ReactNode } from 'react';

interface CardProps extends MantineCardProps {
  title?: string;
  subtitle?: string;
  icon?: ReactNode;
  children: ReactNode;
  hoverable?: boolean;
}

export const Card = ({
  title,
  subtitle,
  icon,
  children,
  hoverable = false,
  className = '',
  ...props
}: CardProps) => {
  return (
    <MantineCard
      shadow="sm"
      padding="lg"
      radius="md"
      className={`bg-background-secondary border border-border transition-all duration-200 ${
        hoverable ? 'hover:shadow-md hover:scale-[1.02] hover:border-accent-info/30' : ''
      } ${className}`}
      {...props}
    >
      {(title || subtitle || icon) && (
        <Group justify="space-between" mb="md">
          <div>
            {title && <Text size="lg" fw={600} className="text-text-primary">{title}</Text>}
            {subtitle && <Text size="sm" className="text-text-secondary">{subtitle}</Text>}
          </div>
          {icon && <div className="text-accent-info">{icon}</div>}
        </Group>
      )}
      {children}
    </MantineCard>
  );
};