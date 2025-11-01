import { Skeleton, Stack, Group, Card } from '@mantine/core';

interface LoadingProps {
  type?: 'page' | 'card' | 'table' | 'form';
  lines?: number;
}

export const Loading = ({ type = 'page', lines = 3 }: LoadingProps) => {
  if (type === 'card') {
    return (
      <Card shadow="sm" padding="lg" radius="md">
        <Skeleton height={24} width="60%" mb="md" />
        <Stack gap="sm">
          {Array.from({ length: lines }).map((_, i) => (
            <Skeleton key={i} height={16} width={`${80 - i * 10}%`} />
          ))}
        </Stack>
      </Card>
    );
  }

  if (type === 'table') {
    return (
      <Stack gap="sm">
        <Group justify="space-between">
          <Skeleton height={32} width={200} />
          <Group gap="xs">
            <Skeleton height={32} width={80} />
            <Skeleton height={32} width={80} />
          </Group>
        </Group>
        <Card shadow="sm" padding="lg" radius="md">
          <Skeleton height={40} mb="sm" />
          {Array.from({ length: lines }).map((_, i) => (
            <Skeleton key={i} height={48} mb="xs" />
          ))}
        </Card>
      </Stack>
    );
  }

  if (type === 'form') {
    return (
      <Stack gap="md">
        <Skeleton height={20} width="30%" />
        <Skeleton height={40} />
        <Skeleton height={20} width="25%" />
        <Skeleton height={40} />
        <Skeleton height={20} width="35%" />
        <Skeleton height={80} />
        <Group justify="flex-end" mt="md">
          <Skeleton height={36} width={80} />
          <Skeleton height={36} width={100} />
        </Group>
      </Stack>
    );
  }

  // Default page loading
  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Skeleton height={32} width={200} />
        <Skeleton height={32} width={120} />
      </Group>
      <Group grow>
        <Card shadow="sm" padding="lg" radius="md">
          <Skeleton height={24} width="60%" mb="md" />
          <Skeleton height={32} width="40%" />
        </Card>
        <Card shadow="sm" padding="lg" radius="md">
          <Skeleton height={24} width="60%" mb="md" />
          <Skeleton height={32} width="40%" />
        </Card>
      </Group>
      <Card shadow="sm" padding="lg" radius="md">
        <Skeleton height={24} width="50%" mb="md" />
        <Skeleton height={200} />
      </Card>
    </Stack>
  );
};