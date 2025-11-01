import { useState, useEffect } from 'react';
import { AppShell, Text, NavLink, Burger, Group, Breadcrumbs, Anchor, Skeleton } from '@mantine/core';
import { IconDashboard, IconList, IconSettings, IconAlertTriangle, IconServer, IconBolt, IconLink, IconChevronRight } from '@tabler/icons-react';
import { Outlet, Link, useLocation } from 'react-router-dom';

const navigationItems = [
  { label: 'Dashboard', icon: IconDashboard, path: '/', description: 'Overview, Charts, Recent Activity' },
  { label: 'Events', icon: IconList, path: '/events', description: 'Live feed, Search, Filters' },
  { label: 'Alerts', icon: IconAlertTriangle, path: '/alerts', description: 'Active, Acknowledged, Dismissed' },
  { label: 'Rules', icon: IconSettings, path: '/rules', description: 'Detection, Correlation' },
  { label: 'Correlation Rules', icon: IconLink, path: '/correlation-rules', description: 'Sequence-based detection' },
  { label: 'Listeners', icon: IconServer, path: '/listeners', description: 'Syslog, CEF, JSON endpoints' },
  { label: 'Actions', icon: IconBolt, path: '/actions', description: 'Webhooks, Notifications' },
];

const getBreadcrumbs = (pathname: string) => {
  const pathSegments = pathname.split('/').filter(Boolean);
  const breadcrumbs = [{ title: 'Dashboard', href: '/' }];

  if (pathSegments.length > 0) {
    const currentItem = navigationItems.find(item => item.path === `/${pathSegments[0]}`);
    if (currentItem) {
      breadcrumbs.push({ title: currentItem.label, href: currentItem.path });
    }
  }

  return breadcrumbs;
};

export const Layout = () => {
  const location = useLocation();
  const [sidebarOpened, setSidebarOpened] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate initial loading
    const timer = setTimeout(() => setLoading(false), 500);
    return () => clearTimeout(timer);
  }, []);

  const breadcrumbs = getBreadcrumbs(location.pathname);

  if (loading) {
    return (
      <AppShell
        header={{ height: 60 }}
        navbar={{ width: 300, breakpoint: 'sm', collapsed: { mobile: !sidebarOpened } }}
        padding="md"
      >
        <AppShell.Header className="bg-background border-b border-border">
          <Skeleton height={40} width={200} className="mx-4" />
        </AppShell.Header>
        <AppShell.Navbar p="xs" className="bg-background-secondary border-r border-border">
          <Skeleton height={40} className="mb-2" />
          <Skeleton height={40} className="mb-2" />
          <Skeleton height={40} className="mb-2" />
          <Skeleton height={40} className="mb-2" />
          <Skeleton height={40} className="mb-2" />
          <Skeleton height={40} className="mb-2" />
          <Skeleton height={40} className="mb-2" />
        </AppShell.Navbar>
        <AppShell.Main className="bg-background">
          <Skeleton height={50} className="mb-4" />
          <Skeleton height={200} className="mb-4" />
          <Skeleton height={300} />
        </AppShell.Main>
      </AppShell>
    );
  }

  return (
    <AppShell
      header={{ height: 60 }}
      navbar={{
        width: 300,
        breakpoint: 'sm',
        collapsed: { mobile: !sidebarOpened }
      }}
      padding="md"
    >
      <AppShell.Header className="bg-background border-b border-border">
        <Group justify="space-between" h="100%" px="md">
          <Group>
            <Burger
              opened={sidebarOpened}
              onClick={() => setSidebarOpened(!sidebarOpened)}
              hiddenFrom="sm"
              size="sm"
            />
            <Text size="xl" fw={700} className="text-text-primary">
              Cerberus SIEM
            </Text>
          </Group>
          <Text size="sm" className="text-text-secondary">
            Security Information & Event Management
          </Text>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="xs" className="bg-background-secondary border-r border-border">
        <div className="mb-4 px-2">
          <Text size="xs" fw={500} className="text-text-secondary uppercase tracking-wider">
            Navigation
          </Text>
        </div>
        {navigationItems.map((item) => {
          const IconComponent = item.icon;
          const isActive = location.pathname === item.path;
          return (
            <NavLink
              key={item.path}
              label={item.label}
              description={item.description}
              leftSection={<IconComponent size="1rem" />}
              component={Link}
              to={item.path}
              active={isActive}
              onClick={() => setSidebarOpened(false)}
              className={`mb-1 rounded-md transition-all duration-200 ${
                isActive
                  ? 'bg-accent-info/10 text-accent-info border-l-2 border-accent-info'
                  : 'text-text-primary hover:bg-background hover:text-accent-info'
              }`}
            />
          );
        })}
      </AppShell.Navbar>

      <AppShell.Main className="bg-background">
        <div className="mb-4">
          <Breadcrumbs separator={<IconChevronRight size={16} />} className="mb-2">
            {breadcrumbs.map((breadcrumb) => (
              <Anchor
                key={breadcrumb.href}
                component={Link}
                to={breadcrumb.href}
                size="sm"
                className="text-text-secondary hover:text-accent-info transition-colors"
              >
                {breadcrumb.title}
              </Anchor>
            ))}
          </Breadcrumbs>
        </div>
        <Outlet />
      </AppShell.Main>
    </AppShell>
  );
};