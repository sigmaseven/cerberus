import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Title, Grid, Text, List, ThemeIcon, Button, Group, Badge } from '@mantine/core';
import { ResponsiveContainer, AreaChart, Area, CartesianGrid, XAxis, YAxis, Tooltip as RechartsTooltip } from 'recharts';
import { IconRefresh, IconTrendingUp, IconTrendingDown, IconActivity, IconAlertTriangle, IconBolt, IconEye, IconList } from '@tabler/icons-react';
import type { Event } from '../types';
import { getEvents, getDashboardStats, getDashboardChart } from '../services/api';
import { notifications } from '@mantine/notifications';
import { getSeverityColor, getSeverityIcon } from '../utils';
import { REFRESH_INTERVAL_MS } from '../constants';
import { Card } from '../components/Card';
import { Loading } from '../components/Loading';

export const Dashboard = () => {
  const [recentEvents, setRecentEvents] = useState<Event[]>([]);
  const [stats, setStats] = useState<{ total_events: number; total_alerts: number } | null>(null);
  const [chartData, setChartData] = useState<{ name: string; events: number; alerts: number }[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const mountedRef = useRef(true);
  const errorCountRef = useRef(0);

  const fetchRecentEvents = useCallback(async () => {
    try {
      const data = await getEvents(10);
      if (mountedRef.current) {
        setRecentEvents(data && Array.isArray(data) ? data : []);
      }
      errorCountRef.current = 0; // Reset on success
    } catch (error) {
      errorCountRef.current++;
      if (mountedRef.current) {
        notifications.show({
          title: 'Error',
          message: `Failed to load recent events: ${(error as Error).message}`,
          color: 'red',
        });
      }
    }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const data = await getDashboardStats();
      if (mountedRef.current) {
        setStats(data);
      }
      errorCountRef.current = 0; // Reset on success
    } catch (error) {
      errorCountRef.current++;
      if (mountedRef.current) {
        notifications.show({
          title: 'Error',
          message: `Failed to load dashboard stats: ${(error as Error).message}`,
          color: 'red',
        });
      }
    }
  }, []);

  const fetchChartData = useCallback(async () => {
    try {
      const data = await getDashboardChart();
      if (mountedRef.current) {
        setChartData(data);
      }
      errorCountRef.current = 0; // Reset on success
    } catch (error) {
      errorCountRef.current++;
      if (mountedRef.current) {
        notifications.show({
          title: 'Error',
          message: `Failed to load chart data: ${(error as Error).message}`,
          color: 'red',
        });
      }
    }
  }, []);

  useEffect(() => {
    Promise.all([fetchRecentEvents(), fetchStats(), fetchChartData()]).finally(() => {
      if (mountedRef.current) {
        setLoading(false);
      }
    });
  }, [fetchRecentEvents, fetchStats, fetchChartData]);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([fetchRecentEvents(), fetchStats(), fetchChartData()]);
    if (mountedRef.current) {
      setRefreshing(false);
    }
  };

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(async () => {
      if (!mountedRef.current || errorCountRef.current > 3) return;
      setRefreshing(true);
      await Promise.all([fetchRecentEvents(), fetchStats(), fetchChartData()]);
      if (mountedRef.current) {
        setRefreshing(false);
      }
    }, REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchRecentEvents, fetchStats, fetchChartData]);

  if (loading) {
    return <Loading type="page" />;
  }

  return (
    <>
      <Group justify="space-between" mb="lg">
        <div>
          <Title order={2} className="text-text-primary">Dashboard</Title>
          <Text size="sm" className="text-text-secondary">Real-time security monitoring overview</Text>
        </div>
        <Group>
          <Badge color="green" variant="dot" className="animate-pulse" title="Auto-refresh every 30 seconds">
            Live
          </Badge>
          <Button
            leftSection={<IconRefresh size="1rem" />}
            onClick={handleRefresh}
            loading={refreshing}
            variant="outline"
          >
            Refresh
          </Button>
        </Group>
      </Group>

      {/* KPI Cards */}
      <Grid mb="lg">
        <Grid.Col span={{ base: 12, sm: 6, lg: 3 }}>
          <Card
            title="Total Events"
            icon={<IconActivity size={24} />}
            hoverable
          >
            <Group justify="space-between" align="flex-end">
              <div>
                <Text size="xl" fw={700} className="text-text-primary">
                  {stats ? stats.total_events.toLocaleString() : '0'}
                </Text>
                <Text size="sm" className="text-text-secondary">Processed</Text>
              </div>
              <IconTrendingUp size={20} className="text-accent-success" />
            </Group>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 6, lg: 3 }}>
          <Card
            title="Active Alerts"
            icon={<IconAlertTriangle size={24} />}
            hoverable
          >
            <Group justify="space-between" align="flex-end">
              <div>
                <Text size="xl" fw={700} className="text-text-primary">
                  {stats ? stats.total_alerts.toLocaleString() : '0'}
                </Text>
                <Text size="sm" className="text-text-secondary">Requiring attention</Text>
              </div>
              <IconTrendingDown size={20} className="text-accent-warning" />
            </Group>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 6, lg: 3 }}>
          <Card
            title="System Status"
            icon={<IconBolt size={24} />}
            hoverable
          >
            <Group justify="space-between" align="flex-end">
              <div>
                <Text size="xl" fw={700} className="text-accent-success">
                  Healthy
                </Text>
                <Text size="sm" className="text-text-secondary">All systems operational</Text>
              </div>
              <div className="w-3 h-3 bg-accent-success rounded-full animate-pulse" />
            </Group>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 6, lg: 3 }}>
          <Card
            title="Quick Actions"
            icon={<IconEye size={24} />}
            hoverable
          >
            <Group gap="xs">
              <Button size="xs" variant="light" component="a" href="/events">
                View Events
              </Button>
              <Button size="xs" variant="light" color="orange" component="a" href="/alerts">
                Check Alerts
              </Button>
            </Group>
          </Card>
        </Grid.Col>
      </Grid>

      {/* Charts and Recent Activity */}
      <Grid>
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Card
            title="Events & Alerts Over Time"
            subtitle="Last 24 hours activity"
            icon={<IconActivity size={20} />}
          >
            <ResponsiveContainer width="100%" height={350}>
              <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="eventsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#00d4ff" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="alertsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#da3633" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#da3633" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                <XAxis
                  dataKey="name"
                  stroke="#8b949e"
                  fontSize={12}
                />
                <YAxis stroke="#8b949e" fontSize={12} />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: '#161b22',
                    border: '1px solid #30363d',
                    borderRadius: '6px',
                  }}
                />
                <YAxis stroke="#8b949e" fontSize={12} />
                <Area
                  type="monotone"
                  dataKey="events"
                  stroke="#00d4ff"
                  fillOpacity={1}
                  fill="url(#eventsGradient)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="alerts"
                  stroke="#da3633"
                  fillOpacity={1}
                  fill="url(#alertsGradient)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Card
            title="Recent Events"
            subtitle="Latest security events"
            icon={<IconList size={20} />}
          >
            <List spacing="sm">
              {recentEvents.slice(0, 8).map((event) => (
                <List.Item
                  key={event.event_id}
                  icon={
                    <ThemeIcon
                      color={getSeverityColor(event.severity)}
                      size={32}
                      radius="xl"
                      className="shadow-sm"
                    >
                      {React.createElement(getSeverityIcon(event.severity), { size: '1rem' })}
                    </ThemeIcon>
                  }
                  className="hover:bg-background rounded-md p-2 -m-2 transition-colors cursor-pointer"
                >
                  <div>
                    <Text size="sm" fw={500} className="text-text-primary">
                      {event.event_type}
                    </Text>
                    <Text size="xs" className="text-text-secondary">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </Text>
                  </div>
                </List.Item>
              ))}
              {recentEvents.length === 0 && (
                <Text size="sm" className="text-text-secondary italic">
                  No recent events
                </Text>
              )}
            </List>
            {recentEvents.length > 0 && (
            <Button
              variant="light"
              size="xs"
              fullWidth
              mt="md"
              component="a"
              href="/events"
              rightSection={<IconActivity size={14} />}
            >
              View All Events
            </Button>
            )}
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
};