import { useEffect, useState } from 'react';
import { Title, Text, Center, Group, Badge, Button, ActionIcon } from '@mantine/core';
import { IconServer, IconNetwork, IconApi, IconRefresh, IconSettings } from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';
import { getListeners } from '../services/api';
import { Loading } from '../components/Loading';
import { Card } from '../components/Card';
import type { ListenerConfig } from '../types';

export const Listeners = () => {
   const [config, setConfig] = useState<ListenerConfig | null>(null);
   const [loading, setLoading] = useState(true);

   const fetchConfig = async () => {
     try {
       const data = await getListeners();
       if (typeof data === 'object' && data !== null && 'syslog' in data && 'cef' in data && 'json' in data) {
         setConfig(data as ListenerConfig);
        } else {
          throw new Error('Invalid listener configuration format');
        }
    } catch {
        notifications.show({
          title: 'Error',
          message: 'Failed to load listener configuration',
         color: 'red',
       });
     } finally {
       setLoading(false);
     }
   };

   useEffect(() => {
     fetchConfig();
   }, []);

   if (loading) {
     return <Loading type="card" lines={6} />;
   }

   if (!config) {
     return (
       <Center style={{ height: '50vh' }}>
         <Text>Failed to load configuration</Text>
       </Center>
     );
   }

   const listeners = [
     {
       id: 'syslog',
       name: 'Syslog Listener',
       icon: <IconServer size={24} />,
       color: 'blue',
       config: config.syslog,
       protocol: 'UDP/TCP',
       description: 'Standard syslog message ingestion'
     },
     {
       id: 'cef',
       name: 'CEF Listener',
       icon: <IconNetwork size={24} />,
       color: 'green',
       config: config.cef,
       protocol: 'UDP/TCP',
       description: 'Common Event Format message processing'
     },
     {
       id: 'json',
       name: 'JSON Listener',
       icon: <IconApi size={24} />,
       color: 'orange',
       config: config.json,
       protocol: 'HTTP/UDP',
       description: 'Structured JSON event ingestion',
       tls: config.json.tls
     }
   ];

   return (
     <>
       <Group justify="space-between" mb="lg">
         <div>
           <Title order={2} className="text-text-primary">Listeners</Title>
           <Text size="sm" className="text-text-secondary">Event ingestion endpoints and protocols</Text>
         </div>
         <Button
           leftSection={<IconRefresh size={16} />}
           variant="outline"
           onClick={() => {
             setLoading(true);
             fetchConfig();
           }}
         >
           Refresh
         </Button>
       </Group>

       <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
         {listeners.map((listener) => (
           <Card
             key={listener.id}
             title={listener.name}
             subtitle={listener.description}
             icon={listener.icon}
             hoverable
           >
             <div className="space-y-3">
               <Group justify="space-between">
                 <div>
                   <Text size="sm" className="text-text-secondary">Host</Text>
                   <Text className="font-mono text-sm">{listener.config.host}</Text>
                 </div>
                 <div>
                   <Text size="sm" className="text-text-secondary">Port</Text>
                   <Text className="font-mono text-sm">{listener.config.port}</Text>
                 </div>
               </Group>

               <div>
                 <Text size="sm" className="text-text-secondary">Protocol</Text>
                 <Text size="sm">{listener.protocol}</Text>
               </div>

               {listener.tls !== undefined && (
                 <div>
                   <Text size="sm" className="text-text-secondary">TLS</Text>
                   <Badge
                     color={listener.tls ? 'green' : 'red'}
                     variant="light"
                     size="sm"
                   >
                     {listener.tls ? 'Enabled' : 'Disabled'}
                   </Badge>
                 </div>
               )}

               <Group justify="space-between" mt="md">
                 <Badge color="green" variant="dot" className="animate-pulse">
                   Active
                 </Badge>
                 <ActionIcon variant="light" color="blue" title="Configure">
                   <IconSettings size={16} />
                 </ActionIcon>
               </Group>
             </div>
           </Card>
         ))}
       </div>

       <Card className="mt-6" title="Listener Statistics" icon={<IconServer size={20} />}>
         <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
           <div className="text-center">
             <Text size="xl" fw={700} className="text-text-primary">3</Text>
             <Text size="sm" className="text-text-secondary">Active Listeners</Text>
           </div>
           <div className="text-center">
             <Text size="xl" fw={700} className="text-text-primary">514-516</Text>
             <Text size="sm" className="text-text-secondary">Port Range</Text>
           </div>
           <div className="text-center">
             <Text size="xl" fw={700} className="text-text-primary">0.0.0.0</Text>
             <Text size="sm" className="text-text-secondary">Bind Address</Text>
           </div>
           <div className="text-center">
             <Text size="xl" fw={700} className="text-text-primary">99.9%</Text>
             <Text size="sm" className="text-text-secondary">Uptime</Text>
           </div>
         </div>
       </Card>
     </>
   );
 };