import { MantineProvider, createTheme } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { BrowserRouter as Router } from 'react-router-dom';
import { Layout } from './components/Layout';

const theme = createTheme({
  primaryColor: 'blue',
  defaultRadius: 'md',
  fontFamily: 'Inter, sans-serif',
  colors: {
    dark: [
      '#f0f6fc', // 0 - text primary
      '#c9d1d9', // 1
      '#8b949e', // 2 - text secondary
      '#6e7681', // 3
      '#484f58', // 4
      '#30363d', // 5 - borders
      '#21262d', // 6
      '#161b22', // 7 - background secondary
      '#0d1117', // 8 - background primary
      '#06090f', // 9
    ],
  },
  components: {
    Button: {
      defaultProps: {
        variant: 'filled',
      },
      styles: {
        root: {
          transition: 'all 150ms ease',
        },
      },
    },
    Card: {
      styles: {
        root: {
          transition: 'all 200ms ease',
        },
      },
    },
    Modal: {
      styles: {
        content: {
          backgroundColor: '#161b22',
          border: '1px solid #30363d',
        },
        header: {
          backgroundColor: '#161b22',
          borderBottom: '1px solid #30363d',
        },
        body: {
          backgroundColor: '#161b22',
        },
      },
    },
  },
});

function App() {
  return (
    <MantineProvider theme={theme} forceColorScheme="dark">
      <Notifications />
      <Router>
        <Layout />
      </Router>
    </MantineProvider>
  );
}

export default App;
