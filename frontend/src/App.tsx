import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from '@mui/material/styles';
import { CssBaseline } from '@mui/material';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { theme } from './theme';
import ErrorBoundary from './components/ErrorBoundary';
import Layout from './components/layout/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Events from './pages/Events';
import EventSearch from './pages/EventSearch';
import Rules from './pages/Rules';
import CorrelationRules from './pages/CorrelationRules';
import Actions from './pages/Actions';
import Listeners from './pages/Listeners';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function PrivateRoute({ children }: { children: React.ReactNode }) {
  // Temporarily bypass authentication for development
  return <>{children}</>;
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider theme={theme}>
          <CssBaseline />
          <Router>
             <Routes>
               <Route path="/login" element={<Login />} />
               <Route path="/" element={<Navigate to="/dashboard" replace />} />
               <Route path="/dashboard" element={<PrivateRoute><Layout page={<Dashboard />} /></PrivateRoute>} />
               <Route path="/alerts" element={<PrivateRoute><Layout page={<Alerts />} /></PrivateRoute>} />
               <Route path="/events" element={<PrivateRoute><Layout page={<Events />} /></PrivateRoute>} />
               <Route path="/event-search" element={<PrivateRoute><Layout page={<EventSearch />} /></PrivateRoute>} />
               <Route path="/rules" element={<PrivateRoute><Layout page={<Rules />} /></PrivateRoute>} />
               <Route path="/correlation-rules" element={<PrivateRoute><Layout page={<CorrelationRules />} /></PrivateRoute>} />
               <Route path="/actions" element={<PrivateRoute><Layout page={<Actions />} /></PrivateRoute>} />
               <Route path="/listeners" element={<PrivateRoute><Layout page={<Listeners />} /></PrivateRoute>} />
               <Route path="*" element={<Navigate to="/dashboard" replace />} />
             </Routes>
          </Router>
        </ThemeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;