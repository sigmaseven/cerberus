import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { ThemeProvider } from '@mui/material/styles';
import { CssBaseline, CircularProgress, Box } from '@mui/material';
import { QueryClientProvider } from '@tanstack/react-query';
import { theme } from './theme';
import ErrorBoundary from './components/ErrorBoundary';
import Layout from './components/layout/Layout';
import { lazy, Suspense } from 'react';
import { queryClient } from './config/queryClient';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import FeedSetupWizard from './components/FeedSetupWizard';

// PERFORMANCE: Lazy load pages to reduce initial bundle size
// Login and Dashboard are eagerly loaded as they're needed immediately
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';

// Code-split secondary pages
const Alerts = lazy(() => import('./pages/Alerts'));
const Investigations = lazy(() => import('./pages/Investigations'));
const CreateInvestigation = lazy(() => import('./pages/CreateInvestigation'));
const InvestigationWorkspace = lazy(() => import('./pages/InvestigationWorkspace'));
const Events = lazy(() => import('./pages/Events'));
const EventSearch = lazy(() => import('./pages/EventSearch'));
const Rules = lazy(() => import('./pages/Rules'));
const RulesPerformance = lazy(() => import('./pages/Rules/PerformanceDashboard'));
const CorrelationRules = lazy(() => import('./pages/CorrelationRules'));
const Actions = lazy(() => import('./pages/Actions'));
const Listeners = lazy(() => import('./pages/Listeners'));
const ML = lazy(() => import('./pages/ML'));
const MitreMatrix = lazy(() => import('./pages/MitreMatrix'));
const MitreCoverage = lazy(() => import('./pages/MitreCoverage'));
const MitreKnowledgeBase = lazy(() => import('./pages/MitreKnowledgeBase'));
const MitreTechniqueDetail = lazy(() => import('./pages/MitreTechniqueDetail'));
const FieldMappings = lazy(() => import('./pages/FieldMappings'));
const Settings = lazy(() => import('./pages/Settings'));

/**
 * Loading fallback component for lazy-loaded routes
 */
const PageLoader = () => (
  <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
    <CircularProgress />
  </Box>
);

/**
 * PERFORMANCE OPTIMIZATION: Use cached auth context instead of fetching on every route
 *
 * BEFORE: Fetched /api/auth/config on every route change (N API calls)
 * AFTER: Uses cached auth context (1 API call on app startup)
 *
 * This reduces unnecessary API calls and improves navigation speed.
 */
function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { authEnabled, isAuthenticated, loading } = useAuth();
  const location = useLocation();

  // Show loading state while checking authentication
  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
      </Box>
    );
  }

  // Redirect to login if not authenticated and auth is enabled
  if (!isAuthenticated && authEnabled) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ThemeProvider theme={theme}>
            <CssBaseline />
            <FeedSetupWizard />
            <Router>
               <Routes>
                 <Route path="/login" element={<ErrorBoundary><Login /></ErrorBoundary>} />
                 <Route path="/" element={<Navigate to="/dashboard" replace />} />
                 <Route path="/dashboard" element={<PrivateRoute><Layout page={<ErrorBoundary><Dashboard /></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/alerts" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><Alerts /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/investigations" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><Investigations /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/investigations/new" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><CreateInvestigation /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/investigations/:id" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><InvestigationWorkspace /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/events" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><Events /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/event-search" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><EventSearch /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/rules" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><Rules /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/rules/performance" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><RulesPerformance /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/correlation-rules" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><CorrelationRules /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/actions" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><Actions /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/listeners" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><Listeners /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/ml" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><ML /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/mitre-matrix" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><MitreMatrix /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/mitre-coverage" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><MitreCoverage /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/mitre-kb" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><MitreKnowledgeBase /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/mitre/techniques/:id" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><MitreTechniqueDetail /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/field-mappings" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><FieldMappings /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="/settings" element={<PrivateRoute><Layout page={<ErrorBoundary><Suspense fallback={<PageLoader />}><Settings /></Suspense></ErrorBoundary>} /></PrivateRoute>} />
                 <Route path="*" element={<Navigate to="/dashboard" replace />} />
               </Routes>
            </Router>
          </ThemeProvider>
        </AuthProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;