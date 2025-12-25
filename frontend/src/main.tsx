import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { logSecurityAudit } from './utils/securityChecks'

// SECURITY: Run security audit in development mode
if (import.meta.env.DEV) {
  console.log('%c🔒 Running Security Audit...', 'color: #4CAF50; font-weight: bold; font-size: 14px;');
  // Delay to allow DOM to be ready
  setTimeout(() => {
    logSecurityAudit();
  }, 1000);
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
