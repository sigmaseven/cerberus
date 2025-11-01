import { createTheme } from '@mui/material/styles';

// Color palette as defined in the plan
const colors = {
  primary: '#1976d2',
  secondary: '#ff9800',
  success: '#4caf50',
  warning: '#ff9800',
  error: '#f44336',
  background: '#121212',
  surface: '#1e1e1e',
};

export const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: colors.primary,
    },
    secondary: {
      main: colors.secondary,
    },
    success: {
      main: colors.success,
    },
    warning: {
      main: colors.warning,
    },
    error: {
      main: colors.error,
    },
    background: {
      default: colors.background,
      paper: colors.surface,
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontSize: 'clamp(2rem, 5vw, 2.5rem)',
      fontWeight: 500,
    },
    h2: {
      fontSize: 'clamp(1.5rem, 4vw, 2rem)',
      fontWeight: 500,
    },
    h3: {
      fontSize: 'clamp(1.25rem, 3vw, 1.75rem)',
      fontWeight: 500,
    },
    h4: {
      fontSize: 'clamp(1.125rem, 2.5vw, 1.5rem)',
      fontWeight: 500,
    },
    h5: {
      fontSize: 'clamp(1rem, 2vw, 1.25rem)',
      fontWeight: 500,
    },
    h6: {
      fontSize: 'clamp(0.875rem, 1.5vw, 1rem)',
      fontWeight: 500,
    },
    body1: {
      fontSize: 'clamp(0.875rem, 2vw, 1rem)',
    },
    body2: {
      fontSize: 'clamp(0.75rem, 1.5vw, 0.875rem)',
    },
  },
  breakpoints: {
    values: {
      xs: 0,
      sm: 600,
      md: 900,
      lg: 1200,
      xl: 1536,
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          scrollbarWidth: 'thin',
          '&::-webkit-scrollbar': {
            width: '8px',
          },
          '&::-webkit-scrollbar-track': {
            background: colors.surface,
          },
          '&::-webkit-scrollbar-thumb': {
            background: colors.primary,
            borderRadius: '4px',
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          borderRadius: '8px',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
  },
});

export default theme;