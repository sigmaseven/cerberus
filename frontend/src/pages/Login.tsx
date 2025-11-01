import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Typography, Button, Paper, Container } from '@mui/material';
import { useAuthStore } from '../stores/auth';

function Login() {
  const navigate = useNavigate();
  const login = useAuthStore((state) => state.login);

  const handleLogin = () => {
    // For development/demo purposes, auto-login with a test token
    login('demo-token');
    navigate('/dashboard');
  };

  useEffect(() => {
    // Auto-login for development
    const timer = setTimeout(() => {
      handleLogin();
    }, 1000);

    return () => clearTimeout(timer);
  }, []);

  return (
    <Container component="main" maxWidth="sm">
      <Box
        sx={{
          marginTop: 8,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
        }}
      >
        <Paper
          elevation={3}
          sx={{
            padding: 4,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            width: '100%',
          }}
        >
          <Typography component="h1" variant="h4" gutterBottom>
            Cerberus SIEM
          </Typography>
          <Typography variant="body1" color="textSecondary" sx={{ mb: 3 }}>
            Security Information and Event Management
          </Typography>
          <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
            Auto-login in progress...
          </Typography>
          <Button
            variant="contained"
            color="primary"
            onClick={handleLogin}
            sx={{ mt: 2 }}
          >
            Login (Demo)
          </Button>
        </Paper>
      </Box>
    </Container>
  );
}

export default Login;