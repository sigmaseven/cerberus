/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

// https://vite.dev/config/
export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    // Remove unsafe-eval from CSP in production builds
    {
      name: 'html-transform-csp',
      transformIndexHtml(html) {
        if (mode === 'production') {
          // Remove 'unsafe-eval' from CSP for production security
          return html.replace(
            "script-src 'self' 'unsafe-eval';",
            "script-src 'self';"
          );
        }
        return html;
      },
    },
  ],
  esbuild: {
    // Skip TypeScript checking during build
    tsconfigRaw: {
      compilerOptions: {
        skipLibCheck: true,
        noImplicitAny: false,
        strict: false,
      },
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
  build: {
    // Optimize build output
    target: 'esnext',
    minify: 'esbuild',
    sourcemap: false, // Disable sourcemaps for production
    rollupOptions: {
      external: [
        // CodeMirror is optional and not currently installed
        'codemirror',
        '@codemirror/state',
        '@codemirror/view',
        '@codemirror/theme-one-dark',
        '@codemirror/autocomplete',
        '@codemirror/language',
        '@codemirror/lang-javascript',
      ],
      output: {
        // Code splitting for better caching
        manualChunks: {
          vendor: ['react', 'react-dom'],
          router: ['react-router-dom'],
          ui: ['@mui/material', '@mui/icons-material', '@emotion/react', '@emotion/styled'],
          charts: ['recharts'],
          utils: ['axios', 'zod', 'zustand'],
        },
        // Optimize chunk file names
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
    // Increase chunk size warning limit
    chunkSizeWarningLimit: 1000,
  },
  test: {
    globals: true,
    environment: 'happy-dom', // Use happy-dom instead of jsdom
    setupFiles: ['./src/test/setup.ts'],
  },
  server: {
    host: '0.0.0.0', // Listen on all interfaces (IPv4 and IPv6)
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
}))