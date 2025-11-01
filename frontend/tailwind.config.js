/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0d1117',
        'background-secondary': '#161b22',
        'text-primary': '#f0f6fc',
        'text-secondary': '#8b949e',
        accent: {
          success: '#238636',
          warning: '#d29922',
          error: '#da3633',
          info: '#00d4ff',
        },
        border: '#30363d',
      },
    },
  },
  plugins: [],
}