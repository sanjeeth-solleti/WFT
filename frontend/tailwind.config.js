/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        wft: {
          // Light Mode Palette
          lightBg: '#f1f5f9', // Slate 100
          lightPanel: '#ffffff', // Crisp white
          lightBorder: '#cbd5e1', // Slate 300
          lightHighlight: '#bae6fd', // Soft classic blue highlight
          lightText: '#0f172a', // Slate 900
          lightMuted: '#475569', // Slate 600

          // Dark Mode Palette
          darkBg: '#0f172a', // Slate 900
          darkPanel: '#1e293b', // Slate 800
          darkBorder: '#334155', // Slate 700
          darkHighlight: '#0c4a6e', // Sky 900
          darkText: '#f8fafc', // Slate 50
          darkMuted: '#94a3b8', // Slate 400

          // Primary Accents
          blue: '#0284c7', // Sky 600 (WFT Blue)
          blueHover: '#0369a1', // Sky 700
          blueLight: '#38bdf8', // Sky 400

          // Enterprise Status Badges (Strict Contrast)
          statusSuccess: '#166534', // Dark green
          statusError: '#991b1b', // Dark red
          statusRunning: '#1e40af', // Dark blue
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
