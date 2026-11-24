/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#050811',
        card: 'rgba(15, 23, 42, 0.45)',
        accent: {
          cyan: '#06B6D4',
          indigo: '#6366F1',
          rose: '#F43F5E',
          amber: '#F59E0B',
          emerald: '#10B981',
          sky: '#0EA5E9'
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif']
      },
      boxShadow: {
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.45)',
        'cyan-glow': '0 0 15px rgba(6, 182, 212, 0.35)',
        'rose-glow': '0 0 15px rgba(244, 63, 94, 0.35)'
      }
    },
  },
  plugins: [],
}
