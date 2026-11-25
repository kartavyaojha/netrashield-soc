/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#09090F',
        surface: '#12111B',
        card: '#161522',
        cardBorder: 'rgba(255, 255, 255, 0.08)',
        accent: {
          indigo: '#6366F1',
          violet: '#818CF8',
          purple: '#A855F7',
          fuchsia: '#D946EF',
          rose: '#F43F5E',
          amber: '#F59E0B',
          emerald: '#10B981',
          cyan: '#06B6D4'
        }
      },
      fontFamily: {
        sans: ['"Space Grotesk"', 'Inter', 'system-ui', 'sans-serif'],
        grotesk: ['"Space Grotesk"', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace']
      },
      letterSpacing: {
        tighter: '-0.04em',
        tight: '-0.02em',
      },
      lineHeight: {
        tightest: '1.02',
        snugger: '1.15',
      },
      boxShadow: {
        'bonanza': '0 24px 64px -12px rgba(0, 0, 0, 0.85)',
        'glow-indigo': '0 0 35px rgba(99, 102, 241, 0.25)',
        'glow-violet': '0 0 30px rgba(129, 140, 248, 0.20)',
        'pill': '0 4px 20px rgba(0, 0, 0, 0.5)',
      },
      borderRadius: {
        '3xl': '24px',
        '4xl': '32px'
      }
    },
  },
  plugins: [],
}
