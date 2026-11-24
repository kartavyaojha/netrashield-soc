/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#07090E',
        surface: '#0D111A',
        card: '#111726',
        cardBorder: 'rgba(255, 255, 255, 0.08)',
        accent: {
          blue: '#1F40E0',
          cyan: '#06B6D4',
          mint: '#1CCBB0',
          emerald: '#12A87A',
          amber: '#F2A930',
          rose: '#F43F5E'
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
        'bonanza': '0 24px 64px -12px rgba(0, 0, 0, 0.65)',
        'glow-blue': '0 0 35px rgba(31, 64, 224, 0.25)',
        'glow-cyan': '0 0 30px rgba(6, 182, 212, 0.25)',
        'pill': '0 4px 20px rgba(0, 0, 0, 0.4)',
      },
      borderRadius: {
        '3xl': '24px',
        '4xl': '32px'
      }
    },
  },
  plugins: [],
}
