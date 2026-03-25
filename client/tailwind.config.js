/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
        display: ['"Space Grotesk"', 'sans-serif'],
        sans: ['"Inter"', 'system-ui', 'sans-serif'],
      },
      colors: {
        shield: {
          bg:      '#080c14',
          surface: '#0d1421',
          card:    '#111827',
          border:  '#1e2d45',
          accent:  '#00d4ff',
          glow:    '#0066ff',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'scan': 'scan 2s ease-in-out infinite',
        'fadeIn': 'fadeIn 0.4s ease forwards',
        'slideUp': 'slideUp 0.4s ease forwards',
      },
      keyframes: {
        scan:    { '0%,100%': { opacity: 0.4 }, '50%': { opacity: 1 } },
        fadeIn:  { from: { opacity: 0 }, to: { opacity: 1 } },
        slideUp: { from: { opacity: 0, transform: 'translateY(16px)' }, to: { opacity: 1, transform: 'translateY(0)' } },
      },
    },
  },
  plugins: [],
};
