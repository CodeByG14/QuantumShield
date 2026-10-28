/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Dark theme - Custom palette
        dark: {
          primary: '#010736',    // Darkest - main background
          secondary: '#0D1C42',  // Cards, surfaces
          tertiary: '#22396F',   // Borders, hover states
          accent: '#FCF1D0',     // Text, highlights
        },
        brand: {
          primary: '#ff1818',    // Keep red for errors/delete
          secondary: '#8470ff',
          accent: '#E3DAC0',
        },
        neutral: {
          100: '#e5e7eb',
          200: '#4b5563',
          300: '#9ca3af',
          400: '#ffffff',
          500: '#f3f4f6',
          600: '#6b7280',
          700: '#000000',
          800: '#bfc4cd',
        },
        background: {
          0: '#010736',    // Main background - darkest
          1: '#0D1C42',    // Card background
          2: '#22396F',    // Elevated surfaces
        },
        text: {
          0: '#FCF1D0',    // Primary text - cream/light
          1: '#E8DDB5',    // Secondary text (slightly darker cream)
          2: '#C8B895',    // Tertiary text
          3: '#A89875',    // Muted text
          4: '#FCF1D0',    // Headings
          5: '#8470ff',
          6: '#262b37',
          7: '#ffffff',
          8: '#155dfc',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      fontSize: {
        base: '16px',
      },
      spacing: {
        '2': '2px',
        '32': '32px',
        '40': '40px',
      },
      borderRadius: {
        'sm': '2px',
        'md': '8px',
        'lg': '12px',
        'xl': '16px',
      },
      transitionDuration: {
        '150': '150ms',
        '200': '200ms',
      },
    },
  },
  plugins: [],
}
