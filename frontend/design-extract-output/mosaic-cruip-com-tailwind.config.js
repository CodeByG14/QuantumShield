/** @type {import('tailwindcss').Config} */
export default {
  theme: {
    extend: {
    colors: {
        primary: {
            '50': 'hsl(0, 100%, 97%)',
            '100': 'hsl(0, 100%, 94%)',
            '200': 'hsl(0, 100%, 86%)',
            '300': 'hsl(0, 100%, 76%)',
            '400': 'hsl(0, 100%, 64%)',
            '500': 'hsl(0, 100%, 50%)',
            '600': 'hsl(0, 100%, 40%)',
            '700': 'hsl(0, 100%, 32%)',
            '800': 'hsl(0, 100%, 24%)',
            '900': 'hsl(0, 100%, 16%)',
            '950': 'hsl(0, 100%, 10%)',
            DEFAULT: '#ff1818'
        },
        secondary: {
            '50': 'hsl(248, 100%, 97%)',
            '100': 'hsl(248, 100%, 94%)',
            '200': 'hsl(248, 100%, 86%)',
            '300': 'hsl(248, 100%, 76%)',
            '400': 'hsl(248, 100%, 64%)',
            '500': 'hsl(248, 100%, 50%)',
            '600': 'hsl(248, 100%, 40%)',
            '700': 'hsl(248, 100%, 32%)',
            '800': 'hsl(248, 100%, 24%)',
            '900': 'hsl(248, 100%, 16%)',
            '950': 'hsl(248, 100%, 10%)',
            DEFAULT: '#8470ff'
        },
        accent: {
            '50': 'hsl(221, 97%, 97%)',
            '100': 'hsl(221, 97%, 94%)',
            '200': 'hsl(221, 97%, 86%)',
            '300': 'hsl(221, 97%, 76%)',
            '400': 'hsl(221, 97%, 64%)',
            '500': 'hsl(221, 97%, 50%)',
            '600': 'hsl(221, 97%, 40%)',
            '700': 'hsl(221, 97%, 32%)',
            '800': 'hsl(221, 97%, 24%)',
            '900': 'hsl(221, 97%, 16%)',
            '950': 'hsl(221, 97%, 10%)',
            DEFAULT: '#155dfc'
        },
        'neutral-50': '#e5e7eb',
        'neutral-100': '#4b5563',
        'neutral-200': '#9ca3af',
        'neutral-300': '#ffffff',
        'neutral-400': '#f3f4f6',
        'neutral-500': '#6b7280',
        'neutral-600': '#000000',
        'neutral-700': '#bfc4cd',
        background: '#f3f4f6',
        foreground: '#000000'
    },
    fontFamily: {
        sans: [
            'Inter',
            'sans-serif'
        ]
    },
    fontSize: {
        '12': [
            '12px',
            {
                lineHeight: '18px'
            }
        ],
        '14': [
            '14px',
            {
                lineHeight: '22.001px'
            }
        ],
        '16': [
            '16px',
            {
                lineHeight: '24px'
            }
        ],
        '18': [
            '18px',
            {
                lineHeight: '27px',
                letterSpacing: '-0.18px'
            }
        ],
        '30': [
            '30px',
            {
                lineHeight: '36px'
            }
        ],
        '30.08': [
            '30.08px',
            {
                lineHeight: '40.0064px',
                letterSpacing: '-0.3008px'
            }
        ]
    },
    spacing: {
        '1': '2px',
        '16': '32px',
        '20': '40px'
    },
    borderRadius: {
        xs: '2px',
        md: '8px',
        lg: '16px'
    },
    boxShadow: {
        xs: 'rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0.05) 0px 1px 2px 0px',
        sm: 'rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0.1) 0px 10px 15px -3px, rgba(0, 0, 0, 0.1) 0px 4px 6px -4px'
    },
    transitionDuration: {
        '150': '0.15s',
        '200': '0.2s'
    },
    transitionTimingFunction: {
        custom: 'cubic-bezier(0.4, 0, 0.2, 1)'
    }
},
  },
};
