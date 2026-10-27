// React Theme — extracted from https://mosaic.cruip.com/
// Compatible with: Chakra UI, Stitches, Vanilla Extract, or any CSS-in-JS

/**
 * TypeScript type definition for this theme:
 *
 * interface Theme {
 *   colors: {
    primary: string;
    secondary: string;
    accent: string;
    background: string;
    foreground: string;
    neutral50: string;
    neutral100: string;
    neutral200: string;
    neutral300: string;
    neutral400: string;
    neutral500: string;
    neutral600: string;
    neutral700: string;
 *   };
 *   fonts: {
    body: string;
 *   };
 *   fontSizes: {
    '12': string;
    '14': string;
    '16': string;
    '18': string;
    '30': string;
    '30.08': string;
 *   };
 *   space: {
    '2': string;
    '32': string;
    '40': string;
 *   };
 *   radii: {
    xs: string;
    md: string;
    lg: string;
 *   };
 *   shadows: {
    xs: string;
    lg: string;
 *   };
 *   states: {
 *     hover: { opacity: number };
 *     focus: { opacity: number };
 *     active: { opacity: number };
 *     disabled: { opacity: number };
 *   };
 * }
 */

export const theme = {
  "colors": {
    "primary": "#ff1818",
    "secondary": "#8470ff",
    "accent": "#155dfc",
    "background": "#f3f4f6",
    "foreground": "#000000",
    "neutral50": "#e5e7eb",
    "neutral100": "#4b5563",
    "neutral200": "#9ca3af",
    "neutral300": "#ffffff",
    "neutral400": "#f3f4f6",
    "neutral500": "#6b7280",
    "neutral600": "#000000",
    "neutral700": "#bfc4cd"
  },
  "fonts": {
    "body": "'Inter', sans-serif"
  },
  "fontSizes": {
    "12": "12px",
    "14": "14px",
    "16": "16px",
    "18": "18px",
    "30": "30px",
    "30.08": "30.08px"
  },
  "space": {
    "2": "2px",
    "32": "32px",
    "40": "40px"
  },
  "radii": {
    "xs": "2px",
    "md": "8px",
    "lg": "16px"
  },
  "shadows": {
    "xs": "rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, oklab(0 0 0 / 0.08) 0px 1px 2px 0px",
    "lg": "rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0.1) 0px 10px 15px -3px, rgba(0, 0, 0, 0.1) 0px 4px 6px -4px"
  },
  "states": {
    "hover": {
      "opacity": 0.08
    },
    "focus": {
      "opacity": 0.12
    },
    "active": {
      "opacity": 0.16
    },
    "disabled": {
      "opacity": 0.38
    }
  }
};

// MUI v5 theme
export const muiTheme = {
  "palette": {
    "primary": {
      "main": "#ff1818",
      "light": "hsl(0, 100%, 70%)",
      "dark": "hsl(0, 100%, 40%)"
    },
    "secondary": {
      "main": "#8470ff",
      "light": "hsl(248, 100%, 87%)",
      "dark": "hsl(248, 100%, 57%)"
    },
    "background": {
      "default": "#f3f4f6",
      "paper": "#ffffff"
    },
    "text": {
      "primary": "#000000",
      "secondary": "#4b5563"
    }
  },
  "typography": {
    "fontFamily": "'Inter', sans-serif",
    "h2": {
      "fontSize": "30px",
      "fontWeight": "700",
      "lineHeight": "36px"
    },
    "body1": {
      "fontSize": "16px",
      "fontWeight": "400",
      "lineHeight": "24px"
    },
    "body2": {
      "fontSize": "12px",
      "fontWeight": "600",
      "lineHeight": "18px"
    }
  },
  "shape": {
    "borderRadius": 8
  },
  "shadows": [
    "rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0.05) 0px 1px 2px 0px",
    "rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, oklab(0 0 0 / 0.08) 0px 1px 2px 0px",
    "rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0) 0px 0px 0px 0px, rgba(0, 0, 0, 0.1) 0px 10px 15px -3px, rgba(0, 0, 0, 0.1) 0px 4px 6px -4px"
  ]
};

export default theme;
