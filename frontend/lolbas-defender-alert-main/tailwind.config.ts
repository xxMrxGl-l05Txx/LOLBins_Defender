import type { Config } from "tailwindcss";
import defaultTheme from "tailwindcss/defaultTheme";

// Colors are HSL triplets in CSS variables (see src/index.css) so opacity modifiers work
const token = (name: string) => `hsl(var(--${name}) / <alpha-value>)`;

export default {
	darkMode: ["class"],
	content: ["./index.html", "./src/**/*.{ts,tsx}"],
	prefix: "",
	theme: {
		container: {
			center: true,
			padding: '2rem',
			screens: {
				'2xl': '1400px'
			}
		},
		extend: {
			fontFamily: {
				sans: ['"IBM Plex Sans"', ...defaultTheme.fontFamily.sans],
				mono: ['"IBM Plex Mono"', ...defaultTheme.fontFamily.mono],
			},
			fontSize: {
				'2xs': ['0.6875rem', { lineHeight: '1rem' }],
			},
			colors: {
				border: token('border'),
				input: token('input'),
				ring: token('ring'),
				background: token('background'),
				foreground: token('foreground'),
				primary: {
					DEFAULT: token('primary'),
					foreground: token('primary-foreground')
				},
				secondary: {
					DEFAULT: token('secondary'),
					foreground: token('secondary-foreground')
				},
				destructive: {
					DEFAULT: token('destructive'),
					foreground: token('destructive-foreground')
				},
				muted: {
					DEFAULT: token('muted'),
					foreground: token('muted-foreground')
				},
				accent: {
					DEFAULT: token('accent'),
					foreground: token('accent-foreground')
				},
				popover: {
					DEFAULT: token('popover'),
					foreground: token('popover-foreground')
				},
				card: {
					DEFAULT: token('card'),
					foreground: token('card-foreground')
				},
				sidebar: {
					DEFAULT: 'hsl(var(--sidebar-background))',
					foreground: 'hsl(var(--sidebar-foreground))',
					primary: 'hsl(var(--sidebar-primary))',
					'primary-foreground': 'hsl(var(--sidebar-primary-foreground))',
					accent: 'hsl(var(--sidebar-accent))',
					'accent-foreground': 'hsl(var(--sidebar-accent-foreground))',
					border: 'hsl(var(--sidebar-border))',
					ring: 'hsl(var(--sidebar-ring))'
				},
				brand: token('brand'),
				ok: token('ok'),
				sev: {
					critical: token('sev-critical'),
					high: token('sev-high'),
					medium: token('sev-medium'),
					low: token('sev-low'),
				},
			},
			borderRadius: {
				lg: 'var(--radius)',
				md: 'calc(var(--radius) - 1px)',
				sm: 'calc(var(--radius) - 2px)'
			},
			keyframes: {
				'accordion-down': {
					from: { height: '0' },
					to: { height: 'var(--radix-accordion-content-height)' }
				},
				'accordion-up': {
					from: { height: 'var(--radix-accordion-content-height)' },
					to: { height: '0' }
				},
				'slide-up': {
					from: { opacity: '0', transform: 'translateY(8px)' },
					to: { opacity: '1', transform: 'translateY(0)' },
				},
			},
			animation: {
				'accordion-down': 'accordion-down 0.2s ease-out',
				'accordion-up': 'accordion-up 0.2s ease-out',
				'slide-up': 'slide-up 0.25s ease-out',
			}
		}
	},
	plugins: [require("tailwindcss-animate")],
} satisfies Config;
