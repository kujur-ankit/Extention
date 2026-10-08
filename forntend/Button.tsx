import React, { forwardRef } from 'react';

export type ButtonVariant = 'primary' | 'default' | 'ghost';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /**
   * Visual style variant of the button.
   * @default 'default'
   */
  variant?: ButtonVariant;

  /**
   * Size presets conforming to Ant Design spacing & typography standards.
   * @default 'md'
   */
  size?: ButtonSize;

  /**
   * If true, shows a spinner loader and disables user interaction.
   * @default false
   */
  isLoading?: boolean;

  /**
   * Optional custom icon rendered alongside the button label.
   */
  icon?: React.ReactNode;

  /**
   * Position of the icon relative to the children text.
   * @default 'left'
   */
  iconPosition?: 'left' | 'right';

  /**
   * If true, expands button to fill 100% of parent container width.
   * @default false
   */
  block?: boolean;

  /**
   * Button content / label.
   */
  children?: React.ReactNode;
}

/**
 * Spinner SVG component matching Ant Design's rotating circular indicator.
 */
const LoadingSpinner: React.FC<{ size: ButtonSize }> = ({ size }) => {
  const sizeMap: Record<ButtonSize, string> = {
    sm: 'w-3 h-3',
    md: 'w-3.5 h-3.5',
    lg: 'w-4.5 h-4.5',
  };

  return (
    <svg
      className={`animate-spin ${sizeMap[size]} shrink-0 text-current`}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="3.5"
      />
      <path
        className="opacity-80"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
};

/**
 * Production-ready <Button> component replicating Ant Design v5 aesthetic
 * using pure Tailwind CSS utility classes.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'default',
      size = 'md',
      isLoading = false,
      icon,
      iconPosition = 'left',
      block = false,
      disabled = false,
      className = '',
      children,
      ...props
    },
    ref
  ) => {
    // 1. Base Styles (Ant Design alignment, interaction & focus rings)
    const baseStyles =
      'inline-flex items-center justify-center font-medium transition-all duration-200 ' +
      'focus:outline-none focus:ring-2 focus:ring-blue-500/30 ' +
      'disabled:cursor-not-allowed select-none active:scale-[0.99] gap-2';

    // 2. Variant Specific Token Mappings
    const variantStyles: Record<ButtonVariant, string> = {
      // Vibrant blue background, white text, subtle glow shadow
      primary:
        'bg-[#1677ff] text-white shadow-sm shadow-blue-500/20 ' +
        'hover:bg-[#4096ff] ' +
        'active:bg-[#0958d9] ' +
        'disabled:bg-[#1677ff] disabled:opacity-60 disabled:shadow-none',

      // Default outline: White background, gray border, gray text with Ant Blue hover border/text
      default:
        'bg-white border border-gray-300 text-gray-700 shadow-sm shadow-black/5 ' +
        'hover:border-[#4096ff] hover:text-[#4096ff] hover:bg-white ' +
        'active:border-[#0958d9] active:text-[#0958d9] ' +
        'disabled:bg-gray-50 disabled:border-gray-200 disabled:text-gray-400 disabled:opacity-60',

      // Ghost (Text): Transparent background, gray text, light gray background on hover with Ant Blue text
      ghost:
        'bg-transparent text-gray-700 ' +
        'hover:bg-gray-100 hover:text-[#4096ff] ' +
        'active:bg-gray-200 active:text-[#0958d9] ' +
        'disabled:text-gray-400 disabled:opacity-60 disabled:hover:bg-transparent',
    };

    // 3. Size Styles (Ant Design compact spacing standards)
    const sizeStyles: Record<ButtonSize, string> = {
      sm: 'px-3 py-1.5 text-xs rounded',
      md: 'px-4 py-2 text-sm rounded-md',
      lg: 'px-6 py-3 text-base rounded-lg',
    };

    // 4. Width modifier
    const widthStyle = block ? 'w-full' : '';

    // Final combined class string
    const buttonClasses = [
      baseStyles,
      variantStyles[variant],
      sizeStyles[size],
      widthStyle,
      className,
    ]
      .filter(Boolean)
      .join(' ');

    const isDisabled = disabled || isLoading;

    return (
      <button
        ref={ref}
        disabled={isDisabled}
        aria-busy={isLoading}
        className={buttonClasses}
        {...props}
      >
        {/* Render Spinner when loading, or leading icon */}
        {isLoading ? (
          <LoadingSpinner size={size} />
        ) : (
          icon && iconPosition === 'left' && <span className="inline-flex shrink-0">{icon}</span>
        )}

        {/* Text Children */}
        {children && <span>{children}</span>}

        {/* Trailing icon if iconPosition === 'right' */}
        {!isLoading && icon && iconPosition === 'right' && (
          <span className="inline-flex shrink-0">{icon}</span>
        )}
      </button>
    );
  }
);

Button.displayName = 'Button';

export default Button;
