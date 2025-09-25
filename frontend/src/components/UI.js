import React from 'react';
import { UI_CONSTANTS } from '../constants';

// Button Component
export const Button = ({ 
  children, 
  onClick, 
  disabled = false, 
  variant = 'primary', 
  size = 'md',
  loading = false,
  ...props 
}) => {
  const getVariantStyles = () => {
    const variants = {
      primary: {
        background: UI_CONSTANTS.COLORS.PRIMARY,
        gradient: createGradientStyle(UI_CONSTANTS.COLORS.PRIMARY, UI_CONSTANTS.COLORS.PRIMARY_DARK),
        shadow: '0 4px 12px rgba(79, 70, 229, 0.3)',
        hoverShadow: '0 6px 16px rgba(79, 70, 229, 0.4)',
      },
      success: {
        background: UI_CONSTANTS.COLORS.SUCCESS,
        gradient: createGradientStyle(UI_CONSTANTS.COLORS.SUCCESS, UI_CONSTANTS.COLORS.SUCCESS_DARK),
        shadow: '0 4px 12px rgba(16, 185, 129, 0.3)',
        hoverShadow: '0 6px 16px rgba(16, 185, 129, 0.4)',
      },
      error: {
        background: UI_CONSTANTS.COLORS.ERROR,
        gradient: createGradientStyle(UI_CONSTANTS.COLORS.ERROR, UI_CONSTANTS.COLORS.ERROR_DARK),
        shadow: '0 2px 4px rgba(239, 68, 68, 0.3)',
        hoverShadow: '0 4px 8px rgba(239, 68, 68, 0.4)',
      },
    };
    return variants[variant] || variants.primary;
  };

  const getSizeStyles = () => {
    const sizes = {
      sm: { padding: '8px 16px', fontSize: '12px', height: '36px' },
      md: { padding: '12px 24px', fontSize: '14px', height: '48px' },
      lg: { padding: '14px 28px', fontSize: '14px', height: '52px' },
    };
    return sizes[size] || sizes.md;
  };

  const variantStyles = getVariantStyles();
  const sizeStyles = getSizeStyles();

  const buttonStyle = {
    ...variantStyles.gradient,
    color: 'white',
    border: 'none',
    borderRadius: UI_CONSTANTS.BORDER_RADIUS.MD,
    cursor: disabled || loading ? 'not-allowed' : 'pointer',
    fontWeight: '600',
    transition: 'all 0.2s ease',
    boxShadow: disabled || loading ? 'none' : variantStyles.shadow,
    minWidth: size === 'lg' ? '150px' : '120px',
    whiteSpace: 'nowrap',
    ...sizeStyles,
    ...props.style,
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      style={buttonStyle}
      {...createHoverEffect(variantStyles.shadow, variantStyles.hoverShadow)}
      {...props}
    >
      {loading ? '⏳ Loading...' : children}
    </button>
  );
};

// Input Component
export const Input = ({ 
  type = 'text', 
  placeholder, 
  value, 
  onChange, 
  onFocus, 
  onBlur,
  disabled = false,
  ...props 
}) => {
  const inputStyle = {
    width: '100%',
    padding: UI_CONSTANTS.SPACING.MD + ' ' + UI_CONSTANTS.SPACING.LG,
    border: `2px solid ${UI_CONSTANTS.COLORS.GRAY[200]}`,
    borderRadius: UI_CONSTANTS.BORDER_RADIUS.MD,
    fontSize: '14px',
    backgroundColor: 'white',
    transition: 'all 0.2s ease',
    cursor: disabled ? 'not-allowed' : 'pointer',
    boxSizing: 'border-box',
    opacity: disabled ? 0.6 : 1,
    ...props.style,
  };

  const handleFocus = (e) => {
    e.target.style.borderColor = UI_CONSTANTS.COLORS.PRIMARY;
    e.target.style.boxShadow = `0 0 0 3px rgba(79, 70, 229, 0.1)`;
    onFocus?.(e);
  };

  const handleBlur = (e) => {
    e.target.style.borderColor = UI_CONSTANTS.COLORS.GRAY[200];
    e.target.style.boxShadow = 'none';
    onBlur?.(e);
  };

  return (
    <input
      type={type}
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      onFocus={handleFocus}
      onBlur={handleBlur}
      disabled={disabled}
      style={inputStyle}
      {...props}
    />
  );
};

// Card Component
export const Card = ({ children, className, ...props }) => {
  const cardStyle = {
    background: 'white',
    border: `1px solid ${UI_CONSTANTS.COLORS.GRAY[200]}`,
    borderRadius: UI_CONSTANTS.BORDER_RADIUS.LG,
    padding: UI_CONSTANTS.SPACING.XXL,
    boxShadow: UI_CONSTANTS.SHADOWS.SM,
    ...props.style,
  };

  return (
    <div className={className} style={cardStyle} {...props}>
      {children}
    </div>
  );
};

// Alert Component
export const Alert = ({ type = 'info', children, ...props }) => {
  const getAlertStyles = () => {
    const types = {
      success: {
        backgroundColor: '#dcfce7',
        color: '#166534',
        borderColor: '#bbf7d0',
        icon: '✅',
      },
      error: {
        backgroundColor: '#fef2f2',
        color: '#991b1b',
        borderColor: '#fecaca',
        icon: '❌',
      },
      info: {
        backgroundColor: '#dbeafe',
        color: '#1e40af',
        borderColor: '#93c5fd',
        icon: 'ℹ️',
      },
      warning: {
        backgroundColor: '#fef3c7',
        color: '#92400e',
        borderColor: '#fde68a',
        icon: '⚠️',
      },
    };
    return types[type] || types.info;
  };

  const alertStyles = getAlertStyles();

  const alertStyle = {
    padding: UI_CONSTANTS.SPACING.MD + ' ' + UI_CONSTANTS.SPACING.LG,
    backgroundColor: alertStyles.backgroundColor,
    color: alertStyles.color,
    borderRadius: UI_CONSTANTS.BORDER_RADIUS.MD,
    fontSize: '14px',
    fontWeight: '500',
    border: `1px solid ${alertStyles.borderColor}`,
    display: 'flex',
    alignItems: 'center',
    gap: UI_CONSTANTS.SPACING.SM,
    ...props.style,
  };

  return (
    <div style={alertStyle} {...props}>
      <span>{alertStyles.icon}</span>
      {children}
    </div>
  );
};

// Helper functions
const createGradientStyle = (color1, color2, direction = '135deg') => ({
  background: `linear-gradient(${direction}, ${color1} 0%, ${color2} 100%)`,
});

const createHoverEffect = (baseShadow, hoverShadow) => ({
  onMouseOver: (e) => {
    if (!e.target.disabled) {
      e.target.style.transform = 'translateY(-1px)';
      e.target.style.boxShadow = hoverShadow;
    }
  },
  onMouseOut: (e) => {
    e.target.style.transform = 'translateY(0)';
    e.target.style.boxShadow = baseShadow;
  },
});
