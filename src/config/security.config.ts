/**
 * Security Configuration
 * Centralized configuration for security-related limits and settings
 */

export interface SecurityConfig {
  inputLimits: {
    maxInputLength: number;
    maxUsernameLength: number;
    maxEmailLength: number;
    maxMessageLength: number;
    maxPasswordLength: number;
  };
  rateLimiting: {
    windowMs: number;
    maxAttempts: number;
  };
  passwordPolicy: {
    minLength: number;
    requireComplexity: boolean;
  };
  sanitization: {
    allowedHtmlTags: string[];
    allowedProtocols: string[];
  };
}

export const securityConfig: SecurityConfig = {
  inputLimits: {
    maxInputLength: 10000,
    maxUsernameLength: 50,
    maxEmailLength: 254,
    maxMessageLength: 5000,
    maxPasswordLength: 128
  },
  rateLimiting: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 5
  },
  passwordPolicy: {
    minLength: 8,
    requireComplexity: true
  },
  sanitization: {
    allowedHtmlTags: ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'span', 'div', 'a'],
    allowedProtocols: ['http', 'https', 'mailto', 'tel']
  }
};

// Environment-specific overrides
if (__DEV__) {
  // More lenient limits for development
  securityConfig.inputLimits.maxInputLength = 50000;
  securityConfig.rateLimiting.maxAttempts = 10;
} else {
  // Stricter limits for production
  securityConfig.inputLimits.maxInputLength = 5000;
  securityConfig.rateLimiting.maxAttempts = 3;
}

export default securityConfig;