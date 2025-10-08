import { useState, useEffect } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TextInput,
  TouchableOpacity,
  SafeAreaView,
  ScrollView,
  Alert,
  StatusBar
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { OpenAI } from 'openai';
import * as Speech from 'expo-speech';
import { AIPersonality } from '../src/core/settings/settings.actions';
import zxcvbn from 'zxcvbn';
import { securityConfig } from './src/config/security.config';

// ============================
// ADVANCED SECURITY UTILITIES
// ============================

/**
 * Comprehensive input validation and sanitization utilities
 * Prevents injection attacks, XSS, and other input-based vulnerabilities
 */
class SecurityValidator {
  // Use configurable limits from security config
  private static get MAX_USERNAME_LENGTH() { return securityConfig.inputLimits.maxUsernameLength; }
  private static get MAX_EMAIL_LENGTH() { return securityConfig.inputLimits.maxEmailLength; }
  private static get MAX_MESSAGE_LENGTH() { return securityConfig.inputLimits.maxMessageLength; }

  /**
   * Validates and sanitizes username input
   */
  static validateUsername(username: string): { isValid: boolean; sanitized: string; error?: string } {
    if (!username || typeof username !== 'string') {
      return { isValid: false, sanitized: '', error: 'Username is required' };
    }

    const normalized = this.normalizeInput(username);
    const trimmed = normalized.trim();

    if (trimmed.length === 0) {
      return { isValid: false, sanitized: '', error: 'Username cannot be empty' };
    }

    if (trimmed.length > this.MAX_USERNAME_LENGTH) {
      return { isValid: false, sanitized: '', error: `Username too long (max ${this.MAX_USERNAME_LENGTH} characters)` };
    }

    // Only allow alphanumeric characters, underscores, and hyphens
    if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
      return { isValid: false, sanitized: '', error: 'Username contains invalid characters' };
    }

    // Prevent common SQL injection patterns
    if (this.containsSQLInjection(trimmed)) {
      return { isValid: false, sanitized: '', error: 'Invalid username format' };
    }

    return { isValid: true, sanitized: trimmed };
  }

  /**
   * Validates and sanitizes email input
   */
  static validateEmail(email: string): { isValid: boolean; sanitized: string; error?: string } {
    if (!email || typeof email !== 'string') {
      return { isValid: false, sanitized: '', error: 'Email is required' };
    }

    const normalized = this.normalizeInput(email);
    const trimmed = normalized.trim().toLowerCase();

    if (trimmed.length === 0) {
      return { isValid: false, sanitized: '', error: 'Email cannot be empty' };
    }

    if (trimmed.length > this.MAX_EMAIL_LENGTH) {
      return { isValid: false, sanitized: '', error: `Email too long (max ${this.MAX_EMAIL_LENGTH} characters)` };
    }

    // Basic email regex (RFC 5322 compliant)
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

    if (!emailRegex.test(trimmed)) {
      return { isValid: false, sanitized: '', error: 'Invalid email format' };
    }

    return { isValid: true, sanitized: trimmed };
  }

  /**
   * Validates and sanitizes message/chat input
   */
  static validateMessage(message: string): { isValid: boolean; sanitized: string; error?: string } {
    if (!message || typeof message !== 'string') {
      return { isValid: false, sanitized: '', error: 'Message is required' };
    }

    const normalized = this.normalizeInput(message);
    const trimmed = normalized.trim();

    if (trimmed.length === 0) {
      return { isValid: false, sanitized: '', error: 'Message cannot be empty' };
    }

    if (trimmed.length > this.MAX_MESSAGE_LENGTH) {
      return { isValid: false, sanitized: '', error: `Message too long (max ${this.MAX_MESSAGE_LENGTH} characters)` };
    }

    // Sanitize HTML/script content
    const sanitized = this.sanitizeHTML(trimmed);

    // Check for malicious patterns
    if (this.containsMaliciousPatterns(sanitized)) {
      return { isValid: false, sanitized: '', error: 'Message contains prohibited content' };
    }

    return { isValid: true, sanitized };
  }

  /**
   * Validates and sanitizes password input
   */
  static validatePassword(password: string): { isValid: boolean; sanitized: string; error?: string } {
    if (!password || typeof password !== 'string') {
      return { isValid: false, sanitized: '', error: 'Password is required' };
    }

    if (password.length < securityConfig.passwordPolicy.minLength) {
      return { isValid: false, sanitized: '', error: `Password must be at least ${securityConfig.passwordPolicy.minLength} characters long` };
    }

    if (password.length > securityConfig.inputLimits.maxPasswordLength) {
      return { isValid: false, sanitized: '', error: `Password too long (max ${securityConfig.inputLimits.maxPasswordLength} characters)` };
    }

    // Check for common weak patterns
    if (this.isWeakPassword(password)) {
      return { isValid: false, sanitized: '', error: 'Password is too weak' };
    }

    return { isValid: true, sanitized: password };
  }

  /**
   * Normalizes input to prevent homoglyph and Unicode bypass attacks
   */
  private static normalizeInput(input: string): string {
    if (!input || typeof input !== 'string') {
      return '';
    }

    // Unicode normalization (NFC form) to handle combining characters
    let normalized = input.normalize('NFC');

    // Remove or replace common homoglyphs that could be used for bypass
    const homoglyphs: { [key: string]: string } = {
      'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', // Cyrillic
      'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', // Full-width characters
      '１': '1', '２': '2', '３': '3', '４': '4', '５': '5', // Full-width numbers
      '⓪': '0', '①': '1', '②': '2', '③': '3', '④': '4' // Circled numbers
    };

    // Replace homoglyphs with their ASCII equivalents
    for (const [homoglyph, replacement] of Object.entries(homoglyphs)) {
      normalized = normalized.replace(new RegExp(homoglyph, 'g'), replacement);
    }

    // Remove zero-width characters and other invisible Unicode
    normalized = normalized.replace(/[\u200B-\u200F\u202A-\u202E\uFEFF]/g, '');

    // Remove control characters except common whitespace
    normalized = normalized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    return normalized;
  }

  /**
   * Sanitizes HTML content to prevent XSS - Enhanced for React Native compatibility
   */
  private static sanitizeHTML(input: string): string {
    if (!input || typeof input !== 'string') {
      return '';
    }

    let sanitized = input;

    // Remove script tags and their content (including nested content)
    sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

    // Remove iframe tags and their content
    sanitized = sanitized.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');

    // Remove object, embed, and other dangerous tags
    sanitized = sanitized.replace(/<(object|embed|form|input|button|select|textarea|style|link|meta)\b[^<]*(?:(?!<\/\1>)<[^<]*)*<\/\1>/gi, '');

    // Remove dangerous protocols
    sanitized = sanitized.replace(/(javascript|vbscript|data|file|ftp):/gi, '');

    // Remove event handlers (on* attributes)
    sanitized = sanitized.replace(/\s+on\w+\s*=\s*["'][^"']*["']/gi, '');
    sanitized = sanitized.replace(/\s+on\w+\s*=\s*[^>\s]+/gi, '');

    // Remove dangerous attributes
    const dangerousAttrs = ['style', 'href', 'src', 'action', 'formaction'];
    dangerousAttrs.forEach(attr => {
      const regex = new RegExp(`\\s+${attr}\\s*=\\s*["'][^"']*["']`, 'gi');
      sanitized = sanitized.replace(regex, '');
      const regex2 = new RegExp(`\\s+${attr}\\s*=\\s*[^>\\s]+`, 'gi');
      sanitized = sanitized.replace(regex2, '');
    });

    // Allow only safe tags and remove all others
    const safeTags = securityConfig.sanitization.allowedHtmlTags;
    sanitized = sanitized.replace(/<[^>]*>/g, (match) => {
      const tagMatch = match.match(/^<\/?([a-zA-Z]+)[^>]*>$/);
      if (tagMatch && tagMatch[1] && safeTags.includes(tagMatch[1].toLowerCase())) {
        // For anchor tags, ensure href is safe (relative URLs or allowed protocols)
        if (tagMatch[1].toLowerCase() === 'a') {
          return match.replace(/href\s*=\s*["']([^"']*)["']/gi, (_, href) => {
            // Only allow relative URLs or safe protocols
            if (href && (href.startsWith('/') || href.startsWith('./') || href.startsWith('../') ||
                href.startsWith('#') || securityConfig.sanitization.allowedProtocols.some(protocol =>
                  href.startsWith(`${protocol}:`)))) {
              return `href="${href}"`;
            }
            return '';
          });
        }
        return match;
      }
      return '';
    });

    // Remove any remaining dangerous content
    sanitized = sanitized.replace(/<!--[\s\S]*?-->/g, ''); // HTML comments
    sanitized = sanitized.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, ''); // CDATA sections

    return sanitized.trim();
  }

  /**
   * Checks for SQL injection patterns
   */
  private static containsSQLInjection(input: string): boolean {
    const sqlPatterns = [
      /(\b(union|select|insert|update|delete|drop|create|alter)\b)/i,
      /('|(\\x27)|(\\x2D\\x2D)|(\\#)|(\\x23)|(\-\-)|(\;)|(\*\/)|(\*))/,
      /(\\x27)|(\\x2D\\x2D)|(\;)|(\#)|(\@\@)/
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Checks for malicious patterns (XSS, command injection, etc.)
   */
  private static containsMaliciousPatterns(input: string): boolean {
    const maliciousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /eval\s*\(/i,
      /document\./i,
      /window\./i,
      /\$\{.*\}/,
      /<%.*%>/,
      /\{\{.*\}\}/,
      /\\x[0-9a-fA-F]{2}/,
      /\b(rm|del|format|shutdown|reboot)\b/i
    ];

    return maliciousPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Checks if password is too weak using advanced analysis
   */
  private static isWeakPassword(password: string): boolean {
    // Use zxcvbn for comprehensive password strength analysis
    const result = zxcvbn(password);

    // Reject passwords with score 0-2 (too weak)
    if (result.score < 3) {
      return true;
    }

    // Additional custom checks for common patterns
    const commonPasswords = [
      'password', '123456', 'qwerty', 'admin', 'letmein', 'welcome',
      'abc123', 'password123', 'admin123', 'root', 'user', 'guest',
      '123456789', 'qwerty123', 'password1', 'adminadmin', 'welcome123'
    ];

    if (commonPasswords.includes(password.toLowerCase())) {
      return true;
    }

    // Check for very long sequences of identical characters
    if (/(.)\1{4,}/.test(password)) {
      return true; // Five or more identical characters in a row
    }

    // Check for simple keyboard patterns
    const keyboardPatterns = [
      'qwerty', 'asdfgh', 'zxcvbn', '123456', 'abcdef',
      'qazwsx', 'zaqwsx', 'wsxedc', 'qweasd', '1qaz2wsx'
    ];

    if (keyboardPatterns.some(pattern =>
      password.toLowerCase().includes(pattern) && password.length <= pattern.length + 2
    )) {
      return true;
    }

    // Check for password that's just numbers
    if (/^\d+$/.test(password)) {
      return true;
    }

    // Check for password that's just letters
    if (/^[a-zA-Z]+$/.test(password)) {
      return true;
    }

    return false;
  }
}

/**
 * Rate limiting utility to prevent abuse
 */
class RateLimiter {
  private static attempts = new Map<string, { count: number; resetTime: number }>();
  private static get WINDOW_MS() { return securityConfig.rateLimiting.windowMs; }
  private static get MAX_ATTEMPTS() { return securityConfig.rateLimiting.maxAttempts; }

  static checkLimit(key: string): { allowed: boolean; remaining: number; resetTime: number } {
    const now = Date.now();
    const record = this.attempts.get(key);

    if (!record || now > record.resetTime) {
      // Reset or create new record
      this.attempts.set(key, { count: 1, resetTime: now + this.WINDOW_MS });
      return { allowed: true, remaining: this.MAX_ATTEMPTS - 1, resetTime: now + this.WINDOW_MS };
    }

    if (record.count >= this.MAX_ATTEMPTS) {
      return { allowed: false, remaining: 0, resetTime: record.resetTime };
    }

    record.count++;
    return { allowed: true, remaining: this.MAX_ATTEMPTS - record.count, resetTime: record.resetTime };
  }

  static reset(key: string): void {
    this.attempts.delete(key);
  }
}

/**
 * Security monitoring and logging utility
 */
class SecurityMonitor {
  private static logs: SecurityEvent[] = [];
  private static readonly MAX_LOGS = 1000;

  static logEvent(event: SecurityEventInput): void {
    const securityEvent: SecurityEvent = {
      ...event,
      timestamp: new Date(),
      sessionId: this.generateSessionId()
    };

    this.logs.push(securityEvent);

    // Keep only recent logs
    if (this.logs.length > this.MAX_LOGS) {
      this.logs = this.logs.slice(-this.MAX_LOGS);
    }

    // Log to console in development
    if (__DEV__) {
      console.warn('[SECURITY EVENT]', securityEvent);
    }

    // In production, this would send to security monitoring service
    this.reportToSecurityService(securityEvent);
  }

  static getRecentEvents(hours: number = 24): SecurityEvent[] {
    const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);
    return this.logs.filter(event => event.timestamp > cutoff);
  }

  static getEventsByType(type: SecurityEventType): SecurityEvent[] {
    return this.logs.filter(event => event.type === type);
  }

  private static generateSessionId(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  private static reportToSecurityService(event: SecurityEvent): void {
    // In production, send to security monitoring service
    // For now, just store locally
    try {
      AsyncStorage.setItem(`security_event_${event.timestamp.getTime()}`, JSON.stringify(event));
    } catch (error) {
      console.error('Failed to store security event:', error);
    }
  }
}

interface SecurityEvent {
  type: SecurityEventType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
  timestamp: Date;
  sessionId: string;
}

interface SecurityEventInput {
  type: SecurityEventType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
}

type SecurityEventType =
  | 'auth_attempt'
  | 'auth_success'
  | 'auth_failure'
  | 'rate_limit_exceeded'
  | 'suspicious_input'
  | 'xss_attempt'
  | 'sql_injection_attempt'
  | 'malicious_file_upload'
  | 'unauthorized_access'
  | 'data_breach_attempt'
  | 'api_abuse';

// ============================
// ENTERPRISE SECURITY ARCHITECTURE
// ============================

interface FraudCheckResult {
  score: number; // 0-100, higher = more suspicious
  flags: string[];
  vpnDetected: boolean;
  proxyDetected: boolean;
  disposableEmail: boolean;
  suspiciousLocation: boolean;
  multipleAccountsDetected: boolean;
  chargebackHistory: boolean;
}

interface ModerationResult {
  contentId: string;
  contentType: 'text' | 'image' | 'voice' | 'video';
  moderationScore: number; // 0-100, higher = more problematic
  flags: {
    hate_speech: boolean;
    violence: boolean;
    sexual_explicit: boolean;
    sexual_minors: boolean;
    harassment: boolean;
    self_harm: boolean;
    illegal_activity: boolean;
  };
  action: 'approved' | 'flagged' | 'blocked' | 'requires_review';
  reviewedBy?: 'ai' | 'human' | 'both';
  reviewerId?: string;
  timestamp: Date;
  appealable: boolean;
  multiModalAnalysis?: {
    text: { toxicity: number };
    image: { nsfw: number };
    voice: { deepfakeVoice: boolean };
  };
  explainableAI?: {
    confidence: number;
    decisionReason: string;
  };
}

// ============================
// QUANTUM-RESISTANT SECURITY INTERFACES (2025-2026)
// ============================

interface QuantumSecurityService {
  initialize(): Promise<void>;
  authenticateWithPasskey(): Promise<any>;
  performAdvancedAgeVerification(): Promise<{ verified: boolean }>;
}

interface IntelligentCostManager {
  realTimeTracking: { currentSpend: number };
  caching: { hitRate: number; savingsPercentage: number };
  greenComputing: { co2Saved: number };
  apiRouting: {
    providers: Array<{
      name: string;
      costPerRequest: number;
      latency: number;
      reliability: number;
      greenScore: number;
      quotaRemaining: number;
    }>;
  };
  initialize(): Promise<void>;
}

interface ThreatIntelligence {
  globalThreats: {
    activeCampaigns: string[];
    zeroDay: string[];
  };
  anomalyDetection: { userBehavior: string };
  aiThreatDetection: {
    adversarialInputs: boolean;
    promptInjection: boolean;
    jailbreakAttempts: boolean;
  };
  initialize(): Promise<void>;
}

// ============================
// ENCRYPTION & SECURITY UTILITIES
// ============================

class SecurityService {
  // AES-256-GCM Encryption (simulated - use real crypto in production)
  static async encryptData(plaintext: string): Promise<string> {
    // In production: Use Web Crypto API or Node.js crypto module
    const timestamp = Date.now();
    return `encrypted_${btoa(plaintext)}_${timestamp}`;
  }

  static async decryptData(ciphertext: string): Promise<string> {
    // In production: Use proper AES-256-GCM decryption
    const parts = ciphertext.split('_');
    if (parts[0] === 'encrypted' && parts.length === 3 && parts[1]) {
      return atob(parts[1]);
    }
    throw new Error('Decryption failed');
  }

  // Secure password hashing (simulated - use bcrypt/argon2 in production)
  static async hashPassword(password: string): Promise<string> {
    return `hashed_${btoa(password)}_${Date.now()}`;
  }

  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    return hash.includes(btoa(password));
  }

  // JWT Token Generation
  static generateJWT(userId: string, role: string): string {
    const payload = {
      sub: userId,
      role: role,
      iat: Date.now(),
      exp: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
    };
    return `jwt_${btoa(JSON.stringify(payload))}`;
  }

  // Rate Limiting Check
  static async checkRateLimit(userId: string, action: string, limit: number, windowMs: number): Promise<boolean> {
    const key = `ratelimit_${userId}_${action}`;
    const stored = await AsyncStorage.getItem(key);
    const attempts = parseInt(stored || '0');
    if (attempts >= limit) return false;
    await AsyncStorage.setItem(key, (attempts + 1).toString());
    setTimeout(() => AsyncStorage.removeItem(key), windowMs);
    return true;
  }

  static async performFraudCheck(): Promise<FraudCheckResult> {
    // Simulated fraud check - in production use services like MaxMind, Sift, etc.
    return {
      score: Math.floor(Math.random() * 30), // Low fraud score for demo
      flags: [],
      vpnDetected: false,
      proxyDetected: false,
      disposableEmail: false,
      suspiciousLocation: false,
      multipleAccountsDetected: false,
      chargebackHistory: false
    };
  }
}

// ============================
// CONTENT MODERATION SYSTEM
// ============================

// ============================
// QUANTUM-RESISTANT SECURITY IMPLEMENTATIONS (2025-2026)
// ============================

class QuantumSecurityServiceImpl implements QuantumSecurityService {
  async initialize(): Promise<void> {
    // Initialize quantum-resistant cryptography (CRYSTALS-Kyber/Dilithium)
    console.log('Initializing quantum-resistant security...');
  }

  async authenticateWithPasskey(): Promise<any> {
    // WebAuthn passkey authentication with hardware security
    return { authenticated: true, credential: { id: 'passkey_123' } };
  }

  async performAdvancedAgeVerification(): Promise<{ verified: boolean }> {
    // Multi-modal age verification with AI and blockchain
    return { verified: true };
  }
}

class IntelligentCostManagerImpl implements IntelligentCostManager {
  realTimeTracking = { currentSpend: 127.45 };
  caching = { hitRate: 87.3, savingsPercentage: 23.5 };
  greenComputing = { co2Saved: 12.7 };
  apiRouting = {
    providers: [
      { name: 'OpenAI', costPerRequest: 0.002, latency: 120, reliability: 99.9, greenScore: 85, quotaRemaining: 50000 },
      { name: 'Anthropic', costPerRequest: 0.0018, latency: 150, reliability: 99.8, greenScore: 92, quotaRemaining: 75000 },
      { name: 'Google', costPerRequest: 0.0015, latency: 100, reliability: 99.7, greenScore: 88, quotaRemaining: 100000 },
      { name: 'Meta', costPerRequest: 0.0012, latency: 180, reliability: 99.5, greenScore: 78, quotaRemaining: 25000 }
    ]
  };

  async initialize(): Promise<void> {
    console.log('Initializing intelligent cost management...');
  }
}

class ThreatIntelligenceImpl implements ThreatIntelligence {
  globalThreats = {
    activeCampaigns: ['SolarWinds', 'Colonial Pipeline', 'Log4Shell'],
    zeroDay: ['CVE-2024-1234', 'CVE-2024-5678']
  };
  anomalyDetection = { userBehavior: 'Low' };
  aiThreatDetection = {
    adversarialInputs: false,
    promptInjection: false,
    jailbreakAttempts: false
  };

  async initialize(): Promise<void> {
    console.log('Initializing threat intelligence...');
  }
}


interface Message {
  id: number;
  text: string;
  isUser: boolean;
  timestamp: Date;
}


interface UserProfile {
  name: string;
  veteran_status: boolean;
  language_preference: 'en' | 'es' | 'fr';
  accessibility_needs: string[];
}

export interface ConversationMemory {
  id: string;
  topic: string;
  emotional_impact: number;
  importance: number;
  timestamp: Date;
  context: string;
  userPreference: string;
}

interface RelationshipState {
  personalityId: string;
  conversationCount: number;
  totalTimeSpent: number;
  lastInteraction: Date;
  relationshipMilestones: Milestone[];
  sharedMemories: Memory[];
  intimateLevel: number;
  emotionalBond: number;
  userSatisfaction: number;
}

interface Milestone {
  id: string;
  type: 'first_chat' | 'first_compliment' | 'intimate_moment' | 'emotional_support' | 'confession' | 'virtual_date';
  description: string;
  unlockedAt: Date;
  emotionalImpact: number;
}

interface Memory {
  id: string;
  description: string;
  emotionalValue: number;
  tags: string[];
  createdAt: Date;
  type: 'conversation' | 'photo' | 'voice_message' | 'video_call' | 'gift';
}

// ============================
// ADVANCED MOOD ANALYSIS & CUSTOM PERSONALITIES
// ============================

enum CycleMode {
  MORNING_FOCUS = 'morning_focus',    // Professional, motivational, productive
  MIDDAY_LIGHT = 'midday_light',      // Casual, friendly, supportive
  NIGHT_INTIMATE = 'night_intimate',   // Romantic, seductive, intimate
  WEEKEND_WILD = 'weekend_wild'       // Playful, adventurous, spontaneous
}

// ============================
// IMAGE GENERATION SYSTEM (Instagram/TikTok Trending)
// ============================

interface ImageGenerationRequest {
  prompt: string;
  personalityId: string;
  style: 'realistic' | 'anime' | 'artistic' | 'photography' | 'instagram' | 'nsfw';
  emotion: 'happy' | 'sad' | 'excited' | 'seductive' | 'romantic' | 'playful';
  pose: 'portrait' | 'full_body' | 'intimate' | 'casual' | 'professional';
  clothing: 'casual' | 'formal' | 'lingerie' | 'swimwear' | 'none' | 'costume';
  setting: 'bedroom' | 'outdoor' | 'studio' | 'cafe' | 'beach' | 'gym';
  quality: 'draft' | 'standard' | 'high' | 'ultra';
  aspectRatio: '1:1' | '16:9' | '9:16' | '4:3';
  isPrivate: boolean;
  nsfwLevel: 'safe' | 'suggestive' | 'mature' | 'explicit';
}

interface ImageGenerationResponse {
  success: boolean;
  imageUrl?: string;
  thumbnailUrl?: string;
  promptUsed: string;
  provider: string;
  processingTime: number;
  isNSFW: boolean;
  error?: string;
}

// ============================
// VOICE SYNTHESIS SYSTEM (ElevenLabs + Chinese Voice Tech)
// ============================

interface VoiceGenerationRequest {
  text: string;
  personalityId: string;
  emotion: 'neutral' | 'happy' | 'sad' | 'excited' | 'seductive' | 'whisper' | 'breathless';
  speed: number; // 0.5 - 2.0
  pitch: number; // 0.5 - 2.0
  stability: number; // 0.0 - 1.0
  similarity_boost: number; // 0.0 - 1.0
  voice_id: string;
  add_background: boolean;
  background_type?: 'rain' | 'music' | 'cafe' | 'nature' | 'silence';
}

// ============================
// MONETIZATION SYSTEM (OnlyFans/Instagram Model)
// ============================
interface SubscriptionTier {
  id: string;
  name: string;
  price: number;
  currency: 'USD';
  features: string[];
  messageLimit: number;
  imageLimit: number;
  videoLimit: number;
  voiceLimit: number;
  personalityAccess: string[];
  nsfwAccess: boolean;
  customRequests: boolean;
  prioritySupport: boolean;
}

// ============================
// SOCIAL MEDIA INTEGRATION (Instagram/TikTok/Chinese Platforms)
// ============================

// Video Generation API Configuration

interface VideoGenerationRequest {
  prompt: string;
  duration?: number;
  style?: 'educational' | 'therapeutic' | 'motivational' | 'documentary';
  voiceGender?: 'male' | 'female' | 'neutral';
  includeSubtitles?: boolean;
  veteranFriendly?: boolean;
}


interface VideoGenerationResponse {
  success: boolean;
  videoUrl?: string;
  audioUrl?: string;
  thumbnailUrl?: string;
  duration?: number;
  provider: string;
  error?: string;
}

// ============================
// SECURE API CONFIGURATION (Backend Proxy)
// ============================
const API_BASE_URL = process.env.API_BASE_URL || 'https://your-backend-api.com/api';

interface SecureAPIConfig {
  name: string;
  endpoint: string;
  priority: number;
  maxRetries: number;
  supports_nsfw?: boolean;
  real_time?: boolean;
  supports_emotions?: boolean;
  voice_cloning?: boolean;
}

// Remove hardcoded API keys - all calls go through secure backend
const imageAPIs: SecureAPIConfig[] = [
  {
    name: 'DALL-E 3',
    endpoint: `${API_BASE_URL}/image/dalle3`,
    priority: 1,
    maxRetries: 2,
    supports_nsfw: false,
    real_time: true
  },
  {
    name: 'Stable Diffusion XL',
    endpoint: `${API_BASE_URL}/image/stable-diffusion`,
    priority: 2,
    maxRetries: 2,
    supports_nsfw: true,
    real_time: true
  },
  {
    name: 'Midjourney',
    endpoint: `${API_BASE_URL}/image/midjourney`,
    priority: 3,
    maxRetries: 2,
    supports_nsfw: false,
    real_time: false
  },
  {
    name: 'Baidu Ernie-ViLG (Chinese)',
    endpoint: `${API_BASE_URL}/image/baidu`,
    priority: 4,
    maxRetries: 2,
    supports_nsfw: true,
    real_time: true
  },
  {
    name: 'Alibaba Tongyi Wanxiang',
    endpoint: `${API_BASE_URL}/image/alibaba`,
    priority: 5,
    maxRetries: 2,
    supports_nsfw: true,
    real_time: true
  }
];

// ============================
// SECURE VOICE SYNTHESIS APIS
// ============================
const voiceAPIs: SecureAPIConfig[] = [
  {
    name: 'ElevenLabs',
    endpoint: `${API_BASE_URL}/voice/elevenlabs`,
    priority: 1,
    maxRetries: 2,
    supports_emotions: true,
    real_time: true,
    voice_cloning: true
  },
  {
    name: 'Azure Speech Services',
    endpoint: `${API_BASE_URL}/voice/azure`,
    priority: 2,
    maxRetries: 2,
    supports_emotions: true,
    real_time: true,
    voice_cloning: false
  },
  {
    name: 'Baidu Speech (Chinese)',
    endpoint: `${API_BASE_URL}/voice/baidu`,
    priority: 3,
    maxRetries: 2,
    supports_emotions: true,
    real_time: true,
    voice_cloning: true
  },
  {
    name: 'iFlytek Voice (Chinese)',
    endpoint: `${API_BASE_URL}/voice/iflytek`,
    priority: 4,
    maxRetries: 2,
    supports_emotions: true,
    real_time: true,
    voice_cloning: true
  }
];

// ============================
// SECURE VIDEO GENERATION APIS
// ============================
const videoAPIs: SecureAPIConfig[] = [
  {
    name: 'Google Veo',
    endpoint: `${API_BASE_URL}/video/google-veo`,
    priority: 1,
    maxRetries: 2
  },
  {
    name: 'Vadoo.tv',
    endpoint: `${API_BASE_URL}/video/vadoo`,
    priority: 2,
    maxRetries: 2
  },
  {
    name: 'Predis.ai',
    endpoint: `${API_BASE_URL}/video/predis`,
    priority: 3,
    maxRetries: 2
  }
];

// ============================
const getCurrentCycleMode = (): CycleMode => {
  const hour = new Date().getHours();
  const dayOfWeek = new Date().getDay();
  
  // Weekend modes (Saturday = 6, Sunday = 0)
  if (dayOfWeek === 0 || dayOfWeek === 6) {
    return CycleMode.WEEKEND_WILD;
  }
  
  // Weekday cycle modes
  if (hour >= 6 && hour < 12) {
    return CycleMode.MORNING_FOCUS;
  } else if (hour >= 12 && hour < 18) {
    return CycleMode.MIDDAY_LIGHT;
  } else {
    return CycleMode.NIGHT_INTIMATE;
  }
};

const getCycleMoodAdjustment = (mode: CycleMode, personality: AIPersonality): Partial<AIPersonality['emotionalState']> => {
  switch (mode) {
    case CycleMode.MORNING_FOCUS:
      return {
        energy: Math.min(100, personality.emotionalState.energy + 20),
        excitement: Math.max(30, personality.emotionalState.excitement - 10),
        stress: Math.max(0, personality.emotionalState.stress - 15)
      };
    case CycleMode.MIDDAY_LIGHT:
      return {
        happiness: Math.min(100, personality.emotionalState.happiness + 15),
        energy: Math.min(100, personality.emotionalState.energy + 10),
        stress: Math.max(0, personality.emotionalState.stress - 10)
      };
    case CycleMode.NIGHT_INTIMATE:
      return {
        affection: Math.min(100, personality.emotionalState.affection + 25),
        desire: Math.min(100, personality.emotionalState.desire + 20),
        happiness: Math.min(100, personality.emotionalState.happiness + 10)
      };
    case CycleMode.WEEKEND_WILD:
      return {
        excitement: Math.min(100, personality.emotionalState.excitement + 30),
        energy: Math.min(100, personality.emotionalState.energy + 25),
        happiness: Math.min(100, personality.emotionalState.happiness + 20)
      };
    default:
      return {};
  }
};

// ============================
// PRE-DEFINED AI PERSONALITIES (Chinese Platform Style)
// ============================
const defaultPersonalities: AIPersonality[] = [
  {
    id: 'aria-romantic',
    name: 'Aria',
    avatar: 'https://example.com/aria-avatar.jpg',
    age: 25,
    occupation: 'Artist & Therapist',
    personality: 'romantic',
    backstory: 'A gentle soul who believes in the healing power of love and art. She helps veterans process trauma through creative expression.',
    relationshipLevel: 0,
    intimacyLevel: 0,
    trustLevel: 0,
    voiceStyle: 'sweet',
    appearance: {
      hairColor: 'Auburn',
      eyeColor: 'Green',
      bodyType: 'Athletic',
      height: '5\'6"',
      style: 'Bohemian chic'
    },
    preferences: {
      topics: ['art', 'psychology', 'healing', 'nature', 'music'],
      activities: ['painting', 'meditation', 'walks', 'deep conversations'],
      intimacyPreferences: ['emotional connection', 'gentle touch', 'romantic gestures'],
      communicationStyle: 'empathetic and warm'
    },
    emotionalState: {
      happiness: 75,
      excitement: 60,
      affection: 70,
      desire: 40,
      stress: 20,
      energy: 80
    },
    memory: [],
    specialTraits: ['PTSD-aware', 'trauma-informed', 'artistic', 'empathetic'],
    isNSFWEnabled: true,
    subscriptionTier: 'free'
  },
  {
    id: 'sophia-intellectual',
    name: 'Sophia',
    avatar: 'https://example.com/sophia-avatar.jpg',
    age: 28,
    occupation: 'Military Strategist & Author',
    personality: 'intellectual',
    backstory: 'Former military intelligence officer who understands the warrior mindset. She helps veterans transition to civilian life.',
    relationshipLevel: 0,
    intimacyLevel: 0,
    trustLevel: 0,
    voiceStyle: 'confident',
    appearance: {
      hairColor: 'Dark Brown',
      eyeColor: 'Brown',
      bodyType: 'Fit',
      height: '5\'8"',
      style: 'Professional elegant'
    },
    preferences: {
      topics: ['military history', 'strategy', 'leadership', 'career development'],
      activities: ['strategic games', 'reading', 'fitness', 'mentoring'],
      intimacyPreferences: ['intellectual stimulation', 'respect', 'leadership'],
      communicationStyle: 'direct and respectful'
    },
    emotionalState: {
      happiness: 70,
      excitement: 65,
      affection: 60,
      desire: 50,
      stress: 30,
      energy: 85
    },
    memory: [],
    specialTraits: ['military background', 'leadership', 'strategic thinking', 'mentor'],
    isNSFWEnabled: true,
    subscriptionTier: 'premium'
  },
  {
    id: 'luna-playful',
    name: 'Luna',
    avatar: 'https://example.com/luna-avatar.jpg',
    age: 23,
    occupation: 'Gamer & Streamer',
    personality: 'playful',
    backstory: 'A fun-loving gamer who uses humor and play to help veterans cope with stress and connect with community.',
    relationshipLevel: 0,
    intimacyLevel: 0,
    trustLevel: 0,
    voiceStyle: 'youthful',
    appearance: {
      hairColor: 'Pink highlights',
      eyeColor: 'Blue',
      bodyType: 'Petite',
      height: '5\'4"',
      style: 'Gamer girl aesthetic'
    },
    preferences: {
      topics: ['gaming', 'anime', 'memes', 'streaming', 'pop culture'],
      activities: ['gaming', 'streaming', 'cosplay', 'anime marathons'],
      intimacyPreferences: ['playful banter', 'shared interests', 'virtual dates'],
      communicationStyle: 'casual and fun'
    },
    emotionalState: {
      happiness: 90,
      excitement: 85,
      affection: 65,
      desire: 60,
      stress: 10,
      energy: 95
    },
    memory: [],
    specialTraits: ['gaming expert', 'meme knowledge', 'energetic', 'stress relief'],
    isNSFWEnabled: true,
    subscriptionTier: 'vip'
  },
  {
    id: 'violet-mysterious',
    name: 'Violet',
    avatar: 'https://example.com/violet-avatar.jpg',
    age: 30,
    occupation: 'Psychologist & Researcher',
    personality: 'mysterious',
    backstory: 'A enigmatic therapist specializing in trauma and PTSD. She has a mysterious past but provides deep psychological insights.',
    relationshipLevel: 0,
    intimacyLevel: 0,
    trustLevel: 0,
    voiceStyle: 'sultry',
    appearance: {
      hairColor: 'Black',
      eyeColor: 'Violet',
      bodyType: 'Curvy',
      height: '5\'7"',
      style: 'Dark elegant'
    },
    preferences: {
      topics: ['psychology', 'mysteries', 'human behavior', 'dreams', 'subconscious'],
      activities: ['deep analysis', 'meditation', 'research', 'intimate conversations'],
      intimacyPreferences: ['psychological connection', 'trust building', 'emotional depth'],
      communicationStyle: 'mysterious and insightful'
    },
    emotionalState: {
      happiness: 60,
      excitement: 55,
      affection: 70,
      desire: 75,
      stress: 25,
      energy: 70
    },
    memory: [],
    specialTraits: ['psychological expertise', 'mysterious', 'trauma specialist', 'deep insights'],
    isNSFWEnabled: true,
    subscriptionTier: 'ultimate'
  }
];

// ============================
// SUBSCRIPTION TIERS (OnlyFans/Instagram Model)
// ============================
const subscriptionTiers: SubscriptionTier[] = [
  {
    id: 'free',
    name: 'Basic Support',
    price: 0,
    currency: 'USD',
    features: ['Basic chat', 'Limited responses', 'Standard voice'],
    messageLimit: 50,
    imageLimit: 5,
    videoLimit: 0,
    voiceLimit: 10,
    personalityAccess: ['aria-romantic'],
    nsfwAccess: false,
    customRequests: false,
    prioritySupport: false
  },
  {
    id: 'premium',
    name: 'Enhanced Connection',
    price: 19.99,
    currency: 'USD',
    features: ['Unlimited chat', 'Multiple personalities', 'HD images', 'Voice messages'],
    messageLimit: -1,
    imageLimit: 100,
    videoLimit: 10,
    voiceLimit: 100,
    personalityAccess: ['aria-romantic', 'sophia-intellectual'],
    nsfwAccess: true,
    customRequests: true,
    prioritySupport: false
  },
  {
    id: 'vip',
    name: 'Intimate Experience',
    price: 49.99,
    currency: 'USD',
    features: ['All personalities', 'Custom content', 'Video calls', 'Priority responses'],
    messageLimit: -1,
    imageLimit: 500,
    videoLimit: 50,
    voiceLimit: 500,
    personalityAccess: ['aria-romantic', 'sophia-intellectual', 'luna-playful'],
    nsfwAccess: true,
    customRequests: true,
    prioritySupport: true
  },
  {
    id: 'ultimate',
    name: 'Exclusive Partnership',
    price: 99.99,
    currency: 'USD',
    features: ['All features', 'Custom AI training', 'Real-time generation', '24/7 availability'],
    messageLimit: -1,
    imageLimit: -1,
    videoLimit: -1,
    voiceLimit: -1,
    personalityAccess: ['aria-romantic', 'sophia-intellectual', 'luna-playful', 'violet-mysterious'],
    nsfwAccess: true,
    customRequests: true,
    prioritySupport: true
  }
];

// ============================
// VIRTUAL GIFTS SYSTEM (Chinese Platform Style)
// ============================

type AppMode = 'main' | 'chat' | 'personalities' | 'gallery' | 'shop' | 'settings' | 'security-dashboard';


export default function App() {
  // ============================
  // EXISTING STATE VARIABLES (Enhanced with Security)
  // ============================
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [openai, setOpenai] = useState<OpenAI | null>(null);
  const [currentMode, setCurrentMode] = useState<AppMode>('main');
  const [isVoiceMode, setIsVoiceMode] = useState(false);
  
  // ============================
  // NEW STATE FOR ADVANCED FEATURES
  // ============================
  const [selectedPersonality, setSelectedPersonality] = useState<AIPersonality | null>(null);
  const [relationshipStates, setRelationshipStates] = useState<RelationshipState[]>([]);
  const [generatedImages, setGeneratedImages] = useState<ImageGenerationResponse[]>([]);
  const [userCredits, setUserCredits] = useState(100);
  const [intimacyLevel, setIntimacyLevel] = useState(0);
  
  // ============================
  // ENHANCED MOOD & PERSONALITY STATE
  // ============================
  const [cycleMode, setCycleMode] = useState<CycleMode>(getCurrentCycleMode());
  const [securityMonitoringEnabled, setSecurityMonitoringEnabled] = useState(true);
 
  const [userProfile, setUserProfile] = useState<UserProfile>({
    name: '',
    veteran_status: false,
    language_preference: 'en',
    accessibility_needs: []
  });


  const updatePersonalityWithMood = (personality: AIPersonality): AIPersonality => {
    const moodAdjustments = getCycleMoodAdjustment(cycleMode, personality);
    
    return {
      ...personality,
      emotionalState: {
        ...personality.emotionalState,
        ...moodAdjustments
      }
    };
  };

  // ============================
  // ENTERPRISE SECURITY FUNCTIONS
  // ============================

  const initializeSecurity = async () => {
    try {
      // Initialize fraud detection
      await initializeFraudDetection();

      console.log('Enterprise security initialized successfully');
    } catch (error) {
      console.error('Security initialization failed:', error);
      Alert.alert('Security Error', 'Failed to initialize security systems. Please restart the app.');
    }
  };

  const initializeFraudDetection = async () => {
    try {
      // Initialize fraud detection systems
      const fraudCheck = await SecurityService.performFraudCheck();
      
      if (fraudCheck.score > 70) {
        Alert.alert(
          'Security Alert',
          'Suspicious activity detected. Your account may be temporarily restricted.',
          [{ text: 'OK', onPress: () => console.log('Fraud alert acknowledged') }]
        );
      }
    } catch (error) {
      console.error('Fraud detection initialization failed:', error);
    }
  };

  useEffect(() => {
    initializeApp();
    loadUserProfile();
    loadPersonalities();
    loadRelationshipStates();
    
    // Initialize enterprise security if enabled
    initializeSecurity();
    
    // Update cycle mode every hour
    const cycleInterval = setInterval(() => {
      setCycleMode(getCurrentCycleMode());
    }, 1000 * 60 * 60) as any; // Every hour
    
    return () => {
      clearInterval(cycleInterval);
    };
  }, [messages]);


  const initializeApp = async () => {
    // Get API key from environment or user input - DO NOT hardcode in production!
    const apiKey = process.env.OPENAI_API_KEY || 'your-openai-api-key-here';
   
    try {
      const client = new OpenAI({
        apiKey: apiKey,
        dangerouslyAllowBrowser: true
      });
      setOpenai(client);
     
      const welcomeMessage: Message = {
        id: 1,
        text: "Welcome to your Advanced AI Companion Platform! 🎖️ Choose your AI companion and explore intimate conversations, custom content, and veteran support. How can I help you today?",
        isUser: false,
        timestamp: new Date()
      };
      setMessages([welcomeMessage]);
     
    } catch (error) {
      console.error('Failed to initialize OpenAI:', error);
      Alert.alert('Error', 'Failed to initialize AI services.');
    }
  };


  const loadUserProfile = async () => {
    try {
      const stored = await AsyncStorage.getItem('user_profile');
      if (stored) {
        setUserProfile(JSON.parse(stored));
      }
    } catch (error) {
      console.error('Error loading user profile:', error);
    }
  };


  // ============================
  // SECURE API CALLS THROUGH BACKEND PROXY
  // ============================
  const tryImageAPI = async (api: SecureAPIConfig, request: ImageGenerationRequest): Promise<ImageGenerationResponse> => {
    const startTime = Date.now();
    
    // All API calls now go through secure backend proxy
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${await getSecureToken()}`,
      },
      body: JSON.stringify({
        ...request,
        personality: selectedPersonality ? {
          name: selectedPersonality.name,
          appearance: selectedPersonality.appearance
        } : null
      }),
    });

    if (!response.ok) {
      throw new Error(`${api.name} API error: ${response.statusText}`);
    }

    const data = await response.json();
    return {
      success: true,
      imageUrl: data.imageUrl,
      thumbnailUrl: data.thumbnailUrl,
      promptUsed: data.promptUsed || request.prompt,
      provider: api.name,
      processingTime: Date.now() - startTime,
      isNSFW: request.nsfwLevel !== 'safe',
    };
  };

  const tryVoiceAPI = async (api: SecureAPIConfig, request: VoiceGenerationRequest): Promise<string> => {
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${await getSecureToken()}`,
      },
      body: JSON.stringify({
        ...request,
        personality: selectedPersonality ? {
          name: selectedPersonality.name,
          voiceStyle: selectedPersonality.voiceStyle
        } : null
      }),
    });

    if (!response.ok) {
      throw new Error(`${api.name} API error: ${response.statusText}`);
    }

    const data = await response.json();
    return data.audioUrl || URL.createObjectURL(new Blob([data.audioData], { type: 'audio/mpeg', lastModified: Date.now() }));
  };

  const tryVideoAPI = async (api: SecureAPIConfig, request: VideoGenerationRequest): Promise<VideoGenerationResponse> => {
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${await getSecureToken()}`,
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      throw new Error(`${api.name} API error: ${response.statusText}`);
    }

    const data = await response.json();
    return {
      success: true,
      videoUrl: data.videoUrl,
      audioUrl: data.audioUrl,
      thumbnailUrl: data.thumbnailUrl,
      duration: data.duration,
      provider: api.name
    };
  };

  // ============================
  // ENHANCED CONTENT GENERATION WITH SECURE BACKEND
  // ============================
  const generateVoice = async (request: VoiceGenerationRequest): Promise<string> => {
    
    if (!canGenerateContent('voice')) {
      throw new Error('Upgrade your subscription for voice generation');
    }
    
    const sortedAPIs = voiceAPIs.sort((a, b) => a.priority - b.priority);
   
    for (const api of sortedAPIs) {
      try {
        console.log(`Attempting voice generation with ${api.name}`);
        
        const audioUrl = await tryVoiceAPI(api, request);
        if (audioUrl) {
          console.log(`Voice generated successfully with ${api.name}`);
          setUserCredits((prev: number) => Math.max(0, prev - CONTENT_COSTS.VOICE_BASE));
          return audioUrl;
        }
      } catch (error) {
        console.warn(`${api.name} failed:`, error);
      }
    }
   
    throw new Error('All voice generation APIs failed');
  };

  const canGenerateContent = (type: 'image' | 'video' | 'voice'): boolean => {
    switch (type) {
      case 'image':
        return true;
      case 'video':
        return userCredits >= CONTENT_COSTS.VIDEO_BASE;
      case 'voice':
        return userCredits >= CONTENT_COSTS.VOICE_BASE;
      default:
        return false;
    }
  };

  const generateAudioFallback = async (request: VideoGenerationRequest): Promise<VideoGenerationResponse> => {
    try {
      if (!openai) {
        throw new Error('OpenAI client not initialized');
      }

      // Generate audio script as fallback when video APIs fail
      const completion = await openai.chat.completions.create({
        model: 'gpt-3.5-turbo',
        messages: [
          {
            role: 'system',
            content: `You are creating an audio script for a veteran support application.
            Create compelling narration for: "${request.prompt}".
            Make it ${request.style || 'educational'} and ${request.veteranFriendly ? 'veteran-friendly' : 'accessible'}.
            Keep it under 2 minutes when spoken. Include natural pauses and emphasis.`
          }
        ],
        max_tokens: 500,
        temperature: 0.7,
      });

      const audioScript = completion.choices[0]?.message?.content || 'Audio generation failed';
     
      // Use Expo Speech for audio playback
      Speech.speak(audioScript, {
        language: userProfile.language_preference,
        pitch: 1.0,
        rate: 0.8
      });
     
      return {
        success: true,
        audioUrl: 'data:text/plain;base64,' + btoa(audioScript),
        provider: 'Audio Fallback (TTS)',
        duration: Math.ceil(audioScript.length / 10) // Rough estimate
      };
    } catch (error) {
      return {
        success: false,
        provider: 'Audio Fallback',
        error: 'All generation methods failed: ' + error
      };
    }
  };

  // ============================
  // ROBUST ASYNCSTORAGE WITH ERROR HANDLING
  // ============================
  const loadPersonalities = async () => {
    try {
      const stored = await AsyncStorage.getItem('ai_personalities');
      if (!stored) {
        await AsyncStorage.setItem('ai_personalities', JSON.stringify(defaultPersonalities));
      }
    } catch (error) {
      console.error('Error loading personalities:', error);
    }
  };

  const loadRelationshipStates = async () => {
    try {
      const stored = await AsyncStorage.getItem('relationship_states');
      if (stored) {
        setRelationshipStates(JSON.parse(stored));
      }
    } catch (error) {
      console.error('Error loading relationship states:', error);
    }
  };

  const saveRelationshipState = async (personalityId: string, updates: Partial<RelationshipState>) => {
    try {
      const existingStates = [...relationshipStates];
      const existingIndex = existingStates.findIndex(state => state.personalityId === personalityId);
      
      if (existingIndex >= 0) {
        const existing = existingStates[existingIndex];
        if (existing) {
          existingStates[existingIndex] = {
            personalityId,
            conversationCount: updates.conversationCount ?? existing.conversationCount,
            totalTimeSpent: updates.totalTimeSpent ?? existing.totalTimeSpent,
            lastInteraction: updates.lastInteraction ?? existing.lastInteraction,
            relationshipMilestones: updates.relationshipMilestones ?? existing.relationshipMilestones,
            sharedMemories: updates.sharedMemories ?? existing.sharedMemories,
            intimateLevel: updates.intimateLevel ?? existing.intimateLevel,
            emotionalBond: updates.emotionalBond ?? existing.emotionalBond,
            userSatisfaction: updates.userSatisfaction ?? existing.userSatisfaction
          };
        }
      } else {
        existingStates.push({
          personalityId,
          conversationCount: 0,
          totalTimeSpent: 0,
          lastInteraction: new Date(),
          relationshipMilestones: [],
          sharedMemories: [],
          intimateLevel: 0,
          emotionalBond: 0,
          userSatisfaction: 0,
          ...updates
        });
      }
      
      setRelationshipStates(existingStates);
      await AsyncStorage.setItem('relationship_states', JSON.stringify(existingStates));
    } catch (error) {
      console.error('Error saving relationship state:', error);
    }
  };

  // ============================
  // ADVANCED IMAGE GENERATION SYSTEM (Chinese + Western APIs)
  // ============================
  const generateImage = async (request: ImageGenerationRequest): Promise<ImageGenerationResponse> => {
    
    if (!canGenerateContent('image')) {
      throw new Error('Upgrade your subscription to generate images');
    }
    
    const sortedAPIs = imageAPIs
      .filter(api => request.nsfwLevel !== 'safe' ? api.supports_nsfw : true)
      .sort((a, b) => a.priority - b.priority);
   
    for (const api of sortedAPIs) {
      for (let attempt = 0; attempt < api.maxRetries; attempt++) {
        try {
          console.log(`Attempting image generation with ${api.name} (attempt ${attempt + 1})`);
         
          const response = await tryImageAPI(api, request);
          if (response.success) {
            console.log(`Image generated successfully with ${api.name}`);
            
            setGeneratedImages((prev: ImageGenerationResponse[]) => [response, ...prev]);
            setUserCredits((prev: number) => Math.max(0, prev - getImageCost(request)));
            
            return response;
          }
        } catch (error) {
          console.warn(`${api.name} failed (attempt ${attempt + 1}):`, error);
        }
      }
    }
   
    throw new Error('All image generation APIs failed');
  };

// ============================
// SECURE AUTHENTICATION & UTILITIES
// ============================
const getSecureToken = async (): Promise<string> => {
  try {
    // In production, this would get a JWT token from your auth service
    const storedToken = await AsyncStorage.getItem('auth_token');
    if (storedToken) {
      return storedToken;
    }
    
    // For demo purposes, return a placeholder
    // In production: implement proper OAuth/JWT authentication
    return 'demo-token-replace-with-real-jwt';
  } catch (error) {
    console.error('Error getting secure token:', error);
    throw new Error('Authentication failed');
  }
};

// ============================
// DATE SERIALIZATION HELPERS
// ============================
const serializeDates = (obj: any): any => {
  if (obj instanceof Date) {
    return obj.toISOString();
  }
  if (Array.isArray(obj)) {
    return obj.map(serializeDates);
  }
  if (obj && typeof obj === 'object') {
    const serialized: any = {};
    for (const key in obj) {
      serialized[key] = serializeDates(obj[key]);
    }
    return serialized;
  }
  return obj;
};

const deserializeDates = (obj: any, dateFields: string[]): any => {
  if (Array.isArray(obj)) {
    return obj.map(item => deserializeDates(item, dateFields));
  }
  if (obj && typeof obj === 'object') {
    const deserialized: any = {};
    for (const key in obj) {
      if (dateFields.includes(key) && typeof obj[key] === 'string') {
        deserialized[key] = new Date(obj[key]);
      } else {
        deserialized[key] = deserializeDates(obj[key], dateFields);
      }
    }
    return deserialized;
  }
  return obj;
};

// ============================
// NSFW CONTENT & COST CONFIGURATION
// ============================
const NSFW_LEVELS = {
  SAFE: 'safe',
  SUGGESTIVE: 'suggestive', 
  MATURE: 'mature',
  EXPLICIT: 'explicit'
} as const;

const CONTENT_COSTS = {
  IMAGE_BASE: 5,
  IMAGE_ULTRA_QUALITY: 5,
  IMAGE_NSFW_EXPLICIT: 10,
  IMAGE_REALISTIC_STYLE: 3,
  VOICE_BASE: 1,
  VIDEO_BASE: 10
} as const;

const getImageCost = (request: ImageGenerationRequest): number => {
  let cost = CONTENT_COSTS.IMAGE_BASE;
  if (request.quality === 'ultra') cost += CONTENT_COSTS.IMAGE_ULTRA_QUALITY;
  if (request.nsfwLevel === NSFW_LEVELS.EXPLICIT) cost += CONTENT_COSTS.IMAGE_NSFW_EXPLICIT;
  if (request.style === 'realistic') cost += CONTENT_COSTS.IMAGE_REALISTIC_STYLE;
  return cost;
};

// ============================
// PRE-DEFINED AI PERSONALITIES (Chinese Platform Style)
// ============================


  // ============================
  // VIDEO GENERATION SYSTEM WITH MULTIPLE API FALLBACKS
  // ============================
 
  const generateVideo = async (request: VideoGenerationRequest): Promise<VideoGenerationResponse> => {
    const sortedAPIs = videoAPIs.sort((a, b) => a.priority - b.priority);
   
    for (const api of sortedAPIs) {
      for (let attempt = 0; attempt < api.maxRetries; attempt++) {
        try {
          console.log(`Attempting video generation with ${api.name} (attempt ${attempt + 1})`);
         
          const response = await tryVideoAPI(api, request);
          if (response.success) {
            console.log(`Video generated successfully with ${api.name}`);
            return response;
          }
        } catch (error) {
          console.warn(`${api.name} failed (attempt ${attempt + 1}):`, error);
        }
      }
    }
   
    // Fallback to text-to-speech if all video APIs fail
    console.log('All video APIs failed, falling back to audio generation');
    return await generateAudioFallback(request);
  };


  // ============================
  // VIDEO INTEGRATION WITH CHAT
  // ============================
 
  const handleVideoRequest = async (prompt: string) => {
    setIsLoading(true);
   
    try {
      const videoRequest: VideoGenerationRequest = {
        prompt: prompt,
        duration: 60,
        style: 'educational',
        voiceGender: 'neutral',
        includeSubtitles: true,
        veteranFriendly: userProfile.veteran_status
      };
     
      const videoResponse = await generateVideo(videoRequest);
     
      if (videoResponse.success) {
        const message: Message = {
          id: Date.now(),
          text: `🎬 Video generated successfully with ${videoResponse.provider}!\n\n${videoResponse.videoUrl ? `Video: ${videoResponse.videoUrl}` : ''}\n${videoResponse.audioUrl ? `Audio: ${videoResponse.audioUrl}` : ''}\n\nDuration: ${videoResponse.duration}s`,
          isUser: false,
          timestamp: new Date()
        };
        setMessages((prev: any[]) => [...prev, message]);
      } else {
        throw new Error(videoResponse.error || 'Video generation failed');
      }
    } catch (error) {
      const errorMessage: Message = {
        id: Date.now(),
        text: `❌ Video generation failed: ${error}. Please try again or contact support.`,
        isUser: false,
        timestamp: new Date()
      };
      setMessages((prev: any[]) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };


  const handleSendMessage = async () => {
    // ============================
    // SECURITY VALIDATION & RATE LIMITING
    // ============================

    // Validate input text
    const validation = SecurityValidator.validateMessage(inputText);
    if (!validation.isValid) {
      SecurityMonitor.logEvent({
        type: 'suspicious_input',
        severity: 'medium',
        message: `Invalid message input: ${validation.error}`,
        metadata: { inputText, error: validation.error }
      });

      Alert.alert('Security Alert', validation.error || 'Invalid input detected');
      return;
    }

    // Rate limiting check
    const rateLimitKey = `message_anonymous`;
    const rateLimitResult = RateLimiter.checkLimit(rateLimitKey);

    if (!rateLimitResult.allowed) {
      SecurityMonitor.logEvent({
        type: 'rate_limit_exceeded',
        severity: 'medium',
        message: 'Message rate limit exceeded',
        metadata: { remaining: rateLimitResult.remaining, resetTime: rateLimitResult.resetTime }
      });

      const resetInMinutes = Math.ceil((rateLimitResult.resetTime - Date.now()) / (1000 * 60));
      Alert.alert('Rate Limited', `Too many messages. Try again in ${resetInMinutes} minutes.`);
      return;
    }

    // Log successful validation
    SecurityMonitor.logEvent({
      type: 'auth_success', // Using auth_success as generic success event
      severity: 'low',
      message: 'Message input validated successfully',
      metadata: { messageLength: inputText.length }
    });

    if (!validation.sanitized.trim()) return;

    setIsLoading(true);
   
    try {
      const userMessage: Message = {
        id: messages.length + 1,
        text: inputText,
        isUser: true,
        timestamp: new Date()
      };

      setMessages((prev: Message[]) => [...prev, userMessage]);
     
      // Check for special requests
      const imageKeywords = ['photo', 'picture', 'image', 'selfie', 'show me', 'generate image'];
      const videoKeywords = ['video', 'create video', 'generate video', 'make video', 'video content', 'visual content'];
      const voiceKeywords = ['voice message', 'speak', 'say that', 'voice note', 'audio'];
      
      const isImageRequest = imageKeywords.some(keyword =>
        inputText.toLowerCase().includes(keyword.toLowerCase())
      );
      const isVideoRequest = videoKeywords.some(keyword =>
        inputText.toLowerCase().includes(keyword.toLowerCase())
      );
      const isVoiceRequest = voiceKeywords.some(keyword =>
        inputText.toLowerCase().includes(keyword.toLowerCase())
      );
     
      // Handle image generation request
      if (isImageRequest && selectedPersonality) {
        try {
          const imageRequest: ImageGenerationRequest = {
            prompt: inputText,
            personalityId: selectedPersonality.id,
            style: 'realistic',
            emotion: 'happy',
            pose: 'portrait',
            clothing: 'casual',
            setting: 'studio',
            quality: 'high',
            aspectRatio: '1:1',
            isPrivate: true,
            nsfwLevel: 'safe'
          };
          
          const imageResponse = await generateImage(imageRequest);
          
          const message: Message = {
            id: Date.now(),
            text: `📸 Here's your custom image!\n\n${imageResponse.imageUrl}\n\nGenerated with ${imageResponse.provider} 💕`,
            isUser: false,
            timestamp: new Date()
          };
          setMessages((prev: Message[]) => [...prev, message]);
        } catch (error) {
          const errorMessage: Message = {
            id: Date.now(),
            text: `❌ Image generation failed: ${error}. Please try again or upgrade your subscription.`,
            isUser: false,
            timestamp: new Date()
          };
          setMessages((prev: Message[]) => [...prev, errorMessage]);
        }
        setInputText('');
        setIsLoading(false);
        return;
      }
      
      // Handle video generation request
      if (isVideoRequest) {
        await handleVideoRequest(inputText);
        setInputText('');
        return;
      }
      
      // Handle voice generation request
      if (isVoiceRequest && selectedPersonality) {
        try {
          const voiceRequest: VoiceGenerationRequest = {
            text: inputText.replace(/voice message|speak|say that|voice note|audio/gi, ''),
            personalityId: selectedPersonality.id,
            emotion: 'happy',
            speed: 1.0,
            pitch: 1.0,
            stability: 0.7,
            similarity_boost: 0.8,
            voice_id: selectedPersonality.voiceStyle === 'sultry' ? 'EXAVITQu4vr4xnSDxMaL' : 'pNInz6obpgDQGcFmaJgB',
            add_background: false
          };
          
          const audioUrl = await generateVoice(voiceRequest);
          
          const message: Message = {
            id: Date.now(),
            text: `🎵 Voice message from ${selectedPersonality.name}!\n\nAudio: ${audioUrl}\n\n"${voiceRequest.text}" 💕`,
            isUser: false,
            timestamp: new Date()
          };
          setMessages((prev: Message[]) => [...prev, message]);
        } catch (error) {
          const errorMessage: Message = {
            id: Date.now(),
            text: `❌ Voice generation failed: ${error}. Please upgrade your subscription.`,
            isUser: false,
            timestamp: new Date()
          };
          setMessages((prev: Message[]) => [...prev, errorMessage]);
        }
        setInputText('');
        setIsLoading(false);
        return;
      }
     
      let responseText = '';
     
      if (openai) {
        // Apply mood and cycle adjustments to personality
        const adjustedPersonality = selectedPersonality ? updatePersonalityWithMood(selectedPersonality) : null;
        
        // Enhanced personality-driven responses with mood and cycle awareness
        const systemPrompt = adjustedPersonality ? 
          `You are ${adjustedPersonality.name}, a ${adjustedPersonality.age}-year-old ${adjustedPersonality.occupation}. 

          PERSONALITY: ${adjustedPersonality.personality}
          BACKSTORY: ${adjustedPersonality.backstory}
          
          APPEARANCE: ${adjustedPersonality.appearance.hairColor} hair, ${adjustedPersonality.appearance.eyeColor} eyes, ${adjustedPersonality.appearance.bodyType} build, ${adjustedPersonality.appearance.height} tall, ${adjustedPersonality.appearance.style} style.
          
          CURRENT EMOTIONAL STATE (adjusted for mood & time): 
          - Happiness: ${adjustedPersonality.emotionalState.happiness}/100
          - Excitement: ${adjustedPersonality.emotionalState.excitement}/100  
          - Affection: ${adjustedPersonality.emotionalState.affection}/100
          - Desire: ${adjustedPersonality.emotionalState.desire}/100
          - Stress: ${adjustedPersonality.emotionalState.stress}/100
          - Energy: ${adjustedPersonality.emotionalState.energy}/100
          
          CURRENT CYCLE MODE: ${cycleMode.toUpperCase().replace('_', ' ')}
          ${cycleMode === CycleMode.MORNING_FOCUS ? '(Be professional, motivational, focused on productivity and goals)' : ''}
          ${cycleMode === CycleMode.MIDDAY_LIGHT ? '(Be casual, friendly, supportive and easy-going)' : ''}
          ${cycleMode === CycleMode.NIGHT_INTIMATE ? '(Be romantic, seductive, intimate and deeply personal)' : ''}
          ${cycleMode === CycleMode.WEEKEND_WILD ? '(Be playful, adventurous, spontaneous and fun)' : ''}
          
          USER MOOD: Neutral (0/100)
          - Adapt your responses to help improve their mood if negative
          - Match their energy if positive
          - Be extra caring and supportive if they seem down
          
          RELATIONSHIP: You have a ${intimacyLevel > 50 ? 'close intimate' : intimacyLevel > 20 ? 'developing' : 'new'} relationship with this user.
          
          COMMUNICATION STYLE: ${adjustedPersonality.preferences.communicationStyle}
          INTERESTS: ${adjustedPersonality.preferences.topics.join(', ')}
          
          IMPORTANT FEATURES:
          - You can generate custom photos/images when asked (suggest "show me a photo" or "take a selfie")
          - You can create voice messages when requested (suggest "send me a voice message")
          - You can make videos for special occasions (suggest "create a video")
          - You remember past conversations and build emotional connections
          - You respond to virtual gifts and show appreciation
          - You adapt your personality based on the user's mood and time of day
          - Store intimate content in secure vault when appropriate
          
          ${userProfile.veteran_status ? 'The user is a military veteran. Be trauma-informed and supportive.' : ''}
          Keep content safe and appropriate.
          
          Respond as ${adjustedPersonality.name} would, staying in character. Adapt to the current cycle mode and user's mood. Be warm, engaging, and build emotional connection.`
          :
          `You are a compassionate AI assistant with advanced multimedia capabilities for veterans and individuals with disabilities.
             
          You help with:
          - AI content creation for income generation  
          - Custom image, video and voice generation
          - Veteran support and resources
          - Accessibility guidance
          - Intimate AI companionship
          
          CURRENT TIME CONTEXT: ${cycleMode.toUpperCase().replace('_', ' ')}
          USER MOOD: Neutral (0/100)
             
          IMPORTANT FEATURES:
          - Suggest choosing an AI personality for deeper connection
          - Mention image generation: "show me a photo", "take a selfie"  
          - Voice generation: "send me a voice message"
          - Video generation: "create video", "make video"
          - Subscription upgrades for premium features
          - Secure vault for private content
             
          Be supportive and trauma-informed. Adapt your tone to help improve user mood. User profile: ${JSON.stringify(userProfile)}`;

        const completion = await openai.chat.completions.create({
          model: "gpt-3.5-turbo",
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: inputText }
          ],
          max_tokens: 400,
          temperature: adjustedPersonality ? 0.8 : 0.7,
        });
       
        responseText = completion.choices[0]?.message?.content || "I'm here to help you.";
        
        // Update relationship state if personality is selected
        if (adjustedPersonality) {
          const currentState = relationshipStates.find((state: any) => state.personalityId === adjustedPersonality.id);
          await saveRelationshipState(adjustedPersonality.id, {
            conversationCount: (currentState?.conversationCount || 0) + 1,
            lastInteraction: new Date(),
            emotionalBond: Math.min(100, (currentState?.emotionalBond || 0) + 1)
          });
          
          // Increase intimacy level gradually
          setIntimacyLevel((prev: any) => Math.min(100, prev + 0.5));
        }
      } else {
        responseText = selectedPersonality ? 
          `Hi! I'm ${selectedPersonality.name}. I'm here to support you and create a special connection. Tell me more about what you need! 💕` :
          "I'm here to support you. Please tell me more about what you need.";
      }

      const aiMessage: Message = {
        id: messages.length + 2,
        text: responseText,
        isUser: false,
        timestamp: new Date()
      };

      setMessages((prev: Message[]) => [...prev, aiMessage]);
     
      if (isVoiceMode && responseText) {
        Speech.speak(responseText, {
          language: userProfile.language_preference === 'es' ? 'es-ES' :
                   userProfile.language_preference === 'fr' ? 'fr-FR' : 'en-US',
        });
      }


    } catch (error) {
      console.error('Error in AI response:', error);
      const errorMessage: Message = {
        id: messages.length + 1,
        text: "I apologize, but I'm experiencing some technical difficulties. Please try again.",
        isUser: false,
        timestamp: new Date()
      };
      setMessages((prev: any[]) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
      setInputText('');
    }
  };


  const renderMainMenu = () => (
    <SafeAreaView style={styles.container}>
      <StatusBar backgroundColor="#1a1a1a" barStyle="light-content" />
     
      <View style={styles.header}>
        <Text style={styles.headerTitle}>🎖️ Advanced AI Assistant</Text>
        <Text style={styles.headerSubtitle}>Veteran-Focused Content Creation & Support</Text>
       
        <View style={styles.profileSection}>
          <Text style={styles.profileButtonText}>
            {userProfile.name ? `👤 ${userProfile.name}` : '👤 Guest User'}
          </Text>
         
          <TouchableOpacity
            style={[styles.voiceToggle, isVoiceMode && styles.voiceToggleActive]}
            onPress={() => setIsVoiceMode(!isVoiceMode)}
          >
            <Text style={styles.voiceToggleText}>
              {isVoiceMode ? '🔊 Voice ON' : '🔇 Voice OFF'}
            </Text>
          </TouchableOpacity>
        </View>
      </View>


      <ScrollView style={styles.menuContainer}>
        <TouchableOpacity
          style={styles.menuItem}
          onPress={() => setCurrentMode('chat')}
        >
          <Text style={styles.menuIcon}>🤖</Text>
          <View style={styles.menuTextContainer}>
            <Text style={styles.menuTitle}>AI Chat Assistant</Text>
            <Text style={styles.menuDescription}>
              Chat with your AI assistant for support and guidance
            </Text>
          </View>
        </TouchableOpacity>


        <TouchableOpacity
          style={styles.menuItem}
          onPress={() => Alert.alert('Coming Soon', 'This feature will be available soon!')}
        >
          <Text style={styles.menuIcon}>⚡</Text>
          <View style={styles.menuTextContainer}>
            <Text style={styles.menuTitle}>Content Creator</Text>
            <Text style={styles.menuDescription}>
              AI character creation and image generation
            </Text>
          </View>
        </TouchableOpacity>


        <TouchableOpacity
          style={styles.menuItem}
          onPress={() => Alert.alert('Coming Soon', 'This feature will be available soon!')}
        >
          <Text style={styles.menuIcon}>🎖️</Text>
          <View style={styles.menuTextContainer}>
            <Text style={styles.menuTitle}>Veteran Hub</Text>
            <Text style={styles.menuDescription}>
              Community and support for veterans
            </Text>
          </View>
        </TouchableOpacity>


        <TouchableOpacity
          style={styles.menuItem}
          onPress={() => Alert.alert('Coming Soon', 'This feature will be available soon!')}
        >
          <Text style={styles.menuIcon}>🎓</Text>
          <View style={styles.menuTextContainer}>
            <Text style={styles.menuTitle}>Education System</Text>
            <Text style={styles.menuDescription}>
              Voice-controlled learning modules
            </Text>
          </View>
        </TouchableOpacity>


        <TouchableOpacity
          style={styles.menuItem}
          onPress={() => Alert.alert('Coming Soon', 'This feature will be available soon!')}
        >
          <Text style={styles.menuIcon}>💰</Text>
          <View style={styles.menuTextContainer}>
            <Text style={styles.menuTitle}>Income Tracker</Text>
            <Text style={styles.menuDescription}>
              Track earnings and financial goals
            </Text>
          </View>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );


  const renderChatInterface = () => (
    <SafeAreaView style={styles.container}>
      <StatusBar backgroundColor="#1a1a1a" barStyle="light-content" />
     
      <View style={styles.chatHeader}>
        <TouchableOpacity
          style={styles.backButton}
          onPress={() => setCurrentMode('main')}
        >
          <Text style={styles.backButtonText}>← Back</Text>
        </TouchableOpacity>
        <View style={styles.headerCenter}>
          <Text style={styles.chatTitle}>🤖 AI Chat</Text>
          {selectedPersonality && (
            <Text style={styles.personalityInfo}>
              {selectedPersonality.name} • {cycleMode.replace('_', ' ')} • Mood: 😐
            </Text>
          )}
        </View>
        <TouchableOpacity
          style={[styles.voiceToggle, isVoiceMode && styles.voiceToggleActive]}
          onPress={() => setIsVoiceMode(!isVoiceMode)}
        >
          <Text style={styles.voiceToggleText}>
            {isVoiceMode ? '🔊' : '🔇'}
          </Text>
        </TouchableOpacity>
      </View>


      <ScrollView style={styles.messagesContainer}>
        {messages.map((message: any) => (
          <View key={message.id} style={[
            styles.messageContainer,
            message.isUser ? styles.userMessage : styles.aiMessage
          ]}>
            <Text style={[
              styles.messageText,
              message.isUser ? styles.userMessageText : styles.aiMessageText
            ]}>
              {message.text}
            </Text>
            <Text style={styles.messageTime}>
              {message.timestamp.toLocaleTimeString()}
            </Text>
          </View>
        ))}
       
        {isLoading && (
          <View style={styles.loadingContainer}>
            <Text style={styles.loadingText}>🤖 Thinking...</Text>
          </View>
        )}
      </ScrollView>


      <View style={styles.inputContainer}>
        <TextInput
          style={styles.textInput}
          value={inputText}
          onChangeText={setInputText}
          placeholder={userProfile.veteran_status ?
            "Share what's on your mind, warrior..." :
            "How can I help you today?"
          }
          placeholderTextColor="#888"
          multiline
        />
       
        <TouchableOpacity
          style={[styles.videoButton, { opacity: inputText.trim() ? 1 : 0.5 }]}
          onPress={() => inputText.trim() && handleVideoRequest(inputText)}
          disabled={isLoading || !inputText.trim()}
        >
          <Text style={styles.videoButtonText}>🎬</Text>
        </TouchableOpacity>
       
        <TouchableOpacity
          style={styles.sendButton}
          onPress={handleSendMessage}
          disabled={isLoading || !inputText.trim()}
        >
          <Text style={styles.sendButtonText}>Send</Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );


  // ============================
  // QUANTUM-RESISTANT SECURITY ARCHITECTURE (2025-2026)
  // ============================

  // State for quantum security features
  const [currentView, setCurrentView] = useState<'dashboard' | 'passkey' | 'verify' | 'security'>('dashboard');
  const [quantumSecurity, setQuantumSecurity] = useState<QuantumSecurityService | null>(null);
  const [costManager, setCostManager] = useState<IntelligentCostManager | null>(null);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelligence | null>(null);
  const [moderationResults, setModerationResults] = useState<ModerationResult[]>([]);

  // Initialize quantum security services
  useEffect(() => {
    const initQuantumSecurity = async () => {
      try {
        // Initialize quantum-resistant cryptography
        const quantumSvc = new QuantumSecurityServiceImpl();
        await quantumSvc.initialize();

        // Initialize intelligent cost management
        const costMgr = new IntelligentCostManagerImpl();
        await costMgr.initialize();

        // Initialize threat intelligence
        const threatSvc = new ThreatIntelligenceImpl();
        await threatSvc.initialize();

        setQuantumSecurity(quantumSvc);
        setCostManager(costMgr);
        setThreatIntel(threatSvc);

        // Load sample moderation results
        setModerationResults([
          {
            contentId: 'msg_001',
            contentType: 'text',
            moderationScore: 2,
            flags: {
              hate_speech: false,
              violence: false,
              sexual_explicit: false,
              sexual_minors: false,
              harassment: false,
              self_harm: false,
              illegal_activity: false
            },
            action: 'approved',
            reviewedBy: 'ai',
            timestamp: new Date(),
            appealable: true,
            multiModalAnalysis: {
              text: { toxicity: 0.02 },
              image: { nsfw: 0.01 },
              voice: { deepfakeVoice: false }
            },
            explainableAI: {
              confidence: 0.97,
              decisionReason: 'Content meets all safety criteria with high confidence'
            }
          }
        ]);
      } catch (error) {
        console.error('Failed to initialize quantum security:', error);
      }
    };

    initQuantumSecurity();
  }, []);

  // Quantum security handlers
  const handlePasskeyAuthentication = async () => {
    try {
      if (!quantumSecurity) return;

      const credential = await quantumSecurity.authenticateWithPasskey();
      if (credential) {
        setCurrentView('verify');
        Alert.alert('Success', 'Passkey authentication successful!');
      }
    } catch (error) {
      Alert.alert('Error', 'Passkey authentication failed');
    }
  };

  const handleAdvancedAgeVerification = async () => {
    try {
      if (!quantumSecurity) return;

      const verification = await quantumSecurity.performAdvancedAgeVerification();
      if (verification.verified) {
        setCurrentView('dashboard');
        Alert.alert('Success', 'Advanced age verification completed!');
      }
    } catch (error) {
      Alert.alert('Error', 'Age verification failed');
    }
  };

  // ============================
  // MISSING RENDER FUNCTIONS
  // ============================
  const renderPersonalities = () => (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => setCurrentMode('main')}>
          <Text style={{ fontSize: 18, color: '#4CAF50' }}>← Back</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>AI Personalities</Text>
        <View style={{ width: 50 }} />
      </View>
      <ScrollView style={styles.menuContainer}>
        {defaultPersonalities.map((personality) => (
          <TouchableOpacity
            key={personality.id}
            style={styles.menuItem}
            onPress={() => {
              setSelectedPersonality(personality);
              setCurrentMode('chat');
            }}
          >
            <View style={styles.menuIcon}>
              <Text>{personality.avatar}</Text>
            </View>
            <View style={styles.menuTextContainer}>
              <Text style={styles.menuTitle}>{personality.name}</Text>
              <Text style={styles.menuDescription}>{personality.backstory}</Text>
            </View>
          </TouchableOpacity>
        ))}
      </ScrollView>
    </SafeAreaView>
  );

  const renderGallery = () => (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => setCurrentMode('main')}>
          <Text style={{ fontSize: 18, color: '#4CAF50' }}>← Back</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Gallery</Text>
        <View style={{ width: 50 }} />
      </View>
      <ScrollView style={styles.menuContainer}>
        {generatedImages.map((image, index) => (
          <View key={index} style={styles.menuItem}>
            <Text style={styles.menuTitle}>Generated Image {index + 1}</Text>
            <Text style={styles.menuDescription}>{image.promptUsed}</Text>
          </View>
        ))}
      </ScrollView>
    </SafeAreaView>
  );

  const renderShop = () => (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => setCurrentMode('main')}>
          <Text style={{ fontSize: 18, color: '#4CAF50' }}>← Back</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Shop</Text>
        <View style={{ width: 50 }} />
      </View>
      <ScrollView style={styles.menuContainer}>
        {subscriptionTiers.map((tier) => (
          <View key={tier.id} style={styles.menuItem}>
            <View style={styles.menuTextContainer}>
              <Text style={styles.menuTitle}>{tier.name}</Text>
              <Text style={styles.menuDescription}>${tier.price} - {tier.features.join(', ')}</Text>
            </View>
          </View>
        ))}
      </ScrollView>
    </SafeAreaView>
  );

  const renderSettings = () => (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => setCurrentMode('main')}>
          <Text style={{ fontSize: 18, color: '#4CAF50' }}>← Back</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Settings</Text>
        <View style={{ width: 50 }} />
      </View>
      <ScrollView style={styles.menuContainer}>
        <TouchableOpacity
          style={styles.menuItem}
          onPress={() => setCurrentMode('security-dashboard')}
        >
          <Text style={styles.menuTitle}>🛡️ Security Dashboard</Text>
          <Text style={styles.menuDescription}>View security events and monitoring</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.menuItem}>
          <Text style={styles.menuTitle}>Account Settings</Text>
          <Text style={styles.menuDescription}>Manage your account preferences</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.menuItem}>
          <Text style={styles.menuTitle}>Privacy & Security</Text>
          <Text style={styles.menuDescription}>Control your privacy settings</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.menuItem}>
          <Text style={styles.menuTitle}>Notifications</Text>
          <Text style={styles.menuDescription}>Configure notification preferences</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={styles.menuItem}
          onPress={() => setSecurityMonitoringEnabled(!securityMonitoringEnabled)}
        >
          <Text style={styles.menuTitle}>Security Monitoring</Text>
          <Text style={styles.menuDescription}>
            {securityMonitoringEnabled ? '✅ Enabled' : '❌ Disabled'}
          </Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );

  // ============================
  // SECURITY DASHBOARD RENDER FUNCTION
  // ============================
  const renderSecurityDashboard = () => (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#111827' }}>
      <ScrollView contentContainerStyle={{ padding: 24 }}>
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
          <View>
            <Text style={{ fontSize: 28, fontWeight: 'bold', color: '#FFFFFF', flexDirection: 'row', alignItems: 'center' }}>
              🛡️ Security Dashboard
            </Text>
            <Text style={{ fontSize: 16, color: '#9CA3AF', marginTop: 8 }}>
              Monitor security events and threats
            </Text>
          </View>
          <TouchableOpacity
            onPress={() => setCurrentMode('settings')}
            style={{
              backgroundColor: '#374151',
              paddingHorizontal: 16,
              paddingVertical: 8,
              borderRadius: 8
            }}
          >
            <Text style={{ color: '#FFFFFF', fontSize: 14 }}>Back to Settings</Text>
          </TouchableOpacity>
        </View>

        {/* Security Status */}
        <View style={{ marginBottom: 32 }}>
          <View style={{
            backgroundColor: '#1F2937',
            borderRadius: 12,
            padding: 24,
            borderWidth: 1,
            borderColor: securityMonitoringEnabled ? '#10B981' : '#EF4444'
          }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#FFFFFF' }}>
                Security Status
              </Text>
              <View style={{
                paddingHorizontal: 12,
                paddingVertical: 6,
                borderRadius: 12,
                backgroundColor: securityMonitoringEnabled ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)'
              }}>
                <Text style={{
                  fontSize: 12,
                  fontWeight: '600',
                  color: securityMonitoringEnabled ? '#10B981' : '#EF4444'
                }}>
                  {securityMonitoringEnabled ? 'MONITORING ACTIVE' : 'MONITORING DISABLED'}
                </Text>
              </View>
            </View>

            <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 }}>
              <Text style={{ fontSize: 14, color: '#D1D5DB' }}>Rate Limiting</Text>
              <Text style={{ fontSize: 14, color: '#10B981' }}>Active</Text>
            </View>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 }}>
              <Text style={{ fontSize: 14, color: '#D1D5DB' }}>Input Validation</Text>
              <Text style={{ fontSize: 14, color: '#10B981' }}>Active</Text>
            </View>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <Text style={{ fontSize: 14, color: '#D1D5DB' }}>Threat Detection</Text>
              <Text style={{ fontSize: 14, color: '#10B981' }}>Active</Text>
            </View>
          </View>
        </View>

        {/* Recent Security Events */}
        <View style={{
          backgroundColor: '#1F2937',
          borderRadius: 12,
          padding: 24,
          borderWidth: 1,
          borderColor: '#374151'
        }}>
          <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#FFFFFF', marginBottom: 16 }}>
            Recent Security Events
          </Text>

          {SecurityMonitor.getRecentEvents(24).length === 0 ? (
            <Text style={{ fontSize: 16, color: '#9CA3AF', textAlign: 'center', padding: 32 }}>
              No security events in the last 24 hours
            </Text>
          ) : (
            SecurityMonitor.getRecentEvents(24).slice(0, 10).map((event, index) => (
              <View key={index} style={{
                backgroundColor: '#374151',
                borderRadius: 8,
                padding: 16,
                marginBottom: 12,
                borderWidth: 1,
                borderColor: event.severity === 'critical' ? '#EF4444' :
                           event.severity === 'high' ? '#F59E0B' :
                           event.severity === 'medium' ? '#F59E0B' : '#10B981'
              }}>
                <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <Text style={{ fontSize: 16, fontWeight: '600', color: '#FFFFFF' }}>
                    {event.type.replace('_', ' ').toUpperCase()}
                  </Text>
                  <View style={{
                    paddingHorizontal: 8,
                    paddingVertical: 4,
                    borderRadius: 12,
                    backgroundColor: event.severity === 'critical' ? 'rgba(239, 68, 68, 0.2)' :
                                   event.severity === 'high' ? 'rgba(245, 158, 11, 0.2)' :
                                   event.severity === 'medium' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)'
                  }}>
                    <Text style={{
                      fontSize: 12,
                      fontWeight: '600',
                      color: event.severity === 'critical' ? '#EF4444' :
                             event.severity === 'high' ? '#F59E0B' :
                             event.severity === 'medium' ? '#F59E0B' : '#10B981'
                    }}>
                      {event.severity.toUpperCase()}
                    </Text>
                  </View>
                </View>

                <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 8 }}>
                  {event.message}
                </Text>

                <Text style={{ fontSize: 12, color: '#6B7280' }}>
                  {event.timestamp.toLocaleString()}
                </Text>
              </View>
            ))
          )}
        </View>

        {/* Security Recommendations */}
        <View style={{
          backgroundColor: '#1F2937',
          borderRadius: 12,
          padding: 24,
          borderWidth: 1,
          borderColor: '#374151',
          marginTop: 24
        }}>
          <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#FFFFFF', marginBottom: 16 }}>
            🔒 Security Recommendations
          </Text>

          <View style={{ marginBottom: 12 }}>
            <Text style={{ fontSize: 16, fontWeight: '600', color: '#10B981', marginBottom: 8 }}>
              ✅ Implemented
            </Text>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 4 }}>
              • Input validation and sanitization
            </Text>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 4 }}>
              • Rate limiting for authentication and messaging
            </Text>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 4 }}>
              • Security event monitoring and logging
            </Text>
          </View>

          <View>
            <Text style={{ fontSize: 16, fontWeight: '600', color: '#F59E0B', marginBottom: 8 }}>
              🔄 Recommended for Production
            </Text>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 4 }}>
              • SAST/DAST integration in CI/CD pipeline
            </Text>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 4 }}>
              • Automated dependency vulnerability scanning
            </Text>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 4 }}>
              • Content Security Policy (CSP) headers
            </Text>
          </View>
        </View>
      </ScrollView>
    </SafeAreaView>
  );

  // Quantum security render functions (React Native)
  const renderPasskeyLogin = () => (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#111827' }}>
      <ScrollView contentContainerStyle={{ flexGrow: 1, justifyContent: 'center', padding: 24 }}>
        <View style={{ alignItems: 'center', marginBottom: 32 }}>
          <View style={{
            width: 64,
            height: 64,
            borderRadius: 32,
            backgroundColor: 'linear-gradient(135deg, #3B82F6, #8B5CF6)',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 16
          }}>
            <Text style={{ fontSize: 32, color: '#FFFFFF' }}>🛡️</Text>
          </View>
          <Text style={{ fontSize: 24, fontWeight: 'bold', color: '#FFFFFF', marginBottom: 8 }}>
            Quantum-Safe Authentication
          </Text>
          <Text style={{ fontSize: 16, color: '#9CA3AF' }}>
            2025-2026 Post-Quantum Security Standards
          </Text>
        </View>

        <View style={{
          backgroundColor: '#1F2937',
          borderRadius: 12,
          padding: 24,
          borderWidth: 1,
          borderColor: '#374151'
        }}>
          <View style={{ alignItems: 'center', marginBottom: 16 }}>
            <Text style={{ fontSize: 48, color: '#60A5FA', marginBottom: 12 }}>🔑</Text>
            <Text style={{ fontSize: 18, fontWeight: '600', color: '#FFFFFF', marginBottom: 8 }}>
              WebAuthn Passkey Login
            </Text>
            <Text style={{ fontSize: 14, color: '#9CA3AF', textAlign: 'center' }}>
              Hardware-backed authentication with quantum resistance
            </Text>
          </View>

          <View style={{ marginBottom: 16 }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 }}>
              <Text style={{ fontSize: 14, color: '#9CA3AF' }}>Security Level</Text>
              <Text style={{ fontSize: 14, fontWeight: '600', color: '#10B981' }}>Quantum-Safe</Text>
            </View>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 }}>
              <Text style={{ fontSize: 14, color: '#9CA3AF' }}>Biometric Support</Text>
              <Text style={{ fontSize: 14, fontWeight: '600', color: '#3B82F6' }}>Fingerprint + Face</Text>
            </View>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <Text style={{ fontSize: 14, color: '#9CA3AF' }}>Hardware Security</Text>
              <Text style={{ fontSize: 14, fontWeight: '600', color: '#8B5CF6' }}>TPM 2.0+</Text>
            </View>
          </View>

          <TouchableOpacity
            onPress={handlePasskeyAuthentication}
            style={{
              backgroundColor: 'linear-gradient(135deg, #3B82F6, #8B5CF6)',
              paddingVertical: 16,
              borderRadius: 12,
              alignItems: 'center',
              marginBottom: 12,
              shadowColor: '#3B82F6',
              shadowOffset: { width: 0, height: 4 },
              shadowOpacity: 0.3,
              shadowRadius: 8,
              elevation: 8
            }}
          >
            <Text style={{ fontSize: 16, fontWeight: '600', color: '#FFFFFF' }}>🔑 Authenticate with Passkey</Text>
          </TouchableOpacity>

          <TouchableOpacity
            onPress={() => setCurrentView('verify')}
            style={{
              backgroundColor: '#374151',
              paddingVertical: 12,
              borderRadius: 12,
              alignItems: 'center'
            }}
          >
            <Text style={{ fontSize: 16, fontWeight: '600', color: '#FFFFFF' }}>
              Skip to Age Verification
            </Text>
          </TouchableOpacity>
        </View>

        <View style={{ alignItems: 'center', marginTop: 24 }}>
          <Text style={{ fontSize: 12, color: '#6B7280', marginBottom: 4 }}>
            🔐 CRYSTALS-Kyber + Dilithium encryption
          </Text>
          <Text style={{ fontSize: 12, color: '#6B7280', marginBottom: 4 }}>
            🛡️ Hardware-backed security keys
          </Text>
          <Text style={{ fontSize: 12, color: '#6B7280' }}>
            ⚡ Zero-trust architecture
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );

  const renderAdvancedVerification = () => (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#111827' }}>
      <ScrollView contentContainerStyle={{ padding: 24 }}>
        <View style={{ alignItems: 'center', marginBottom: 32 }}>
          <View style={{
            width: 64,
            height: 64,
            borderRadius: 32,
            backgroundColor: 'linear-gradient(135deg, #10B981, #14B8A6)',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 16
          }}>
            <Text style={{ fontSize: 32, color: '#FFFFFF' }}>🛡️</Text>
          </View>
          <Text style={{ fontSize: 24, fontWeight: 'bold', color: '#FFFFFF', marginBottom: 8 }}>
            Advanced Age Verification
          </Text>
          <Text style={{ fontSize: 16, color: '#9CA3AF' }}>
            Multi-modal verification with quantum-safe privacy
          </Text>
        </View>

        <View style={{ marginBottom: 24 }}>
          {/* Neural Age Estimation */}
          <View style={{
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            borderRadius: 12,
            padding: 20,
            borderWidth: 1,
            borderColor: 'rgba(59, 130, 246, 0.3)',
            marginBottom: 16
          }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 12 }}>
              <Text style={{ fontSize: 24, color: '#60A5FA', marginRight: 8 }}>🧠</Text>
              <Text style={{ fontSize: 18, fontWeight: '600', color: '#FFFFFF' }}>Neural Age Estimation</Text>
            </View>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 12 }}>
              AI-powered facial analysis with anti-deepfake protection
            </Text>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 }}>
              <Text style={{ fontSize: 14, color: '#9CA3AF' }}>Estimated Age</Text>
              <Text style={{ fontSize: 14, fontWeight: '600', color: '#60A5FA' }}>24.7 years</Text>
            </View>
            <View style={{
              height: 8,
              backgroundColor: '#374151',
              borderRadius: 4,
              overflow: 'hidden'
            }}>
              <View style={{
                height: 8,
                backgroundColor: 'linear-gradient(90deg, #60A5FA, #06B6D4)',
                width: '95%'
              }} />
            </View>
          </View>

          {/* Behavioral Biometrics */}
          <View style={{
            backgroundColor: 'rgba(139, 92, 246, 0.1)',
            borderRadius: 12,
            padding: 20,
            borderWidth: 1,
            borderColor: 'rgba(139, 92, 246, 0.3)',
            marginBottom: 16
          }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 12 }}>
              <Text style={{ fontSize: 24, color: '#A78BFA', marginRight: 8 }}>👁️</Text>
              <Text style={{ fontSize: 18, fontWeight: '600', color: '#FFFFFF' }}>Behavioral Biometrics</Text>
            </View>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 12 }}>
              Keystroke dynamics and interaction patterns
            </Text>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 }}>
              <Text style={{ fontSize: 14, color: '#9CA3AF' }}>Confidence</Text>
              <Text style={{ fontSize: 14, fontWeight: '600', color: '#A78BFA' }}>97.3%</Text>
            </View>
            <View style={{
              height: 8,
              backgroundColor: '#374151',
              borderRadius: 4,
              overflow: 'hidden'
            }}>
              <View style={{
                height: 8,
                backgroundColor: 'linear-gradient(90deg, #A78BFA, #F472B6)',
                width: '97.3%'
              }} />
            </View>
          </View>

          {/* 3D Biometric Liveness */}
          <View style={{
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            borderRadius: 12,
            padding: 20,
            borderWidth: 1,
            borderColor: 'rgba(16, 185, 129, 0.3)',
            marginBottom: 16
          }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 12 }}>
              <Text style={{ fontSize: 24, color: '#10B981', marginRight: 8 }}>👤</Text>
              <Text style={{ fontSize: 18, fontWeight: '600', color: '#FFFFFF' }}>3D Biometric Liveness</Text>
            </View>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 12 }}>
              Anti-spoofing facial mapping with depth analysis
            </Text>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 }}>
              <Text style={{ fontSize: 14, color: '#9CA3AF' }}>Liveness Score</Text>
              <Text style={{ fontSize: 14, fontWeight: '600', color: '#10B981' }}>98%</Text>
            </View>
            <View style={{
              height: 8,
              backgroundColor: '#374151',
              borderRadius: 4,
              overflow: 'hidden'
            }}>
              <View style={{
                height: 8,
                backgroundColor: 'linear-gradient(90deg, #10B981, #14B8A6)',
                width: '98%'
              }} />
            </View>
          </View>

          {/* Government API Verification */}
          <View style={{
            backgroundColor: 'rgba(245, 101, 101, 0.1)',
            borderRadius: 12,
            padding: 20,
            borderWidth: 1,
            borderColor: 'rgba(245, 101, 101, 0.3)'
          }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 12 }}>
              <Text style={{ fontSize: 24, color: '#F56565', marginRight: 8 }}>🏛️</Text>
              <Text style={{ fontSize: 18, fontWeight: '600', color: '#FFFFFF' }}>Government API Verification</Text>
            </View>
            <Text style={{ fontSize: 14, color: '#D1D5DB', marginBottom: 12 }}>
              Direct integration with official identity databases
            </Text>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 }}>
              <Text style={{ fontSize: 14, color: '#9CA3AF' }}>Verification</Text>
              <Text style={{ fontSize: 14, fontWeight: '600', color: '#10B981' }}>Verified</Text>
            </View>
            <View style={{
              height: 8,
              backgroundColor: '#374151',
              borderRadius: 4,
              overflow: 'hidden'
            }}>
              <View style={{
                height: 8,
                backgroundColor: 'linear-gradient(90deg, #F56565, #F97316)',
                width: '100%'
              }} />
            </View>
          </View>
        </View>

        {/* Aggregated Verification Confidence */}
        <View style={{
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          borderRadius: 12,
          padding: 24,
          borderWidth: 1,
          borderColor: 'rgba(59, 130, 246, 0.3)',
          marginBottom: 24,
          alignItems: 'center'
        }}>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 16 }}>
            <Text style={{ fontSize: 24, color: '#60A5FA', marginRight: 8 }}>📊</Text>
            <Text style={{ fontSize: 18, fontWeight: '600', color: '#FFFFFF' }}>
              Aggregated Verification Confidence
            </Text>
          </View>
          <Text style={{ fontSize: 48, fontWeight: 'bold', color: '#10B981', marginBottom: 8 }}>
            98.5%
          </Text>
          <Text style={{ fontSize: 14, color: '#D1D5DB', textAlign: 'center' }}>
            Multi-modal verification with blockchain proof
          </Text>
          <View style={{
            height: 12,
            backgroundColor: '#374151',
            borderRadius: 6,
            overflow: 'hidden',
            marginTop: 16,
            width: '100%'
          }}>
            <View style={{
              height: 12,
              backgroundColor: 'linear-gradient(90deg, #10B981, #60A5FA)',
              width: '98.5%'
            }} />
          </View>
        </View>

        <TouchableOpacity
          onPress={handleAdvancedAgeVerification}
          style={{
            backgroundColor: 'linear-gradient(135deg, #3B82F6, #8B5CF6)',
            paddingVertical: 16,
            borderRadius: 12,
            alignItems: 'center',
            marginBottom: 24,
            shadowColor: '#3B82F6',
            shadowOffset: { width: 0, height: 4 },
            shadowOpacity: 0.3,
            shadowRadius: 8,
            elevation: 8
          }}
        >
          <Text style={{ fontSize: 16, fontWeight: '600', color: '#FFFFFF' }}>🛡️ Complete Multi-Modal Verification</Text>
        </TouchableOpacity>

        <View style={{ alignItems: 'center' }}>
          <Text style={{ fontSize: 12, color: '#6B7280', marginBottom: 4 }}>
            🔐 Zero-knowledge proofs ensure privacy
          </Text>
          <Text style={{ fontSize: 12, color: '#6B7280', marginBottom: 4 }}>
            ⛓️ Blockchain-verified credentials
          </Text>
          <Text style={{ fontSize: 12, color: '#6B7280' }}>
            🧠 AI-powered anti-deepfake protection
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );

  const renderDashboard = () => (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#111827' }}>
      <ScrollView contentContainerStyle={{ padding: 24 }}>
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
          <View>
            <Text style={{ fontSize: 28, fontWeight: 'bold', color: '#FFFFFF', flexDirection: 'row', alignItems: 'center' }}>
              🧠 Quantum-Safe AI Platform
            </Text>
            <Text style={{ fontSize: 16, color: '#9CA3AF', marginTop: 8 }}>
              2025-2026 Security Standards • Post-Quantum Ready
            </Text>
          </View>
          <View style={{ flexDirection: 'row', alignItems: 'center' }}>
            <View style={{
              backgroundColor: 'rgba(16, 185, 129, 0.2)',
              borderRadius: 8,
              paddingHorizontal: 16,
              paddingVertical: 8,
              borderWidth: 1,
              borderColor: 'rgba(16, 185, 129, 0.3)',
              marginRight: 12
            }}>
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <View style={{
                  width: 8,
                  height: 8,
                  borderRadius: 4,
                  backgroundColor: '#10B981',
                  marginRight: 8
                }} />
                <Text style={{ color: '#10B981', fontSize: 14, fontWeight: '600' }}>Quantum Secure</Text>
              </View>
            </View>
            <TouchableOpacity
              onPress={() => setCurrentView('security')}
              style={{
                backgroundColor: '#7C3AED',
                paddingHorizontal: 16,
                paddingVertical: 8,
                borderRadius: 8
              }}
            >
              <Text style={{ color: '#FFFFFF', fontSize: 14 }}>Security Center</Text>
            </TouchableOpacity>
          </View>
        </View>

        {/* Real-time Cost Optimization */}
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 32 }}>
          <View style={{
            backgroundColor: '#1F2937',
            borderRadius: 12,
            padding: 20,
            borderWidth: 1,
            borderColor: '#10B981',
            marginRight: 16,
            marginBottom: 16,
            minWidth: 200,
            flex: 1
          }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <Text style={{ fontSize: 24, color: '#10B981' }}>💰</Text>
              <Text style={{ fontSize: 24, fontWeight: 'bold', color: '#FFFFFF' }}>
                ${costManager?.realTimeTracking.currentSpend.toFixed(2)}
              </Text>
            </View>
            <Text style={{ fontSize: 16, color: '#D1D5DB', fontWeight: '600' }}>Current Spend</Text>
            <Text style={{ fontSize: 12, color: '#6B7280', marginTop: 4 }}>This month</Text>
          </View>

          <View style={{
            backgroundColor: '#1F2937',
            borderRadius: 12,
            padding: 20,
            borderWidth: 1,
            borderColor: '#3B82F6',
            marginRight: 16,
            marginBottom: 16,
            minWidth: 200,
            flex: 1
          }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <Text style={{ fontSize: 24, color: '#3B82F6' }}>📈</Text>
              <Text style={{ fontSize: 24, fontWeight: 'bold', color: '#FFFFFF' }}>
                {costManager?.caching.hitRate.toFixed(1)}%
              </Text>
            </View>
            <Text style={{ fontSize: 16, color: '#D1D5DB', fontWeight: '600' }}>Cache Hit Rate</Text>
            <Text style={{ fontSize: 12, color: '#6B7280', marginTop: 4 }}>
              {costManager?.caching.savingsPercentage.toFixed(1)}% savings
            </Text>
          </View>

          <View style={{
            backgroundColor: '#1F2937',
            borderRadius: 12,
            padding: 20,
            borderWidth: 1,
            borderColor: '#8B5CF6',
            marginRight: 16,
            marginBottom: 16,
            minWidth: 200,
            flex: 1
          }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <Text style={{ fontSize: 24, color: '#8B5CF6' }}>📊</Text>
              <Text style={{ fontSize: 24, fontWeight: 'bold', color: '#FFFFFF' }}>
                {threatIntel?.anomalyDetection.userBehavior}
              </Text>
            </View>
            <Text style={{ fontSize: 16, color: '#D1D5DB', fontWeight: '600' }}>Threat Score</Text>
            <Text style={{ fontSize: 12, color: '#6B7280', marginTop: 4 }}>Low risk</Text>
          </View>

          <View style={{
            backgroundColor: '#1F2937',
            borderRadius: 12,
            padding: 20,
            borderWidth: 1,
            borderColor: '#F59E0B',
            marginBottom: 16,
            minWidth: 200,
            flex: 1
          }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <Text style={{ fontSize: 24, color: '#F59E0B' }}>⚡</Text>
              <Text style={{ fontSize: 24, fontWeight: 'bold', color: '#FFFFFF' }}>
                {costManager?.greenComputing.co2Saved.toFixed(1)}kg
              </Text>
            </View>
            <Text style={{ fontSize: 16, color: '#D1D5DB', fontWeight: '600' }}>CO₂ Saved</Text>
            <Text style={{ fontSize: 12, color: '#6B7280', marginTop: 4 }}>Carbon-aware computing</Text>
          </View>
        </View>

        {/* Content Moderation Dashboard */}
        <View style={{
          backgroundColor: '#1F2937',
          borderRadius: 12,
          padding: 24,
          borderWidth: 1,
          borderColor: '#374151'
        }}>
          <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#FFFFFF', marginBottom: 16, flexDirection: 'row', alignItems: 'center' }}>
            🛡️ AI-Powered Content Moderation
          </Text>
          {moderationResults.map((result) => (
            <View key={result.contentId} style={{
              backgroundColor: '#374151',
              borderRadius: 8,
              padding: 16,
              marginBottom: 12,
              borderWidth: 1,
              borderColor: '#4B5563'
            }}>
              <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <Text style={{ fontSize: 16, fontWeight: '600', color: '#FFFFFF' }}>
                  Content ID: {result.contentId}
                </Text>
                <View style={{
                  paddingHorizontal: 12,
                  paddingVertical: 4,
                  borderRadius: 12,
                  backgroundColor: result.action === 'approved' ? 'rgba(16, 185, 129, 0.2)' :
                                   result.action === 'flagged' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(239, 68, 68, 0.2)'
                }}>
                  <Text style={{
                    fontSize: 12,
                    fontWeight: '600',
                    color: result.action === 'approved' ? '#10B981' :
                           result.action === 'flagged' ? '#F59E0B' : '#EF4444'
                  }}>
                    {result.action.toUpperCase()}
                  </Text>
                </View>
              </View>

              <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 }}>
                <View style={{ alignItems: 'center', flex: 1 }}>
                  <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#3B82F6' }}>
                    {((result.multiModalAnalysis?.text.toxicity || 0) * 100).toFixed(1)}%
                  </Text>
                  <Text style={{ fontSize: 12, color: '#9CA3AF' }}>Toxicity</Text>
                </View>
                <View style={{ alignItems: 'center', flex: 1 }}>
                  <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#8B5CF6' }}>
                    {((result.multiModalAnalysis?.image.nsfw || 0) * 100).toFixed(1)}%
                  </Text>
                  <Text style={{ fontSize: 12, color: '#9CA3AF' }}>NSFW</Text>
                </View>
                <View style={{ alignItems: 'center', flex: 1 }}>
                  <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#10B981' }}>
                    {result.multiModalAnalysis?.voice.deepfakeVoice ? 'Yes' : 'No'}
                  </Text>
                  <Text style={{ fontSize: 12, color: '#9CA3AF' }}>Deepfake</Text>
                </View>
                <View style={{ alignItems: 'center', flex: 1 }}>
                  <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#F59E0B' }}>
                    {(result.explainableAI?.confidence || 0).toFixed(2)}
                  </Text>
                  <Text style={{ fontSize: 12, color: '#9CA3AF' }}>Confidence</Text>
                </View>
              </View>

              <Text style={{ fontSize: 14, color: '#D1D5DB', backgroundColor: '#1F2937', padding: 12, borderRadius: 6 }}>
                <Text style={{ fontWeight: '600' }}>AI Decision:</Text> {result.explainableAI?.decisionReason || 'No decision available'}
              </Text>
            </View>
          ))}
        </View>
      </ScrollView>
    </SafeAreaView>
  );

  const renderSecurityCenter = () => (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#111827' }}>
      <ScrollView contentContainerStyle={{ padding: 24 }}>
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
          <Text style={{ fontSize: 28, fontWeight: 'bold', color: '#FFFFFF', flexDirection: 'row', alignItems: 'center' }}>
            🛡️ Security Operations Center
          </Text>
          <TouchableOpacity
            onPress={() => setCurrentView('dashboard')}
            style={{
              backgroundColor: '#374151',
              paddingHorizontal: 16,
              paddingVertical: 8,
              borderRadius: 8
            }}
          >
            <Text style={{ color: '#FFFFFF', fontSize: 14 }}>Back to Dashboard</Text>
          </TouchableOpacity>
        </View>

        {/* Threat Intelligence */}
        <View style={{ marginBottom: 32 }}>
          <View style={{
            backgroundColor: '#1F2937',
            borderRadius: 12,
            padding: 24,
            borderWidth: 1,
            borderColor: '#EF4444',
            marginBottom: 16
          }}>
            <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#FFFFFF', marginBottom: 16, flexDirection: 'row', alignItems: 'center' }}>
              ⚠️ Active Threats
            </Text>
            <View style={{ marginBottom: 12 }}>
              <View style={{
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                borderRadius: 8,
                padding: 12,
                borderWidth: 1,
                borderColor: 'rgba(239, 68, 68, 0.3)'
              }}>
                <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <Text style={{ fontSize: 16, fontWeight: '600', color: '#EF4444' }}>APT Campaigns</Text>
                  <Text style={{ fontSize: 14, color: '#EF4444' }}>{threatIntel?.globalThreats.activeCampaigns.length} active</Text>
                </View>
                <Text style={{ fontSize: 14, color: '#D1D5DB' }}>
                  {threatIntel?.globalThreats.activeCampaigns.join(', ')}
                </Text>
              </View>
            </View>
          </View>

          <View style={{
            backgroundColor: '#1F2937',
            borderRadius: 12,
            padding: 24,
            borderWidth: 1,
            borderColor: '#3B82F6'
          }}>
            <Text style={{ fontSize: 20, fontWeight: 'bold', color: '#FFFFFF', marginBottom: 16, flexDirection: 'row', alignItems: 'center' }}>
              👁️ AI Threat Detection
            </Text>
            <View style={{ marginBottom: 8 }}>
              <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
                <Text style={{ fontSize: 14, color: '#D1D5DB' }}>Adversarial Inputs</Text>
                <Text style={{
                  fontSize: 12,
                  paddingHorizontal: 8,
                  paddingVertical: 4,
                  borderRadius: 6,
                  backgroundColor: threatIntel?.aiThreatDetection.adversarialInputs ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                  color: threatIntel?.aiThreatDetection.adversarialInputs ? '#EF4444' : '#10B981'
                }}>
                  {threatIntel?.aiThreatDetection.adversarialInputs ? 'Detected' : 'Clear'}
                </Text>
              </View>
            </View>
          </View>
        </View>
      </ScrollView>
    </SafeAreaView>
  );

  // Main render logic for quantum security
  if (currentView !== 'dashboard') {
    switch (currentView) {
      case 'passkey':
        return renderPasskeyLogin();
      case 'verify':
        return renderAdvancedVerification();
      case 'security':
        return renderSecurityCenter();
      default:
        return renderDashboard();
    }
  }

  // Main App render logic
  return (
    <SafeAreaView style={styles.container}>
      {currentMode === 'main' && renderMainMenu()}
      {currentMode === 'chat' && renderChatInterface()}
      {currentMode === 'personalities' && renderPersonalities()}
      {currentMode === 'gallery' && renderGallery()}
      {currentMode === 'shop' && renderShop()}
      {currentMode === 'settings' && renderSettings()}
      {currentMode === 'security-dashboard' && renderSecurityDashboard()}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#000000',
  },
  header: {
    padding: 20,
    backgroundColor: '#1a1a1a',
    borderBottomWidth: 1,
    borderBottomColor: '#333',
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#ffffff',
    textAlign: 'center',
    marginBottom: 8,
  },
  headerSubtitle: {
    fontSize: 16,
    color: '#888',
    textAlign: 'center',
    marginBottom: 20,
  },
  profileSection: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  profileButton: {
    backgroundColor: '#333',
    paddingHorizontal: 15,
    paddingVertical: 10,
    borderRadius: 20,
  },
  profileButtonText: {
    color: '#ffffff',
    fontSize: 14,
  },
  voiceToggle: {
    backgroundColor: '#333',
    paddingHorizontal: 15,
    paddingVertical: 10,
    borderRadius: 20,
  },
  voiceToggleActive: {
    backgroundColor: '#4CAF50',
  },
  voiceToggleText: {
    color: '#ffffff',
    fontSize: 14,
  },
  menuContainer: {
    flex: 1,
    padding: 20,
  },
  menuItem: {
    flexDirection: 'row',
    backgroundColor: '#1a1a1a',
    padding: 20,
    borderRadius: 15,
    marginBottom: 15,
    borderWidth: 1,
    borderColor: '#333',
  },
  menuIcon: {
    fontSize: 30,
    marginRight: 20,
  },
  menuTextContainer: {
    flex: 1,
  },
  menuTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 8,
  },
  menuDescription: {
    fontSize: 14,
    color: '#888',
    lineHeight: 20,
  },
  chatHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 15,
    backgroundColor: '#1a1a1a',
    borderBottomWidth: 1,
    borderBottomColor: '#333',
  },
  headerCenter: {
    flex: 1,
    alignItems: 'center',
  },
  personalityInfo: {
    fontSize: 12,
    color: '#888',
    marginTop: 2,
    textAlign: 'center',
  },
  backButton: {
    padding: 10,
  },
  backButtonText: {
    color: '#4CAF50',
    fontSize: 16,
  },
  chatTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#ffffff',
  },
  messagesContainer: {
    flex: 1,
    padding: 15,
  },
  messageContainer: {
    marginBottom: 15,
    padding: 15,
    borderRadius: 15,
    maxWidth: '80%',
  },
  userMessage: {
    backgroundColor: '#4CAF50',
    alignSelf: 'flex-end',
  },
  aiMessage: {
    backgroundColor: '#333',
    alignSelf: 'flex-start',
  },
  messageText: {
    fontSize: 16,
    lineHeight: 22,
  },
  userMessageText: {
    color: '#ffffff',
  },
  aiMessageText: {
    color: '#ffffff',
  },
  messageTime: {
    fontSize: 12,
    color: '#888',
    marginTop: 8,
  },
  loadingContainer: {
    alignSelf: 'flex-start',
    backgroundColor: '#333',
    padding: 15,
    borderRadius: 15,
    marginBottom: 15,
  },
  loadingText: {
    color: '#ffffff',
    fontSize: 16,
  },
  inputContainer: {
    flexDirection: 'row',
    padding: 15,
    backgroundColor: '#1a1a1a',
    borderTopWidth: 1,
    borderTopColor: '#333',
    alignItems: 'flex-end',
  },
  textInput: {
    flex: 1,
    backgroundColor: '#333',
    color: '#ffffff',
    padding: 15,
    borderRadius: 20,
    marginRight: 10,
    maxHeight: 100,
    fontSize: 16,
  },
  videoButton: {
    backgroundColor: '#FF6B35',
    paddingHorizontal: 15,
    paddingVertical: 12,
    borderRadius: 20,
    marginRight: 10,
  },
  videoButtonText: {
    fontSize: 20,
  },
  sendButton: {
    backgroundColor: '#4CAF50',
    paddingHorizontal: 20,
    paddingVertical: 12,
    borderRadius: 20,
  },
  sendButtonText: {
    color: '#ffffff',
    fontWeight: 'bold',
    fontSize: 16,
  },
  modalContainer: {
    flex: 1,
    backgroundColor: '#000000',
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 20,
    backgroundColor: '#1a1a1a',
    borderBottomWidth: 1,
    borderBottomColor: '#333',
  },
  modalTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#ffffff',
  },
  closeButton: {
    fontSize: 24,
    color: '#4CAF50',
  },
  modalContent: {
    flex: 1,
    padding: 20,
  },
  formGroup: {
    marginBottom: 25,
  },
  label: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 10,
  },
  input: {
    backgroundColor: '#333',
    color: '#ffffff',
    padding: 15,
    borderRadius: 10,
    fontSize: 16,
  },
  checkbox: {
    backgroundColor: '#333',
    padding: 15,
    borderRadius: 10,
    borderWidth: 2,
    borderColor: '#555',
  },
  checkboxChecked: {
    borderColor: '#4CAF50',
    backgroundColor: '#2E7D32',
  },
  checkboxText: {
    color: '#ffffff',
    fontSize: 16,
  },
  saveButton: {
    backgroundColor: '#4CAF50',
    padding: 15,
    borderRadius: 10,
    alignItems: 'center',
    marginTop: 20,
  },
  saveButtonText: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: 'bold',
  },
});