import React, { useState, useEffect } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TextInput,
  TouchableOpacity,
  SafeAreaView,
  ScrollView,
  Alert,
  StatusBar,
  Modal
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { OpenAI } from 'openai';
import * as Speech from 'expo-speech';
import { AIPersonality } from '../src/core/settings/settings.actions';


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
interface CustomAIPersonality extends AIPersonality {
  userGenerated: boolean;
  voiceCloneUploaded: boolean;
  imageStyleToken: string; // for consistent image generation
  moodAdjustment: number; // dynamic mood modifier
  cycleMode: CycleMode;
}

enum CycleMode {
  MORNING_FOCUS = 'morning_focus',    // Professional, motivational, productive
  MIDDAY_LIGHT = 'midday_light',      // Casual, friendly, supportive
  NIGHT_INTIMATE = 'night_intimate',   // Romantic, seductive, intimate
  WEEKEND_WILD = 'weekend_wild'       // Playful, adventurous, spontaneous
}

interface SecureContentVault {
  encryptedImages: string[];
  encryptedVoiceMessages: string[];
  encryptedVideos: string[];
  unlockMethod: 'pin' | 'biometric';
  accessHistory: VaultAccess[];
  privacyLevel: 'standard' | 'maximum' | 'paranoid';
}

interface VaultAccess {
  timestamp: Date;
  contentType: string;
  accessMethod: string;
  success: boolean;
}

// ============================
// IMAGE GENERATION SYSTEM (Instagram/TikTok Trending)
// ============================
interface ImageAPIConfig {
  name: string;
  endpoint: string;
  apiKey: string;
  priority: number;
  maxRetries: number;
  supports_nsfw: boolean;
  real_time: boolean;
}

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
interface VoiceAPIConfig {
  name: string;
  endpoint: string;
  apiKey: string;
  priority: number;
  supports_emotions: boolean;
  real_time: boolean;
  voice_cloning: boolean;
}

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

interface VirtualGift {
  id: string;
  name: string;
  emoji: string;
  price: number;
  rarity: 'common' | 'rare' | 'epic' | 'legendary';
  effect: string;
  unlocks?: string;
}

interface ContentRequest {
  id: string;
  userId: string;
  personalityId: string;
  type: 'photo' | 'video' | 'voice' | 'custom_chat';
  description: string;
  price: number;
  status: 'pending' | 'accepted' | 'completed' | 'rejected';
  deadline: Date;
  isNSFW: boolean;
}

// ============================
// SOCIAL MEDIA INTEGRATION (Instagram/TikTok/Chinese Platforms)
// ============================
interface SocialPlatform {
  name: 'instagram' | 'tiktok' | 'twitter' | 'weibo' | 'douyin' | 'xiaohongshu';
  apiEndpoint: string;
  apiKey: string;
  isActive: boolean;
  autoPost: boolean;
  contentTypes: string[];
}

interface ContentSchedule {
  id: string;
  platform: string;
  content: string;
  media: string[];
  scheduledTime: Date;
  hashtags: string[];
  isNSFW: boolean;
  personalityId: string;
  targetAudience: string;
}


// Video Generation API Configuration
interface VideoAPIConfig {
  name: string;
  endpoint: string;
  apiKey: string;
  priority: number;
  maxRetries: number;
}


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


// Multiple Video API Configurations with Failover System
const videoAPIs: VideoAPIConfig[] = [
  {
    name: 'Google Veo',
    endpoint: 'https://vertex-ai.googleapis.com/v1/projects/YOUR_PROJECT/locations/us-central1/publishers/google/models/veo-001:generateVideo',
    apiKey: process.env.GOOGLE_CLOUD_API_KEY || 'your-google-api-key',
    priority: 1,
    maxRetries: 2
  },
  {
    name: 'Vadoo.tv',
    endpoint: 'https://api.vadoo.tv/v1/video/generate',
    apiKey: process.env.VADOO_API_KEY || 'your-vadoo-api-key',
    priority: 2,
    maxRetries: 2
  },
  {
    name: 'Predis.ai',
    endpoint: 'https://api.predis.ai/v1/text-to-video',
    apiKey: process.env.PREDIS_API_KEY || 'your-predis-api-key',
    priority: 3,
    maxRetries: 2
  }
];

// ============================
// CUTTING-EDGE IMAGE GENERATION APIS (Chinese + Western)
// ============================
const imageAPIs: ImageAPIConfig[] = [
  {
    name: 'DALL-E 3',
    endpoint: 'https://api.openai.com/v1/images/generations',
    apiKey: process.env.OPENAI_API_KEY || 'your-openai-key',
    priority: 1,
    maxRetries: 2,
    supports_nsfw: false,
    real_time: true
  },
  {
    name: 'Stable Diffusion XL',
    endpoint: 'https://api.stability.ai/v1/generation/stable-diffusion-xl-1024-v1-0/text-to-image',
    apiKey: process.env.STABILITY_API_KEY || 'your-stability-key',
    priority: 2,
    maxRetries: 2,
    supports_nsfw: true,
    real_time: true
  },
  {
    name: 'Midjourney',
    endpoint: 'https://api.midjourney.com/v1/imagine',
    apiKey: process.env.MIDJOURNEY_API_KEY || 'your-midjourney-key',
    priority: 3,
    maxRetries: 2,
    supports_nsfw: false,
    real_time: false
  },
  {
    name: 'Baidu Ernie-ViLG (Chinese)',
    endpoint: 'https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/text2image/sd_xl',
    apiKey: process.env.BAIDU_API_KEY || 'your-baidu-key',
    priority: 4,
    maxRetries: 2,
    supports_nsfw: true,
    real_time: true
  },
  {
    name: 'Alibaba Tongyi Wanxiang',
    endpoint: 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text2image/image-synthesis',
    apiKey: process.env.ALIBABA_API_KEY || 'your-alibaba-key',
    priority: 5,
    maxRetries: 2,
    supports_nsfw: true,
    real_time: true
  }
];

// ============================
// ADVANCED VOICE SYNTHESIS APIS (ElevenLabs + Chinese Voice Tech)
// ============================
const voiceAPIs: VoiceAPIConfig[] = [
  {
    name: 'ElevenLabs',
    endpoint: 'https://api.elevenlabs.io/v1/text-to-speech',
    apiKey: process.env.ELEVENLABS_API_KEY || 'your-elevenlabs-key',
    priority: 1,
    supports_emotions: true,
    real_time: true,
    voice_cloning: true
  },
  {
    name: 'Azure Speech Services',
    endpoint: 'https://[region].tts.speech.microsoft.com/cognitiveservices/v1',
    apiKey: process.env.AZURE_SPEECH_KEY || 'your-azure-key',
    priority: 2,
    supports_emotions: true,
    real_time: true,
    voice_cloning: false
  },
  {
    name: 'Baidu Speech (Chinese)',
    endpoint: 'https://tsn.baidu.com/text2audio',
    apiKey: process.env.BAIDU_SPEECH_KEY || 'your-baidu-speech-key',
    priority: 3,
    supports_emotions: true,
    real_time: true,
    voice_cloning: true
  },
  {
    name: 'iFlytek Voice (Chinese)',
    endpoint: 'https://api.xfyun.cn/v2/tts',
    apiKey: process.env.IFLYTEK_API_KEY || 'your-iflytek-key',
    priority: 4,
    supports_emotions: true,
    real_time: true,
    voice_cloning: true
  }
];

// ============================
// ADVANCED MOOD ANALYSIS SYSTEM
// ============================
const analyzeSentiment = (text: string): number => {
  const positiveWords = ['happy', 'great', 'amazing', 'wonderful', 'fantastic', 'love', 'excellent', 'perfect', 'awesome', 'brilliant', 'excited', 'joy', 'beautiful', 'incredible', 'outstanding'];
  const negativeWords = ['sad', 'terrible', 'awful', 'horrible', 'hate', 'angry', 'frustrated', 'depressed', 'anxious', 'worried', 'scared', 'lonely', 'tired', 'stressed', 'overwhelmed'];
  const intimateWords = ['kiss', 'touch', 'close', 'together', 'intimate', 'passion', 'desire', 'love', 'romance', 'cuddle', 'embrace', 'caress', 'gentle', 'tender', 'affection'];
  
  const words = text.toLowerCase().split(/\s+/);
  let sentiment = 0;
  
  words.forEach(word => {
    if (positiveWords.includes(word)) sentiment += 10;
    if (negativeWords.includes(word)) sentiment -= 10;
    if (intimateWords.includes(word)) sentiment += 5; // Slight positive bias for intimacy
  });
  
  // Account for punctuation intensity
  const exclamationCount = (text.match(/!/g) || []).length;
  const questionCount = (text.match(/\?/g) || []).length;
  
  sentiment += exclamationCount * 3; // Excitement boost
  sentiment += questionCount * 1; // Curiosity boost
  
  return sentiment;
};

const adjustMood = (recentMessages: Message[]): number => {
  // Advanced sentiment analysis with conversation context
  const mood = recentMessages.reduce((acc, msg) => {
    const sentimentScore = msg.isUser ? analyzeSentiment(msg.text) : 0;
    const timeDecay = Math.max(0.1, 1 - (Date.now() - msg.timestamp.getTime()) / (1000 * 60 * 60)); // Decay over hours
    return acc + (sentimentScore * timeDecay);
  }, 0);
  
  return Math.max(-100, Math.min(100, mood)); // -100 = depressed, 100 = euphoric
};

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
// SECURE CONTENT VAULT SYSTEM
// ============================
const createSecureVault = (): SecureContentVault => {
  return {
    encryptedImages: [],
    encryptedVoiceMessages: [],
    encryptedVideos: [],
    unlockMethod: 'pin',
    accessHistory: [],
    privacyLevel: 'standard'
  };
};

const encryptContent = (content: string, key: string): string => {
  // Simple XOR encryption for demo (use proper encryption in production)
  let encrypted = '';
  for (let i = 0; i < content.length; i++) {
    encrypted += String.fromCharCode(content.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return btoa(encrypted); // Base64 encode
};

const decryptContent = (encryptedContent: string, key: string): string => {
  try {
    const decoded = atob(encryptedContent); // Base64 decode
    let decrypted = '';
    for (let i = 0; i < decoded.length; i++) {
      decrypted += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return decrypted;
  } catch (error) {
    console.error('Decryption failed:', error);
    return '';
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
const virtualGifts: VirtualGift[] = [
  { id: 'heart', name: 'Heart', emoji: '❤️', price: 1, rarity: 'common', effect: '+5 affection' },
  { id: 'rose', name: 'Rose', emoji: '🌹', price: 5, rarity: 'common', effect: '+10 romance' },
  { id: 'diamond', name: 'Diamond', emoji: '💎', price: 25, rarity: 'rare', effect: '+20 excitement' },
  { id: 'crown', name: 'Crown', emoji: '👑', price: 50, rarity: 'epic', effect: 'Unlocks royal treatment' },
  { id: 'kiss', name: 'Kiss', emoji: '💋', price: 10, rarity: 'common', effect: '+15 intimacy' },
  { id: 'champagne', name: 'Champagne', emoji: '🍾', price: 30, rarity: 'rare', effect: 'Virtual celebration' },
  { id: 'lingerie', name: 'Lingerie', emoji: '👙', price: 75, rarity: 'epic', effect: 'Unlocks intimate photos' },
  { id: 'yacht', name: 'Yacht', emoji: '🛥️', price: 500, rarity: 'legendary', effect: 'Virtual vacation date' }
];


type AppMode = 'main' | 'chat' | 'personalities' | 'gallery' | 'shop' | 'settings';


export default function App() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [openai, setOpenai] = useState<OpenAI | null>(null);
  const [currentMode, setCurrentMode] = useState<AppMode>('main');
  const [showProfileSetup, setShowProfileSetup] = useState(false);
  const [isVoiceMode, setIsVoiceMode] = useState(false);
  
  // ============================
  // NEW STATE FOR ADVANCED FEATURES
  // ============================
  const [selectedPersonality, setSelectedPersonality] = useState<AIPersonality | null>(null);
  const [relationshipStates, setRelationshipStates] = useState<RelationshipState[]>([]);
  const [generatedImages, setGeneratedImages] = useState<ImageGenerationResponse[]>([]);
  const [userSubscription, setUserSubscription] = useState<SubscriptionTier>(subscriptionTiers[0]);
  const [userCredits, setUserCredits] = useState(100);
  const [conversationMemory, setConversationMemory] = useState<ConversationMemory[]>([]);
  const [isGeneratingImage, setIsGeneratingImage] = useState(false);
  const [isGeneratingVoice, setIsGeneratingVoice] = useState(false);
  const [currentEmotion, setCurrentEmotion] = useState<string>('neutral');
  const [intimacyLevel, setIntimacyLevel] = useState(0);
  const [showNSFWContent, setShowNSFWContent] = useState(false);
  
  // ============================
  // ENHANCED MOOD & PERSONALITY STATE
  // ============================
  const [currentMood, setCurrentMood] = useState(0);
  const [cycleMode, setCycleMode] = useState<CycleMode>(getCurrentCycleMode());
  const [customPersonalities, setCustomPersonalities] = useState<CustomAIPersonality[]>([]);
  const [secureVault, setSecureVault] = useState<SecureContentVault>(createSecureVault());
  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  const [userPin, setUserPin] = useState<string>('');
  const [moodHistory, setMoodHistory] = useState<{timestamp: Date, mood: number}[]>([]);
 
  const [userProfile, setUserProfile] = useState<UserProfile>({
    name: '',
    veteran_status: false,
    language_preference: 'en',
    accessibility_needs: []
  });


  const loadSecureVault = async () => {
    try {
      const stored = await AsyncStorage.getItem('secure_vault');
      if (stored) {
        setSecureVault(JSON.parse(stored));
      }
    } catch (error) {
      console.error('Error loading secure vault:', error);
    }
  };

  const saveSecureVault = async (vault: SecureContentVault) => {
    try {
      await AsyncStorage.setItem('secure_vault', JSON.stringify(vault));
      setSecureVault(vault);
    } catch (error) {
      console.error('Error saving secure vault:', error);
    }
  };

  const updatePersonalityWithMood = (personality: AIPersonality): AIPersonality => {
    const moodAdjustments = getCycleMoodAdjustment(cycleMode, personality);
    const moodInfluence = currentMood / 100; // -1 to 1
    
    return {
      ...personality,
      emotionalState: {
        ...personality.emotionalState,
        ...moodAdjustments,
        happiness: Math.max(0, Math.min(100, personality.emotionalState.happiness + (moodInfluence * 20))),
        stress: Math.max(0, Math.min(100, personality.emotionalState.stress - (moodInfluence * 15))),
        energy: Math.max(0, Math.min(100, personality.emotionalState.energy + (moodInfluence * 10)))
      }
    };
  };

  useEffect(() => {
    initializeApp();
    loadUserProfile();
    loadPersonalities();
    loadRelationshipStates();
    loadSecureVault();
    
    // Update cycle mode every hour
    const cycleInterval = setInterval(() => {
      setCycleMode(getCurrentCycleMode());
    }, 1000 * 60 * 60) as any; // Every hour
    
    // Update mood every 30 seconds based on recent messages
    const moodInterval = setInterval(() => {
      const recentMessages = messages.slice(-10); // Last 10 messages
      const newMood = adjustMood(recentMessages);
      setCurrentMood(newMood);
      
      // Track mood history
      setMoodHistory((prev: any) => [...prev.slice(-23), { timestamp: new Date(), mood: newMood }]); // Keep last 24 hours
    }, 30000) as any; // Every 30 seconds
    
    return () => {
      clearInterval(cycleInterval);
      clearInterval(moodInterval);
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


  const saveUserProfile = async (profile: UserProfile) => {
    try {
      await AsyncStorage.setItem('user_profile', JSON.stringify(profile));
      setUserProfile(profile);
    } catch (error) {
      console.error('Error saving user profile:', error);
    }
  };

  // ============================
  // ADVANCED PERSONALITY AND RELATIONSHIP MANAGEMENT
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
        existingStates[existingIndex] = { ...existingStates[existingIndex], ...updates };
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
    setIsGeneratingImage(true);
    
    if (!canGenerateContent('image')) {
      setIsGeneratingImage(false);
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
            
            setIsGeneratingImage(false);
            return response;
          }
        } catch (error) {
          console.warn(`${api.name} failed (attempt ${attempt + 1}):`, error);
        }
      }
    }
   
    setIsGeneratingImage(false);
    throw new Error('All image generation APIs failed');
  };

  const tryImageAPI = async (api: ImageAPIConfig, request: ImageGenerationRequest): Promise<ImageGenerationResponse> => {
    const startTime = Date.now();
    
    switch (api.name) {
      case 'DALL-E 3':
        return await generateWithDALLE3(api, request);
      case 'Stable Diffusion XL':
        return await generateWithStableDiffusion(api, request);
      case 'Baidu Ernie-ViLG (Chinese)':
        return await generateWithBaidu(api, request);
      case 'Alibaba Tongyi Wanxiang':
        return await generateWithAlibaba(api, request);
      default:
        throw new Error(`Unknown API: ${api.name}`);
    }
  };

  const generateWithDALLE3 = async (api: ImageAPIConfig, request: ImageGenerationRequest): Promise<ImageGenerationResponse> => {
    const personality = selectedPersonality;
    const enhancedPrompt = `${request.prompt}. Character: ${personality?.name}, ${personality?.appearance.hairColor} hair, ${personality?.appearance.eyeColor} eyes, ${personality?.appearance.bodyType} build, ${request.emotion} expression, ${request.pose} pose, wearing ${request.clothing}, in ${request.setting}. Style: ${request.style}, high quality, detailed`;
    
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api.apiKey}`,
      },
      body: JSON.stringify({
        model: 'dall-e-3',
        prompt: enhancedPrompt,
        n: 1,
        size: request.aspectRatio === '1:1' ? '1024x1024' : '1792x1024',
        quality: request.quality === 'ultra' ? 'hd' : 'standard',
        style: request.style === 'realistic' ? 'natural' : 'vivid'
      }),
    });

    if (!response.ok) {
      throw new Error(`DALL-E 3 API error: ${response.statusText}`);
    }

    const data = await response.json();
    return {
      success: true,
      imageUrl: data.data[0].url,
      promptUsed: enhancedPrompt,
      provider: 'DALL-E 3',
      processingTime: Date.now() - Date.now(),
      isNSFW: request.nsfwLevel !== 'safe',
    };
  };

  const generateWithStableDiffusion = async (api: ImageAPIConfig, request: ImageGenerationRequest): Promise<ImageGenerationResponse> => {
    const personality = selectedPersonality;
    const enhancedPrompt = `masterpiece, best quality, ${request.prompt}, ${personality?.name}, ${personality?.appearance.hairColor} hair, ${personality?.appearance.eyeColor} eyes, ${request.emotion} expression, ${request.pose}, ${request.clothing}, ${request.setting}, ${request.style} style`;
    
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api.apiKey}`,
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        text_prompts: [{ text: enhancedPrompt, weight: 1 }],
        cfg_scale: 7,
        height: request.aspectRatio === '9:16' ? 1344 : 1024,
        width: request.aspectRatio === '16:9' ? 1344 : 1024,
        samples: 1,
        steps: request.quality === 'ultra' ? 50 : 30,
        sampler: 'K_DPM_2_ANCESTRAL'
      }),
    });

    if (!response.ok) {
      throw new Error(`Stable Diffusion API error: ${response.statusText}`);
    }

    const data = await response.json();
    return {
      success: true,
      imageUrl: `data:image/png;base64,${data.artifacts[0].base64}`,
      promptUsed: enhancedPrompt,
      provider: 'Stable Diffusion XL',
      processingTime: Date.now() - Date.now(),
      isNSFW: request.nsfwLevel !== 'safe',
    };
  };

  const generateWithBaidu = async (api: ImageAPIConfig, request: ImageGenerationRequest): Promise<ImageGenerationResponse> => {
    const personality = selectedPersonality;
    const enhancedPrompt = `${request.prompt}, ${personality?.name}, ${personality?.appearance.hairColor}头发, ${personality?.appearance.eyeColor}眼睛, ${request.emotion}表情, ${request.style}风格`;
    
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api.apiKey}`,
      },
      body: JSON.stringify({
        prompt: enhancedPrompt,
        width: 1024,
        height: 1024,
        image_num: 1,
        style: request.style
      }),
    });

    if (!response.ok) {
      throw new Error(`Baidu API error: ${response.statusText}`);
    }

    const data = await response.json();
    return {
      success: true,
      imageUrl: data.data[0].b64_image ? `data:image/png;base64,${data.data[0].b64_image}` : data.data[0].url,
      promptUsed: enhancedPrompt,
      provider: 'Baidu Ernie-ViLG',
      processingTime: Date.now() - Date.now(),
      isNSFW: request.nsfwLevel !== 'safe',
    };
  };

  const generateWithAlibaba = async (api: ImageAPIConfig, request: ImageGenerationRequest): Promise<ImageGenerationResponse> => {
    const personality = selectedPersonality;
    const enhancedPrompt = `${request.prompt}, ${personality?.name}, ${personality?.appearance.hairColor}头发, ${personality?.appearance.eyeColor}眼睛, ${request.emotion}表情, ${request.style}风格`;
    
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api.apiKey}`,
        'X-DashScope-Async': 'enable',
      },
      body: JSON.stringify({
        model: 'wanx-v1',
        input: {
          prompt: enhancedPrompt,
          negative_prompt: 'low quality, blurry, distorted',
          style: request.style,
          size: '1024*1024',
          n: 1,
          seed: Math.floor(Math.random() * 1000000)
        }
      }),
    });

    if (!response.ok) {
      throw new Error(`Alibaba API error: ${response.statusText}`);
    }

    const data = await response.json();
    return {
      success: true,
      imageUrl: data.output.results[0].url,
      promptUsed: enhancedPrompt,
      provider: 'Alibaba Tongyi Wanxiang',
      processingTime: Date.now() - Date.now(),
      isNSFW: request.nsfwLevel !== 'safe',
    };
  };

  // ============================
  // ADVANCED VOICE SYNTHESIS (ElevenLabs + Chinese Voice Tech)
  // ============================
  const generateVoice = async (request: VoiceGenerationRequest): Promise<string> => {
    setIsGeneratingVoice(true);
    
    if (!canGenerateContent('voice')) {
      setIsGeneratingVoice(false);
      throw new Error('Upgrade your subscription for voice generation');
    }
    
    const sortedAPIs = voiceAPIs.sort((a, b) => a.priority - b.priority);
   
    for (const api of sortedAPIs) {
      try {
        console.log(`Attempting voice generation with ${api.name}`);
        
        const audioUrl = await tryVoiceAPI(api, request);
        if (audioUrl) {
          console.log(`Voice generated successfully with ${api.name}`);
          setUserCredits((prev: number) => Math.max(0, prev - 1));
          setIsGeneratingVoice(false);
          return audioUrl;
        }
      } catch (error) {
        console.warn(`${api.name} failed:`, error);
      }
    }
   
    setIsGeneratingVoice(false);
    throw new Error('All voice generation APIs failed');
  };

  const tryVoiceAPI = async (api: VoiceAPIConfig, request: VoiceGenerationRequest): Promise<string> => {
    switch (api.name) {
      case 'ElevenLabs':
        return await generateWithElevenLabs(api, request);
      case 'Azure Speech Services':
        return await generateWithAzureSpeech(api, request);
      case 'Baidu Speech (Chinese)':
        return await generateWithBaiduSpeech(api, request);
      default:
        throw new Error(`Unknown Voice API: ${api.name}`);
    }
  };

  const generateWithElevenLabs = async (api: VoiceAPIConfig, request: VoiceGenerationRequest): Promise<string> => {
    const response = await fetch(`${api.endpoint}/${request.voice_id}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'xi-api-key': api.apiKey,
      },
      body: JSON.stringify({
        text: request.text,
        model_id: 'eleven_multilingual_v2',
        voice_settings: {
          stability: request.stability,
          similarity_boost: request.similarity_boost,
          style: request.emotion === 'seductive' ? 0.8 : 0.4,
          use_speaker_boost: true
        }
      }),
    });

    if (!response.ok) {
      throw new Error(`ElevenLabs API error: ${response.statusText}`);
    }

    const audioBlob = await response.blob();
    return URL.createObjectURL(audioBlob);
  };

  const generateWithAzureSpeech = async (api: VoiceAPIConfig, request: VoiceGenerationRequest): Promise<string> => {
    const ssml = `
      <speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xml:lang="en-US">
        <voice name="en-US-AriaNeural">
          <prosody rate="${request.speed}x" pitch="${request.pitch > 1 ? '+' : ''}${(request.pitch - 1) * 50}%">
            <express-as style="${request.emotion}">
              ${request.text}
            </express-as>
          </prosody>
        </voice>
      </speak>
    `;

    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/ssml+xml',
        'X-Microsoft-OutputFormat': 'audio-16khz-32kbitrate-mono-mp3',
        'Ocp-Apim-Subscription-Key': api.apiKey,
      },
      body: ssml,
    });

    if (!response.ok) {
      throw new Error(`Azure Speech API error: ${response.statusText}`);
    }

    const audioBlob = await response.blob();
    return URL.createObjectURL(audioBlob);
  };

  const generateWithBaiduSpeech = async (api: VoiceAPIConfig, request: VoiceGenerationRequest): Promise<string> => {
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        tok: api.apiKey,
        tex: request.text,
        lan: 'zh',
        ctp: '1',
        cuid: 'cosmos-predict-app',
        spd: Math.round(request.speed * 5).toString(),
        pit: Math.round(request.pitch * 5).toString(),
        vol: '9',
        per: request.emotion === 'seductive' ? '4' : '1'
      }),
    });

    if (!response.ok) {
      throw new Error(`Baidu Speech API error: ${response.statusText}`);
    }

    const audioBlob = await response.blob();
    return URL.createObjectURL(audioBlob);
  };

  const canGenerateContent = (type: 'image' | 'video' | 'voice'): boolean => {
    const limits = userSubscription;
    switch (type) {
      case 'image':
        return limits.imageLimit === -1 || generatedImages.length < limits.imageLimit;
      case 'video':
        return limits.videoLimit === -1 || userCredits >= 10;
      case 'voice':
        return limits.voiceLimit === -1 || userCredits >= 1;
      default:
        return false;
    }
  };

  const getImageCost = (request: ImageGenerationRequest): number => {
    let cost = 5;
    if (request.quality === 'ultra') cost += 5;
    if (request.nsfwLevel === 'explicit') cost += 10;
    if (request.style === 'realistic') cost += 3;
    return cost;
  };


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


  const tryVideoAPI = async (api: VideoAPIConfig, request: VideoGenerationRequest): Promise<VideoGenerationResponse> => {
    switch (api.name) {
      case 'Google Veo':
        return await generateWithGoogleVeo(api, request);
      case 'Vadoo.tv':
        return await generateWithVadoo(api, request);
      case 'Predis.ai':
        return await generateWithPredis(api, request);
      default:
        throw new Error(`Unknown API: ${api.name}`);
    }
  };


  const generateWithGoogleVeo = async (api: VideoAPIConfig, request: VideoGenerationRequest): Promise<VideoGenerationResponse> => {
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api.apiKey}`,
      },
      body: JSON.stringify({
        prompt: request.prompt,
        duration: request.duration || 30,
        style: request.style || 'educational',
        resolution: '1280x720',
        fps: 24,
        veteran_optimized: request.veteranFriendly !== false
      }),
    });


    if (!response.ok) {
      throw new Error(`Google Veo API error: ${response.statusText}`);
    }


    const data = await response.json();
    return {
      success: true,
      videoUrl: data.video_url,
      thumbnailUrl: data.thumbnail_url,
      duration: data.duration,
      provider: 'Google Veo'
    };
  };


  const generateWithVadoo = async (api: VideoAPIConfig, request: VideoGenerationRequest): Promise<VideoGenerationResponse> => {
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api.apiKey}`,
      },
      body: JSON.stringify({
        text: request.prompt,
        voice: request.voiceGender || 'neutral',
        include_subtitles: request.includeSubtitles !== false,
        style: request.style || 'educational',
        veteran_optimized: request.veteranFriendly !== false,
        duration: request.duration || 30
      }),
    });


    if (!response.ok) {
      throw new Error(`Vadoo API error: ${response.statusText}`);
    }


    const data = await response.json();
    return {
      success: true,
      videoUrl: data.video_url,
      audioUrl: data.audio_url,
      thumbnailUrl: data.thumbnail_url,
      duration: data.duration,
      provider: 'Vadoo.tv'
    };
  };


  const generateWithPredis = async (api: VideoAPIConfig, request: VideoGenerationRequest): Promise<VideoGenerationResponse> => {
    const response = await fetch(api.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api.apiKey}`,
      },
      body: JSON.stringify({
        prompt: request.prompt,
        format: 'mp4',
        quality: 'high',
        social_optimized: true,
        captions: request.includeSubtitles !== false,
        duration: request.duration || 30,
        style: request.style || 'educational'
      }),
    });


    if (!response.ok) {
      throw new Error(`Predis API error: ${response.statusText}`);
    }


    const data = await response.json();
    return {
      success: true,
      videoUrl: data.download_url,
      thumbnailUrl: data.thumbnail,
      duration: data.duration,
      provider: 'Predis.ai'
    };
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
        setMessages(prev => [...prev, message]);
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
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };


  const handleSendMessage = async () => {
    if (!inputText.trim()) return;
   
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
            emotion: currentEmotion as any,
            pose: 'portrait',
            clothing: 'casual',
            setting: 'studio',
            quality: 'high',
            aspectRatio: '1:1',
            isPrivate: true,
            nsfwLevel: showNSFWContent ? 'mature' : 'safe'
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
            emotion: currentEmotion as any,
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
          
          USER MOOD: ${currentMood > 30 ? 'Very Positive' : currentMood > 10 ? 'Positive' : currentMood > -10 ? 'Neutral' : currentMood > -30 ? 'Negative' : 'Very Negative'} (${currentMood}/100)
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
          ${showNSFWContent ? 'NSFW content is enabled. You can be flirtatious and intimate when appropriate.' : 'Keep content safe and appropriate.'}
          
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
          USER MOOD: ${currentMood > 30 ? 'Very Positive' : currentMood > 10 ? 'Positive' : currentMood > -10 ? 'Neutral' : currentMood > -30 ? 'Negative' : 'Very Negative'} (${currentMood}/100)
             
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
      setMessages(prev => [...prev, errorMessage]);
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
          <TouchableOpacity
            style={styles.profileButton}
            onPress={() => setShowProfileSetup(true)}
          >
            <Text style={styles.profileButtonText}>
              {userProfile.name ? `👤 ${userProfile.name}` : '👤 Setup Profile'}
            </Text>
          </TouchableOpacity>
         
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


  const renderAIChat = () => (
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
              {selectedPersonality.name} • {cycleMode.replace('_', ' ')} • Mood: {currentMood > 0 ? '😊' : currentMood < -20 ? '😔' : '😐'}
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
        {messages.map((message) => (
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


  const renderProfileSetup = () => (
    <Modal visible={showProfileSetup} animationType="slide">
      <SafeAreaView style={styles.modalContainer}>
        <View style={styles.modalHeader}>
          <Text style={styles.modalTitle}>Profile Setup</Text>
          <TouchableOpacity onPress={() => setShowProfileSetup(false)}>
            <Text style={styles.closeButton}>✕</Text>
          </TouchableOpacity>
        </View>
       
        <ScrollView style={styles.modalContent}>
          <View style={styles.formGroup}>
            <Text style={styles.label}>Name</Text>
            <TextInput
              style={styles.input}
              value={userProfile.name}
              onChangeText={(text) => setUserProfile(prev => ({ ...prev, name: text }))}
              placeholder="Enter your name"
              placeholderTextColor="#888"
            />
          </View>
         
          <View style={styles.formGroup}>
            <Text style={styles.label}>Veteran Status</Text>
            <TouchableOpacity
              style={[styles.checkbox, userProfile.veteran_status && styles.checkboxChecked]}
              onPress={() => setUserProfile(prev => ({ ...prev, veteran_status: !prev.veteran_status }))}
            >
              <Text style={styles.checkboxText}>
                {userProfile.veteran_status ? '✓' : ''} I am a military veteran
              </Text>
            </TouchableOpacity>
          </View>
         
          <TouchableOpacity
            style={styles.saveButton}
            onPress={() => {
              saveUserProfile(userProfile);
              setShowProfileSetup(false);
              Alert.alert('Profile Saved', 'Your profile has been saved successfully!');
            }}
          >
            <Text style={styles.saveButtonText}>Save Profile</Text>
          </TouchableOpacity>
        </ScrollView>
      </SafeAreaView>
    </Modal>
  );


  if (currentMode === 'chat') {
    return (
      <>
        {renderAIChat()}
        {renderProfileSetup()}
      </>
    );
  }


  return (
    <>
      {renderMainMenu()}
      {renderProfileSetup()}
    </>
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