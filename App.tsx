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


type AppMode = 'main' | 'chat';


export default function App() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [openai, setOpenai] = useState<OpenAI | null>(null);
  const [currentMode, setCurrentMode] = useState<AppMode>('main');
  const [showProfileSetup, setShowProfileSetup] = useState(false);
  const [isVoiceMode, setIsVoiceMode] = useState(false);
 
  const [userProfile, setUserProfile] = useState<UserProfile>({
    name: '',
    veteran_status: false,
    language_preference: 'en',
    accessibility_needs: []
  });


  useEffect(() => {
    initializeApp();
    loadUserProfile();
  }, []);


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
        text: "Welcome to your Advanced AI Assistant! 🎖️ I'm here to help with content creation and veteran support. How can I assist you today?",
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


      setMessages(prev => [...prev, userMessage]);
     
      // Check if user is requesting video generation
      const videoKeywords = ['video', 'create video', 'generate video', 'make video', 'video content', 'visual content'];
      const isVideoRequest = videoKeywords.some(keyword =>
        inputText.toLowerCase().includes(keyword.toLowerCase())
      );
     
      if (isVideoRequest) {
        // Handle video generation request
        await handleVideoRequest(inputText);
        setInputText('');
        return;
      }
     
      let responseText = '';
     
      if (openai) {
        const completion = await openai.chat.completions.create({
          model: "gpt-3.5-turbo",
          messages: [
            {
              role: "system",
              content: `You are a compassionate AI assistant with video generation capabilities for veterans and individuals with disabilities.
             
              You help with:
              - AI content creation for income generation
              - Video generation for educational and therapeutic content
              - Veteran support and resources
              - Accessibility guidance
             
              IMPORTANT: If users want video content, suggest they use keywords like "create video", "generate video", or "video about [topic]" to trigger the video generation system.
             
              You have access to multiple video generation APIs:
              - Google Veo (highest quality)
              - Vadoo.tv (great for narrated content)
              - Predis.ai (social media optimized)
              - Audio fallback (always works)
             
              Be supportive and trauma-informed. User profile: ${JSON.stringify(userProfile)}`
            },
            { role: "user", content: inputText }
          ],
          max_tokens: 300,
          temperature: 0.7,
        });
       
        responseText = completion.choices[0]?.message?.content || "I'm here to help you.";
      } else {
        responseText = "I'm here to support you. Please tell me more about what you need.";
      }


      const aiMessage: Message = {
        id: messages.length + 2,
        text: responseText,
        isUser: false,
        timestamp: new Date()
      };


      setMessages(prev => [...prev, aiMessage]);
     
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
        <Text style={styles.chatTitle}>🤖 AI Chat</Text>
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