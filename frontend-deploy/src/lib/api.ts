'use client';

import { AuthUser, CreateFamilyRequest, FamilyProfile, InviteMemberRequest, SubdomainInfo, FamilyPost, MediaAttachment } from './types';

// Export types that components might need
export type Post = FamilyPost;
export interface MediaUpload {
  file: File;
  type: 'image' | 'video';
  alt?: string;
}

export interface UploadResponse {
  url: string;
}

// Hardcode the API base URL to prevent any environment variable issues
const API_BASE_URL = 'https://kinjar-api.fly.dev';

// Debug: log the API base URL for troubleshooting
if (typeof window !== 'undefined') {
  console.log(`[API] Environment API_URL: ${process.env.NEXT_PUBLIC_API_URL}`);
  console.log(`[API] Final API_BASE_URL: ${API_BASE_URL}`);
}

// Demo mode configuration for development/testing
const DEMO_MODE = {
  enabled: false,  // Disabled to use real API
  credentials: {
    email: 'testuser@kinjar.com',
    password: 'TestPass123!',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiIxNjc0Njc0ZS04ZDA1LTQ1ZjYtODA3NS04OWJjNDdlNDkyZDgiLCJpYXQiOjE3NjIxODU0NDcsImV4cCI6MTc2MzM5NTA0N30.pTwpnFEOaNL8VIvPn6CjI9cQ40pUNIZuWxUo3sAGwQc'
  }
};

// Utility to get subdomain information
export function getSubdomainInfo(): SubdomainInfo {
  if (typeof window === 'undefined') {
    return { isSubdomain: false, isRootDomain: true };
  }

  const hostname = window.location.hostname;
  const parts = hostname.split('.');

  // Handle localhost development
  if (hostname === 'localhost' || hostname.startsWith('192.168.') || hostname.startsWith('127.0.0.1')) {
    const urlParams = new URLSearchParams(window.location.search);
    const devFamily = urlParams.get('family');
    if (devFamily) {
      return {
        isSubdomain: true,
        subdomain: devFamily,
        familySlug: devFamily,
        isRootDomain: false
      };
    }
    return { isSubdomain: false, isRootDomain: true };
  }

  // Production subdomain detection for kinjar.com
  if (parts.length >= 3 && parts[parts.length - 2] === 'kinjar' && parts[parts.length - 1] === 'com') {
    const subdomain = parts.slice(0, -2).join('.');
    if (subdomain && subdomain !== 'www' && subdomain !== 'admin') {
      return {
        isSubdomain: true,
        subdomain,
        familySlug: subdomain,
        isRootDomain: false
      };
    }
  }

  // Handle direct .kinjar.com subdomains (like slaughterbeck.kinjar.com)
  if (parts.length === 3 && parts[1] === 'kinjar' && parts[2] === 'com') {
    const subdomain = parts[0];
    if (subdomain && subdomain !== 'www' && subdomain !== 'admin') {
      return {
        isSubdomain: true,
        subdomain,
        familySlug: subdomain,
        isRootDomain: false
      };
    }
  }

  return { isSubdomain: false, isRootDomain: true };
}

// API client class
class KinjarAPI {
  private baseURL: string;
  private token: string | null = null;

  constructor() {
    this.baseURL = API_BASE_URL;
    console.log(`[API Client] Initialized with baseURL: ${this.baseURL}`);
    this.loadToken();
  }

  private loadToken() {
    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem('kinjar-auth-token');
      console.log(`[API] Token loaded: ${this.token ? this.token.substring(0, 20) + '...' : 'none'}`);
      
      // In demo mode, auto-load the demo token if no token exists
      if (DEMO_MODE.enabled && !this.token) {
        this.token = DEMO_MODE.credentials.token;
        localStorage.setItem('kinjar-auth-token', this.token);
      }
    }
  }

  private saveToken(token: string) {
    this.token = token;
    if (typeof window !== 'undefined') {
      localStorage.setItem('kinjar-auth-token', token);
      console.log(`[API] Token saved: ${token.substring(0, 20)}...`);
    }
  }

  private removeToken() {
    this.token = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('kinjar-auth-token');
    }
  }

  private async request(endpoint: string, options: RequestInit = {}) {
    // Ensure baseURL is absolute
    if (!this.baseURL.startsWith('http')) {
      console.error(`[API] Invalid baseURL: ${this.baseURL}. Using fallback.`);
      this.baseURL = 'https://kinjar-api.fly.dev';
    }
    
    const url = `${this.baseURL}${endpoint}`;
    
    // Debug logging for development and production to troubleshoot
    console.log(`[API Request] ${options.method || 'GET'} ${url}`);
    console.log(`[API Request] baseURL: ${this.baseURL}, endpoint: ${endpoint}`);
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
      console.log(`[API Request] Auth token present: ${this.token.substring(0, 20)}...`);
    } else {
      console.log(`[API Request] No auth token available`);
    }

    // Add subdomain context for API calls
    const subdomainInfo = getSubdomainInfo();
    if (subdomainInfo.isSubdomain && subdomainInfo.familySlug) {
      headers['x-tenant-slug'] = subdomainInfo.familySlug;
      
      // Debug logging
      console.log(`[API Request] Setting x-tenant-slug: ${subdomainInfo.familySlug}`);
    }

    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      if (response.status === 401) {
        this.removeToken();
        // Don't automatically redirect - let the auth context handle it
        // This prevents redirect loops
      }
      
      // Enhanced error logging for debugging
      const errorData = await response.json().catch(() => ({ message: 'Request failed' }));
      console.error(`[API Error] ${response.status} ${response.statusText}:`, errorData);
      
      throw new Error(errorData.message || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Authentication
  async login(email: string, password: string): Promise<{ user: AuthUser; token: string }> {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    this.saveToken(response.token);
    return response;
  }

  async register(userData: { name: string; email: string; password: string }): Promise<{ ok: boolean; user?: any; error?: string }> {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });

    return response;
  }

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.removeToken();
    }
  }

  async getCurrentUser(): Promise<AuthUser> {
    return this.request('/auth/me');
  }

  // Family Management
  async createFamily(familyData: CreateFamilyRequest): Promise<{ family: FamilyProfile; user: AuthUser; token: string }> {
    const response = await this.request('/families/create', {
      method: 'POST',
      body: JSON.stringify(familyData),
    });

    this.saveToken(response.token);
    return response;
  }

  async getFamilyBySlug(slug: string): Promise<FamilyProfile> {
    return this.request(`/families/${slug}`);
  }

  async getCurrentFamily(): Promise<FamilyProfile> {
    const subdomainInfo = getSubdomainInfo();
    if (!subdomainInfo.isSubdomain || !subdomainInfo.familySlug) {
      throw new Error('Not in a family context');
    }
    return this.getFamilyBySlug(subdomainInfo.familySlug);
  }

  async updateFamily(familyId: string, updates: Partial<FamilyProfile>): Promise<FamilyProfile> {
    return this.request(`/families/${familyId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  // Member Management
  async inviteMember(invite: InviteMemberRequest): Promise<void> {
    return this.request('/families/invite', {
      method: 'POST',
      body: JSON.stringify(invite),
    });
  }

  async updateMemberRole(familyId: string, memberId: string, role: string): Promise<void> {
    return this.request(`/families/${familyId}/members/${memberId}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
  }

  // Media and Posts
  async uploadMedia(file: File): Promise<UploadResponse> {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${this.baseURL}/media/upload`, {
      method: 'POST',
      headers: {
        'Authorization': this.token ? `Bearer ${this.token}` : '',
        // Remove Content-Type for FormData to set boundary automatically
      },
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Upload failed' }));
      throw new Error(errorData.message || 'Upload failed');
    }

    return response.json();
  }

  async createPost(postData: {
    content: string;
    familyId: string;
    media?: MediaAttachment;
    visibility?: 'family' | 'connections' | 'public';
    tags?: string[];
  }): Promise<FamilyPost> {
    // Transform frontend data to backend format
    const backendData: any = {
      content: postData.content,
      title: postData.content.length > 50 ? postData.content.substring(0, 47) + '...' : postData.content,
      visibility: postData.visibility || 'family'
    };

    // Handle media transformation
    if (postData.media) {
      if (postData.media.url.startsWith('http') && !postData.media.url.includes('blob.vercel-storage.com')) {
        // Only use media_id for actual backend media IDs, not blob URLs
        backendData.media_id = postData.media.url;
      } else {
        // For Vercel Blob URLs, send the URL as media data
        console.log('[API] Sending blob URL as media:', postData.media.url);
        backendData.media = {
          url: postData.media.url,
          type: postData.media.type
        };
      }
    }

    // Note: tags are not yet supported by backend, but include for future compatibility
    if (postData.tags && postData.tags.length > 0) {
      backendData.tags = postData.tags;
    }

    console.log('[API] Sending post data to backend (v2):', backendData);

    const response = await this.request('/api/posts', {
      method: 'POST',
      body: JSON.stringify(backendData),
    });

    // Transform backend response to frontend format
    const backendPost = response.post;
    const frontendPost: FamilyPost = {
      id: backendPost.id,
      familyId: backendPost.tenant_id,
      authorId: backendPost.author_id,
      authorName: 'User', // TODO: Get from user profile
      authorAvatarColor: '#3B82F6', // Default color
      createdAt: backendPost.published_at || backendPost.created_at,
      content: backendPost.content,
      media: postData.media, // Use original media from frontend
      visibility: postData.visibility || 'family',
      status: 'approved', // Backend posts are auto-approved
      reactions: 0, // Default
      comments: [], // Default
      tags: postData.tags || [] // Use original tags from frontend
    };

    return frontendPost;
  }

  async getFamilyPosts(familySlugOrId: string, limit: number = 20, offset: number = 0): Promise<FamilyPost[]> {
    // Try the API endpoint first (uses slug)
    let response;
    try {
      response = await this.request(`/api/families/${familySlugOrId}/posts?limit=${limit}&offset=${offset}`);
    } catch (error) {
      // Fallback to families endpoint (uses ID) 
      response = await this.request(`/families/${familySlugOrId}/posts?limit=${limit}&offset=${offset}`);
    }

    // Transform backend posts to frontend format
    const backendPosts = response.posts || response || [];
    const frontendPosts: FamilyPost[] = backendPosts.map((backendPost: any) => ({
      id: backendPost.id,
      familyId: backendPost.tenant_id || familySlugOrId,
      authorId: backendPost.author_id,
      authorName: backendPost.author_name || 'User', // Use author name if available
      authorAvatarColor: backendPost.author_avatar || '#3B82F6', // Default color
      createdAt: backendPost.published_at || backendPost.created_at,
      content: backendPost.content,
      media: (backendPost.media_filename || backendPost.media_url || backendPost.media_external_url) ? {
        type: backendPost.media_content_type?.startsWith('image/') ? 'image' : 'video',
        url: backendPost.media_url || backendPost.media_external_url || `/api/media/${backendPost.media_id}`,
        alt: backendPost.title
      } : undefined,
      visibility: backendPost.is_public ? 'public' : 'family',
      status: 'approved', // Backend posts are auto-approved
      reactions: 0, // TODO: Get from backend
      comments: [], // TODO: Get from backend
      tags: [] // TODO: Get from backend
    }));

    console.log(`[API] Transformed ${frontendPosts.length} posts from backend`);
    return frontendPosts;
  }

  async addComment(postId: string, content: string): Promise<{ id: string; authorName: string; authorAvatarColor: string; content: string; createdAt: string }> {
    return this.request(`/posts/${postId}/comments`, {
      method: 'POST',
      body: JSON.stringify({ content }),
    });
  }

  async addReaction(postId: string, reaction: string): Promise<void> {
    return this.request(`/posts/${postId}/reactions`, {
      method: 'POST',
      body: JSON.stringify({ reaction }),
    });
  }

  // Root Admin Functions
  async getAllFamilies(): Promise<FamilyProfile[]> {
    return this.request('/admin/families');
  }

  async getAllUsers(): Promise<AuthUser[]> {
    return this.request('/admin/users');
  }

  async createRootAdmin(email: string, password: string, name: string): Promise<AuthUser> {
    return this.request('/admin/create-root', {
      method: 'POST',
      body: JSON.stringify({ email, password, name }),
    });
  }

  // Utility method to check if subdomain is available
  async checkSubdomainAvailable(subdomain: string): Promise<boolean> {
    try {
      await this.request(`/families/check-subdomain/${subdomain}`);
      return true;
    } catch {
      return false;
    }
  }
}

export const api = new KinjarAPI();