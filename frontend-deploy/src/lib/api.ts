// API client for Kinjar backend integration
const API_BASE_URL = 'https://kinjar-api.fly.dev';

export interface User {
  id: number;
  username: string;
  email: string;
  role: 'root_admin' | 'family_admin' | 'member';
  family_id?: number;
  family_name?: string;
  created_at: string;
  is_active: boolean;
}

export interface Family {
  id: number;
  name: string;
  slug: string;
  description?: string;
  theme_primary?: string;
  theme_secondary?: string;
  is_public: boolean;
  created_at: string;
  admin_id: number;
  member_count: number;
}

export interface Post {
  id: number;
  user_id: number;
  family_id: number;
  content: string;
  media_url?: string;
  media_type?: 'image' | 'video';
  created_at: string;
  username: string;
  family_name: string;
  comment_count: number;
  reaction_count: number;
  user_reaction?: string;
}

export interface Comment {
  id: number;
  post_id: number;
  user_id: number;
  content: string;
  created_at: string;
  username: string;
}

export interface MediaUpload {
  url: string;
  filename: string;
  size: number;
  type: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

class KinjarAPI {
  private token: string | null = null;

  constructor() {
    // Initialize token from localStorage in browser
    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem('kinjar_token');
    }
  }

  private async request(endpoint: string, options: RequestInit = {}): Promise<any> {
    const url = `${API_BASE_URL}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(url, {
      ...options,
      headers: headers as HeadersInit,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Authentication
  async login(username: string, password: string): Promise<AuthResponse> {
    const result: AuthResponse = await this.request('/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });

    this.token = result.token;
    if (typeof window !== 'undefined' && this.token) {
      localStorage.setItem('kinjar_token', this.token);
    }

    return result;
  }

  async register(userData: {
    username: string;
    email: string;
    password: string;
    family_name: string;
  }): Promise<AuthResponse> {
    const result: AuthResponse = await this.request('/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });

    this.token = result.token;
    if (typeof window !== 'undefined' && this.token) {
      localStorage.setItem('kinjar_token', this.token);
    }

    return result;
  }

  async getCurrentUser(): Promise<User> {
    return this.request('/user/me');
  }

  logout(): void {
    this.token = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('kinjar_token');
    }
  }

  // Family Management
  async getFamilies(): Promise<Family[]> {
    return this.request('/families');
  }

  async getFamilyBySlug(slug: string): Promise<Family> {
    return this.request(`/families/${slug}`);
  }

  async createFamily(familyData: {
    name: string;
    description?: string;
    theme_primary?: string;
    theme_secondary?: string;
  }): Promise<Family> {
    return this.request('/families', {
      method: 'POST',
      body: JSON.stringify(familyData),
    });
  }

  async updateFamily(familyId: number, updates: Partial<Family>): Promise<Family> {
    return this.request(`/families/${familyId}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }

  async getFamilyMembers(familyId: number): Promise<User[]> {
    return this.request(`/families/${familyId}/members`);
  }

  async inviteToFamily(familyId: number, email: string, role: string = 'member'): Promise<void> {
    return this.request(`/families/${familyId}/invite`, {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    });
  }

  // Posts and Content
  async getPosts(familyId?: number, limit: number = 20, offset: number = 0): Promise<Post[]> {
    const params = new URLSearchParams({
      limit: limit.toString(),
      offset: offset.toString(),
    });
    
    if (familyId) {
      params.append('family_id', familyId.toString());
    }

    return this.request(`/posts?${params}`);
  }

  async createPost(postData: {
    content: string;
    family_id: number;
    media_url?: string;
    media_type?: 'image' | 'video';
  }): Promise<Post> {
    return this.request('/posts', {
      method: 'POST',
      body: JSON.stringify(postData),
    });
  }

  async deletePost(postId: number): Promise<void> {
    return this.request(`/posts/${postId}`, {
      method: 'DELETE',
    });
  }

  // Comments
  async getComments(postId: number): Promise<Comment[]> {
    return this.request(`/posts/${postId}/comments`);
  }

  async createComment(postId: number, content: string): Promise<Comment> {
    return this.request(`/posts/${postId}/comments`, {
      method: 'POST',
      body: JSON.stringify({ content }),
    });
  }

  async deleteComment(commentId: number): Promise<void> {
    return this.request(`/comments/${commentId}`, {
      method: 'DELETE',
    });
  }

  // Reactions
  async addReaction(postId: number, reaction: string): Promise<void> {
    return this.request(`/posts/${postId}/reactions`, {
      method: 'POST',
      body: JSON.stringify({ reaction }),
    });
  }

  async removeReaction(postId: number): Promise<void> {
    return this.request(`/posts/${postId}/reactions`, {
      method: 'DELETE',
    });
  }

  // Media Upload
  async uploadMedia(file: File): Promise<MediaUpload> {
    const formData = new FormData();
    formData.append('file', file);

    // Don't set Content-Type header for FormData
    const headers: HeadersInit = {};
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE_URL}/upload`, {
      method: 'POST',
      headers,
      body: formData,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(error || `Upload failed: ${response.status}`);
    }

    return response.json();
  }

  // Family Connections
  async getConnectedFamilies(familyId: number): Promise<Family[]> {
    return this.request(`/families/${familyId}/connections`);
  }

  async connectFamilies(familyId: number, targetFamilyId: number): Promise<void> {
    return this.request(`/families/${familyId}/connect`, {
      method: 'POST',
      body: JSON.stringify({ target_family_id: targetFamilyId }),
    });
  }

  async disconnectFamilies(familyId: number, targetFamilyId: number): Promise<void> {
    return this.request(`/families/${familyId}/disconnect`, {
      method: 'POST',
      body: JSON.stringify({ target_family_id: targetFamilyId }),
    });
  }

  // Admin Functions (Root Admin only)
  async getAllFamilies(): Promise<Family[]> {
    return this.request('/admin/families');
  }

  async getAllUsers(): Promise<User[]> {
    return this.request('/admin/users');
  }

  async updateUserRole(userId: number, role: string): Promise<void> {
    return this.request(`/admin/users/${userId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role }),
    });
  }

  async deactivateUser(userId: number): Promise<void> {
    return this.request(`/admin/users/${userId}/deactivate`, {
      method: 'POST',
    });
  }

  // Search
  async searchFamilies(query: string): Promise<Family[]> {
    return this.request(`/search/families?q=${encodeURIComponent(query)}`);
  }

  async searchUsers(query: string, familyId?: number): Promise<User[]> {
    const params = new URLSearchParams({ q: query });
    if (familyId) {
      params.append('family_id', familyId.toString());
    }
    return this.request(`/search/users?${params}`);
  }
}

// Export singleton instance
export const api = new KinjarAPI();
export default api;