export interface SubdomainInfo {
  isSubdomain: boolean;
  subdomain?: string;
  familySlug?: string;
  isRootDomain: boolean;
}

export interface MembershipInfo {
  familyId: string;
  familySlug: string;
  familyName: string;
  role: 'OWNER' | 'ADMIN' | 'MEMBER';
  joinedAt: string | null;
}

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  avatarColor?: string;
  globalRole: 'ROOT_ADMIN' | 'FAMILY_ADMIN' | 'MEMBER';
  memberships: MembershipInfo[];
  createdAt?: string | null;
  lastLoginAt?: string | null;
}

export type User = AuthUser;

export interface CreateFamilyRequest {
  name: string;
  slug?: string;
  description?: string;
}

export interface FamilyProfile {
  id: string;
  slug: string;
  name: string;
  description?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface InviteMemberRequest {
  email: string;
  role?: 'MEMBER' | 'ADMIN' | 'OWNER';
  message?: string;
}

export interface MediaAttachment {
  id?: string;
  url: string;
  type: 'image' | 'video';
  alt?: string;
  thumbnailUrl?: string;
}

export interface PostComment {
  id: string;
  authorId: string;
  authorName?: string;
  authorAvatarColor?: string;
  content: string;
  createdAt: string;
}

export interface FamilyPost {
  id: string;
  familyId: string;
  authorId: string;
  authorName: string;
  authorAvatarColor?: string;
  createdAt: string;
  content: string;
  media?: MediaAttachment;
  visibility: 'family' | 'connections' | 'public';
  status: string;
  reactions: number;
  comments: PostComment[];
  tags: string[];
}
