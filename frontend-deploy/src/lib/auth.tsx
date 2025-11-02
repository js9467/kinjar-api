'use client';

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { api, User } from './api';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (userData: {
    username: string;
    email: string;
    password: string;
    family_name?: string;
  }) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isRootAdmin: boolean;
  isFamilyAdmin: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already logged in via cookies
    const checkAuth = async () => {
      try {
        // Try to get current user - this will work if valid session cookie exists
        const currentUser = await api.getCurrentUser();
        setUser(currentUser);
      } catch (error) {
        console.error('Auth check failed:', error);
        // User not logged in or session expired
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  const login = async (username: string, password: string) => {
    try {
      const result = await api.login(username, password);
      setUser(result.user);
    } catch (error) {
      throw error;
    }
  };

  const register = async (userData: {
    username: string;
    email: string;
    password: string;
    family_name?: string;
  }) => {
    try {
      const registerData = {
        ...userData,
        family_name: userData.family_name || userData.username, // Use username as default family name
      };
      const result = await api.register(registerData);
      setUser(result.user);
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    api.logout();
    setUser(null);
  };

  const value: AuthContextType = {
    user,
    loading,
    login,
    register,
    logout,
    isAuthenticated: !!user,
    isRootAdmin: user?.role === 'root_admin',
    isFamilyAdmin: user?.role === 'family_admin' || user?.role === 'root_admin',
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// Higher-order component for protected routes
export function withAuth<T extends {}>(Component: React.ComponentType<T>) {
  return function AuthenticatedComponent(props: T) {
    const { user, loading } = useAuth();

    if (loading) {
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="loading-spinner"></div>
        </div>
      );
    }

    if (!user) {
      if (typeof window !== 'undefined') {
        window.location.href = '/auth/login';
      }
      return null;
    }

    return <Component {...props} />;
  };
}

// Component for role-based access control
export function RequireRole({ 
  role, 
  children, 
  fallback = null 
}: { 
  role: 'root_admin' | 'family_admin' | 'member';
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const { user } = useAuth();

  if (!user) {
    return <>{fallback}</>;
  }

  const hasPermission = () => {
    switch (role) {
      case 'root_admin':
        return user.role === 'root_admin';
      case 'family_admin':
        return user.role === 'family_admin' || user.role === 'root_admin';
      case 'member':
        return true; // All authenticated users are at least members
      default:
        return false;
    }
  };

  return hasPermission() ? <>{children}</> : <>{fallback}</>;
}