'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { api, Post, getSubdomainInfo } from '../lib/api';
import { useAuth } from '../lib/auth';

function formatTimestamp(timestamp: string): string {
  if (!timestamp) {
    return '';
  }

  try {
    const date = new Date(timestamp);
    return isNaN(date.getTime()) ? timestamp : date.toLocaleString();
  } catch {
    return timestamp;
  }
}

function MediaPreview({ media }: { media: Post['media'] }) {
  if (!media) {
    return null;
  }

  if (media.type === 'image') {
    return (
      <img
        src={media.url}
        alt={media.alt || 'Post media'}
        className="mt-4 w-full rounded-lg object-cover"
      />
    );
  }

  if (media.type === 'video') {
    return (
      <video
        src={media.url}
        controls
        className="mt-4 w-full rounded-lg"
      />
    );
  }

  return null;
}

export default function FamilyFeed() {
  const { user, loading: authLoading } = useAuth();
  const [posts, setPosts] = useState<Post[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deletingPostId, setDeletingPostId] = useState<string | null>(null);
  const [familySlug, setFamilySlug] = useState<string | null>(null);

  useEffect(() => {
    const info = getSubdomainInfo();
    if (info.isSubdomain && info.familySlug) {
      setFamilySlug(info.familySlug);
    } else {
      setError('Visit your family subdomain to view posts.');
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!familySlug) {
      return;
    }

    let cancelled = false;

    const loadPosts = async () => {
      setLoading(true);
      setError(null);

      try {
        const fetched = await api.getFamilyPosts(familySlug);
        if (!cancelled) {
          setPosts(fetched);
        }
      } catch (err) {
        if (!cancelled) {
          const message = err instanceof Error ? err.message : 'Failed to load posts';
          setError(message);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    loadPosts();

    return () => {
      cancelled = true;
    };
  }, [familySlug]);

  const membershipRole = useMemo(() => {
    if (!user || !familySlug) {
      return null;
    }

    const membership = user.memberships.find((m) => m.familySlug === familySlug);
    return membership?.role ?? null;
  }, [user, familySlug]);

  const canManagePosts = useMemo(() => {
    if (!user) {
      return () => false;
    }

    const isAdmin = membershipRole === 'ADMIN' || membershipRole === 'OWNER' || user.globalRole === 'ROOT_ADMIN';

    return (post: Post) => {
      if (!user) {
        return false;
      }
      return isAdmin || post.authorId === user.id;
    };
  }, [user, membershipRole]);

  const handleDelete = async (postId: string) => {
    if (!familySlug || deletingPostId) {
      return;
    }

    const post = posts.find((item) => item.id === postId);
    if (post && !canManagePosts(post)) {
      setError('You do not have permission to delete this post.');
      return;
    }

    if (typeof window !== 'undefined') {
      const confirmed = window.confirm('Are you sure you want to delete this post?');
      if (!confirmed) {
        return;
      }
    }

    setDeletingPostId(postId);

    try {
      await api.deletePost(postId, familySlug);
      setPosts((prev) => prev.filter((item) => item.id !== postId));
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to delete post';
      setError(message);
    } finally {
      setDeletingPostId(null);
    }
  };

  const showLoading = loading || authLoading;

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-10">
      <div className="max-w-4xl mx-auto px-4 space-y-6">
        <header className="flex flex-col gap-2">
          <h1 className="text-3xl font-bold text-gray-900">Family Posts</h1>
          {familySlug && (
            <p className="text-sm text-gray-600">Showing posts for <span className="font-medium">{familySlug}</span></p>
          )}
        </header>

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}

        {showLoading && (
          <div className="rounded-lg border border-gray-200 bg-white px-4 py-8 text-center text-gray-500 shadow-sm">
            Loading posts...
          </div>
        )}

        {!showLoading && posts.length === 0 && !error && (
          <div className="rounded-lg border border-gray-200 bg-white px-4 py-8 text-center text-gray-500 shadow-sm">
            No posts have been shared yet.
          </div>
        )}

        {!showLoading && posts.map((post) => (
          <article key={post.id} className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-gray-900">{post.authorName}</h2>
                <p className="text-sm text-gray-500">{formatTimestamp(post.createdAt)}</p>
              </div>
              {canManagePosts(post) && (
                <button
                  onClick={() => handleDelete(post.id)}
                  disabled={deletingPostId === post.id}
                  className="rounded-md border border-red-200 bg-red-50 px-3 py-1 text-sm font-medium text-red-600 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {deletingPostId === post.id ? 'Deleting...' : 'Delete'}
                </button>
              )}
            </div>

            <p className="mt-4 whitespace-pre-line text-gray-700">{post.content}</p>

            <MediaPreview media={post.media} />
          </article>
        ))}
      </div>
    </div>
  );
}
