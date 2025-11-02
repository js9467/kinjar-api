'use client';

import React, { useState, useRef } from 'react';
import { api, MediaUpload } from '../lib/api';

interface UploadComponentProps {
  familyId: number;
  onUploadSuccess?: (post: any) => void;
  onUploadError?: (error: string) => void;
  className?: string;
}

export default function UploadComponent({
  familyId,
  onUploadSuccess,
  onUploadError,
  className = ''
}: UploadComponentProps) {
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [postContent, setPostContent] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (files: FileList | null) => {
    if (!files || files.length === 0) return;
    
    const file = files[0];
    validateAndUpload(file);
  };

  const validateAndUpload = async (file: File) => {
    // Validate file type
    const validTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'video/mov'];
    if (!validTypes.includes(file.type)) {
      onUploadError?.('Please select a valid image or video file (JPEG, PNG, GIF, WebP, MP4, WebM, MOV)');
      return;
    }

    // Validate file size (150MB limit)
    const maxSize = 150 * 1024 * 1024; // 150MB in bytes
    if (file.size > maxSize) {
      onUploadError?.('File size must be less than 150MB');
      return;
    }

    setUploading(true);
    setUploadProgress(0);

    try {
      // Upload media to Vercel Blob
      const mediaUpload: MediaUpload = await api.uploadMedia(file);
      setUploadProgress(100);

      // Create post with media
      const mediaType = file.type.startsWith('image/') ? 'image' : 'video';
      const post = await api.createPost({
        content: postContent || `Shared a ${mediaType}`,
        family_id: familyId,
        media_url: mediaUpload.url,
        media_type: mediaType
      });

      onUploadSuccess?.(post);
      setPostContent('');
      
    } catch (error) {
      console.error('Upload failed:', error);
      onUploadError?.(error instanceof Error ? error.message : 'Upload failed');
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    handleFileSelect(e.dataTransfer.files);
  };

  const triggerFileSelect = () => {
    fileInputRef.current?.click();
  };

  const handleCameraCapture = () => {
    // For mobile camera capture
    if (fileInputRef.current) {
      fileInputRef.current.setAttribute('capture', 'environment');
      fileInputRef.current.click();
    }
  };

  return (
    <div className={`bg-white rounded-lg shadow-sm border p-4 ${className}`}>
      {/* Post content input */}
      <div className="mb-4">
        <textarea
          value={postContent}
          onChange={(e) => setPostContent(e.target.value)}
          placeholder="What's happening in your family?"
          className="w-full p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          rows={3}
        />
      </div>

      {/* Upload area */}
      <div
        className={`upload-dropzone p-6 text-center cursor-pointer transition-colors ${
          dragOver ? 'dragover' : ''
        } ${uploading ? 'pointer-events-none opacity-50' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={triggerFileSelect}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*,video/*"
          onChange={(e) => handleFileSelect(e.target.files)}
          className="hidden"
        />

        {uploading ? (
          <div className="space-y-4">
            <div className="loading-spinner mx-auto"></div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${uploadProgress}%` }}
              ></div>
            </div>
            <p className="text-gray-600">Uploading... {uploadProgress}%</p>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="text-gray-400">
              <svg className="w-12 h-12 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
            </div>
            <div>
              <p className="text-gray-700 font-medium">Drop photos or videos here</p>
              <p className="text-gray-500 text-sm">or click to browse (max 150MB)</p>
            </div>
          </div>
        )}
      </div>

      {/* Mobile action buttons */}
      <div className="flex gap-3 mt-4 md:hidden">
        <button
          onClick={handleCameraCapture}
          disabled={uploading}
          className="flex-1 bg-blue-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center gap-2"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 13a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          Camera
        </button>
        <button
          onClick={triggerFileSelect}
          disabled={uploading}
          className="flex-1 bg-gray-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-gray-700 disabled:opacity-50 flex items-center justify-center gap-2"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
          </svg>
          Gallery
        </button>
      </div>

      {/* Post without media button */}
      {postContent.trim() && !uploading && (
        <div className="mt-4 flex justify-end">
          <button
            onClick={async () => {
              if (!postContent.trim()) return;
              
              setUploading(true);
              try {
                const post = await api.createPost({
                  content: postContent,
                  family_id: familyId
                });
                onUploadSuccess?.(post);
                setPostContent('');
              } catch (error) {
                onUploadError?.(error instanceof Error ? error.message : 'Failed to create post');
              } finally {
                setUploading(false);
              }
            }}
            disabled={uploading}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50"
          >
            Post
          </button>
        </div>
      )}
    </div>
  );
}