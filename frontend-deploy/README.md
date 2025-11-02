# Kinjar - Family Social Platform

A comprehensive, modern family social platform built with Next.js 14, designed specifically for families to share memories, connect across generations, and maintain privacy.

## 🌟 Features

### Core Platform
- **Family-Based Social Networking** with subdomain support (`family.kinjar.com`)
- **Mobile-First Photo/Video Sharing** with instant camera integration
- **Real-Time Family Feeds** with posts, comments, and reactions
- **Cross-Family Connections** to share content between connected families
- **Role-Based Permissions** (Root Admin, Family Admin, Member)
- **Progressive Web App** capabilities for native app experience

### Family Features
- Private family spaces with custom themes and branding
- Mobile-optimized upload interface for photos and videos
- Family member management and invitations
- Connected family discovery and content sharing
- Family settings and customization options

### Technical Features
- **Next.js 14** with App Router and TypeScript
- **Tailwind CSS** with custom family theme support
- **Vercel Blob Storage** integration for media uploads
- **JWT Authentication** with role management
- **API Integration** with Flask backend on Fly.io
- **Subdomain Routing** for family-specific experiences

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- npm or yarn
- Vercel account (for Blob storage)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/js9467/kinjar-frontend.git
   cd kinjar-frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   
   Copy `.env.local.example` to `.env.local` and update:
   
   ```env
   # Kinjar API Configuration
   KINJAR_API_URL=https://kinjar-api.fly.dev
   NEXT_PUBLIC_API_URL=https://kinjar-api.fly.dev
   
   # Vercel Blob Storage
   BLOB_READ_WRITE_TOKEN=your-vercel-blob-token-here
   
   # Authentication
   NEXTAUTH_SECRET=your-secure-secret-here
   NEXTAUTH_URL=http://localhost:3000
   
   # App Configuration
   NEXT_PUBLIC_APP_URL=https://kinjar.com
   ```

4. **Start the development server**
   ```bash
   npm run dev
   ```

5. **Open your browser**
   
   Navigate to [http://localhost:3000](http://localhost:3000)

## 🔧 Configuration

### Vercel Blob Setup

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Navigate to Storage > Create > Blob
3. Copy your `BLOB_READ_WRITE_TOKEN`
4. Add it to your `.env.local` file

### Backend Integration

The app integrates with the Kinjar API backend running on Fly.io. The backend provides:
- User authentication and authorization
- Family management and settings
- Media upload and storage
- Post and comment systems
- Family connections and invitations

### Subdomain Configuration

The application supports subdomain-based family routing:
- `kinjar.com` - Main landing page
- `family-name.kinjar.com` - Family homepage
- `admin.kinjar.com` - Administrative interface

## 📁 Project Structure

```
src/
├── app/                          # Next.js App Router pages
│   ├── auth/                     # Authentication pages
│   ├── families/[slug]/          # Dynamic family pages
│   ├── admin/                    # Admin dashboard
│   ├── layout.tsx                # Root layout
│   ├── page.tsx                  # Landing page
│   └── globals.css               # Global styles
├── components/                   # React components
│   ├── FamilyHomePage.tsx        # Main family interface
│   ├── UploadComponent.tsx       # Mobile upload interface
│   ├── PostFeed.tsx              # Post feed with comments
│   └── providers.tsx             # Context providers
├── lib/                          # Utilities and configurations
│   ├── api.ts                    # API client
│   ├── auth.tsx                  # Authentication context
│   └── utils.ts                  # Utility functions
└── types/                        # TypeScript type definitions
```

## 🔒 Security Features

- **Family Isolation**: Each family can only access their own content
- **Secure Authentication**: JWT-based auth with role management
- **File Validation**: Client and server-side file type and size validation
- **CORS Protection**: Properly configured cross-origin request handling
- **Role-Based Access**: Granular permissions for different user types

## 📱 Mobile Experience

- **Touch-Friendly Interface**: Optimized for mobile devices
- **Camera Integration**: Instant photo/video capture and sharing
- **Responsive Design**: Works perfectly on all screen sizes
- **Fast Loading**: Optimized images and lazy loading
- **PWA Support**: Install as native app on mobile devices

## 🚀 Deployment

### Vercel (Recommended)

1. **Connect Repository**: Link your GitHub repository to Vercel
2. **Configure Environment Variables** in Vercel dashboard:
   ```
   KINJAR_API_URL=https://kinjar-api.fly.dev
   BLOB_READ_WRITE_TOKEN=your-vercel-blob-token
   NEXTAUTH_SECRET=your-secure-secret
   NEXT_PUBLIC_APP_URL=https://kinjar.com
   ```
3. **Deploy**: Automatic deployment on git push

### Environment Variables for Production

```env
KINJAR_API_URL=https://kinjar-api.fly.dev
NEXT_PUBLIC_API_URL=https://kinjar-api.fly.dev
BLOB_READ_WRITE_TOKEN=your-vercel-blob-token
NEXTAUTH_SECRET=your-production-secret
NEXTAUTH_URL=https://kinjar.com
NEXT_PUBLIC_APP_URL=https://kinjar.com
NODE_ENV=production
```

## 🛠 Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint
- `npm run type-check` - Run TypeScript type checking

### Technology Stack

- **Framework**: Next.js 14 with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS with custom themes
- **Authentication**: JWT with role-based permissions
- **Storage**: Vercel Blob for media files
- **Backend**: Flask API on Fly.io
- **Deployment**: Vercel with automatic deployments

## 🏗 Architecture

### Frontend Architecture
- **Component-Based**: Modular React components
- **Context API**: Global state management for auth
- **API Client**: Centralized backend communication
- **Route Protection**: Authentication-based routing
- **Theme System**: Dynamic family branding

### Backend Integration
- **RESTful API**: Clean API endpoints for all operations
- **File Upload**: Direct integration with Vercel Blob
- **Real-Time**: Optimistic updates and refresh patterns
- **Error Handling**: Comprehensive error management
- **Loading States**: Smooth user experience

## 📞 Support

For technical support or questions about family access:
- Backend API: `kinjar-api.fly.dev`
- Frontend Issues: Create GitHub issue
- Family Access: Contact your family administrator

## 🔧 Troubleshooting

### Common Issues

**Upload fails or slow**
- Check BLOB_READ_WRITE_TOKEN is correct
- Verify file size under 150MB
- Ensure stable internet connection

**Authentication not working**
- Verify KINJAR_API_URL points to correct backend
- Check that backend is running on Fly.io
- Confirm JWT secret matches backend

**Development server won't start**
- Check Node.js version (18+ required)
- Clear node_modules and reinstall: `rm -rf node_modules && npm install`
- Verify all environment variables are set

**Family pages not loading**
- Ensure family exists in backend database
- Check API endpoints are accessible
- Verify subdomain routing configuration

## 📝 License

Private family platform - not for public distribution.

---

Built with ❤️ for families who want to stay connected privately and securely.