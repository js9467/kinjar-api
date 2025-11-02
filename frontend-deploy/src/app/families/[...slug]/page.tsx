import { redirect } from 'next/navigation'

// This handles all family subdomain routes like family.kinjar.com/posts
export default function FamilyDynamicPage({ params }: { params: { slug: string[] } }) {
  // For now, redirect to main login page
  // TODO: Implement actual family-specific routing
  redirect('/auth/login')
}