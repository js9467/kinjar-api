import { redirect } from 'next/navigation'

// This page handles family subdomain routing
// When someone visits family.kinjar.com, they get redirected here
export default function FamilyPage() {
  // For now, redirect to main login page
  // TODO: Implement actual family-specific pages
  redirect('/auth/login')
}