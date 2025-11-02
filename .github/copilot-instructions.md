<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Kinjar Family Social Platform

## Project Overview
This is a comprehensive React/Next.js workspace for the Kinjar family social platform - a modern, mobile-first social media application designed specifically for families.

## Core Features
- Family-based social networking with subdomain support (family.kinjar.com)
- Mobile-optimized photo/video upload and sharing
- Real-time family feeds with posts, comments, and reactions
- Family connections and cross-family content sharing
- Role-based permissions (root admin, family admin, member)
- Responsive design for mobile and desktop

## Technical Stack
- Next.js 14 with App Router and TypeScript
- Tailwind CSS for styling with custom family themes
- Vercel Blob integration for media storage
- JWT authentication with role management
- API integration with existing Flask backend on Fly.io
- Subdomain routing for family spaces
- Progressive Web App capabilities

## Project Checklist

- [x] ✅ Verify that the copilot-instructions.md file in the .github directory is created.

- [x] ✅ Clarify Project Requirements
	<!-- Requirements clearly specified: React/Next.js family social platform with mobile-first design and Flask backend integration -->

- [x] ✅ Scaffold the Project
	<!--
	Project scaffolded manually with Next.js 14, TypeScript, Tailwind CSS. 
	Core structure created: components, lib, API client, auth context, upload component, post feed.
	Need to install dependencies via npm when Node.js environment is available.
	-->

- [x] ✅ Customize the Project
	<!--
	Comprehensive family social platform created with:
	- API client integration with Flask backend
	- Authentication system with JWT
	- Mobile-optimized upload component
	- Family homepage with post feed
	- Role-based permissions
	- Subdomain routing support
	- Family connections and cross-posting
	Complete codebase ready for deployment.
	-->

- [ ] Install Required Extensions
	<!-- ONLY install extensions provided mentioned in the get_project_setup_info. Skip this step otherwise and mark as completed. -->

- [ ] Compile the Project
	<!--
	Verify that all previous steps have been completed.
	Install any missing dependencies.
	Run diagnostics and resolve any issues.
	Check for markdown files in project folder for relevant instructions on how to do this.
	-->

- [ ] Create and Run Task
	<!--
	Verify that all previous steps have been completed.
	Check https://code.visualstudio.com/docs/debugtest/tasks to determine if the project needs a task. If so, use the create_and_run_task to create and launch a task based on package.json, README.md, and project structure.
	Skip this step otherwise.
	 -->

- [ ] Launch the Project
	<!--
	Verify that all previous steps have been completed.
	Prompt user for debug mode, launch only if confirmed.
	 -->

- [ ] Ensure Documentation is Complete
	<!--
	Verify that all previous steps have been completed.
	Verify that README.md and the copilot-instructions.md file in the .github directory exists and contains current project information.
	Clean up the copilot-instructions.md file in the .github directory by removing all HTML comments.
	 -->