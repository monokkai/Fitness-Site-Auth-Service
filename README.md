# 🔐 Authentication Service

## Overview

The Authentication Service handles user registration, login, logout, and session management for the HandFit application. Built with ASP.NET Core and Entity Framework, it provides secure JWT-based authentication with MySQL database storage.

## 🏗️ Architecture

- **Framework**: ASP.NET Core 8.0 with C#
- **Database**: MySQL with Entity Framework Core
- **Authentication**: JWT tokens + HTTP-only cookies
- **Password Security**: BCrypt hashing

## 🔧 Core Features

### 1. User Registration

- **Email validation** with regex pattern matching
- **Username uniqueness** checking (minimum 3 characters)
- **Password strength** validation (minimum 6 characters)
- **BCrypt password hashing** for security
- **Automatic JWT token** generation

### 2. User Authentication

- **Email/password login** with secure validation
- **JWT token generation** with user claims
- **HTTP-only cookie** session management
- **Last login tracking** for user analytics
- **Cookie-based authentication** with 7-day expiration

### 3. Session Management

- **Secure logout** with cookie clearing
- **Current user retrieval** from JWT claims
- **Session persistence** across requests
- **Authentication state validation**

## 📡 API Endpoints

### Authentication Routes

```
POST /api/auth/register - User registration
POST /api/auth/login    - User login
POST /api/auth/logout   - User logout (requires auth)
GET  /api/auth/me       - Get current user (requires auth)
```

## 🔒 Security Features

- **BCrypt password hashing** with salt
- **JWT token validation** with claims
- **HTTP-only cookies** to prevent XSS
- **CORS configuration** for frontend integration
- **Input validation** and sanitization
- **Secure cookie options** (SameSite, Path, Expires)

## 🗄️ Database Schema

### Users Table

```sql
- Id (int, primary key, auto-increment)
- Username (varchar, unique, not null)
- Email (varchar, unique, not null)
- PasswordHash (varchar, not null)
- IsActive (boolean, default true)
- CreatedAt (datetime, not null)
- UpdatedAt (datetime, not null)
- LastLoginAt (datetime, nullable)
```

## 🚀 Quick Start

### Run Service

```bash
cd deploy
docker-compose up --build
```

## 🔄 Service Integration

- **API Gateway**: Routes authentication requests
- **Users Service**: Shares user data for profiles
- **Training Service**: Validates user sessions
- **Frontend**: Receives JWT tokens and manages sessions

## 📊 Logging & Monitoring

- **Structured logging** with Microsoft.Extensions.Logging
- **Authentication events** tracking
- **Error handling** with detailed messages
- **Security event logging** (failed logins, registrations)
- **Performance monitoring** for database operations

## 🛡️ Error Handling

- **Validation errors** with descriptive messages
- **Duplicate email/username** detection
- **Password strength** enforcement
- **Database connection** error handling
- **JWT token validation** errors
