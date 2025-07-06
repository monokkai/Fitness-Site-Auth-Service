# Authentication Service (ASP.NET Core 8.0)

## 🔐 Overview

This is the Authentication Microservice for the **Fitness Microservices Application**, responsible for:

- 🎯 **User Authentication**: Secure login and registration
- 🔑 **JWT Token Management**: Generation and validation of Bearer tokens
- 👤 **User Management**: Basic user operations and profile data
- 🛡️ **Password Security**: Secure password hashing and validation

The service is built using:

- **ASP.NET Core 8.0** — Modern, cross-platform web framework
- **Entity Framework Core** — ORM for database operations
- **JWT Bearer** — For token-based authentication
- **MySQL** — Primary database


### Public Routes

- `POST /api/auth/register` — New user registration request
- `POST /api/auth/login` — User authentication request (both work for frontend part on backend)
- `POST /api/auth/refresh-token` — Refresh JWT token

### Protected Routes

Accessible only with valid JWT Bearer Token:

- `GET /api/auth/profile` — Get user profile
- `PUT /api/auth/profile` — Update user profile
- `POST /api/auth/change-password` — Change user password

> !! All protected routes require `Authorization: Bearer <token>` header

## 👤 User Model

Core user attributes include:

- Unique identifier
- Username
- Email (unique)
- Password hash
- Creation timestamp
- Last login timestamp
- Account status

## 🔒 Security Features

- **Password Hashing**: Secure password storage using modern hashing algorithms
- **JWT Configuration**:
  - Access tokens (short-lived)
  - Refresh tokens (longer validity)
- **Rate Limiting**: Prevents brute force attacks
- **Input Validation**: Thorough request validation

## 🧪 Testing

To run the service locally:

1. Ensure MySQL is running
2. Update connection string in `appsettings.json`
3. Run migrations: `dotnet ef database update`
4. Start the service: `dotnet run`

## 🔐 Authentication Flow

1. Client sends credentials
2. Service validates credentials
3. On success:
   - Generates JWT token
   - Returns token with user info
4. Client uses token for subsequent requests
5. Service validates token on protected endpoints

---

- `nginx-service` --> https://github.com/monokkai/Fitness-Site-Nginx-Service
- `auth-service` --> https://github.com/monokkai/Fitness-Site-Auth-Service 📍 U're here
- `rewards-service` --> https://github.com/monokkai/Fitness-Site-Rewards-Service
- `frontend` --> https://github.com/monokkai/Fitness-Site-Front

---

## 🐳 Docker Database Commands

```bash
docker exec -it auth-db mysql -u root -phandfit_root

docker exec auth-db mysql -uhandfit_user -phandfit_pass -e "USE handfit_db; SELECT UserId, Username, Email, CreatedAt, LastLoginAt, IsActive FROM Users;"
```
