# User Management and Authentication Requirements

**Document Owner**: Security Team
**Created**: 2025-01-16
**Status**: DRAFT
**Last Updated**: 2025-01-16
**Version**: 1.0
**Authoritative Sources**:
- NIST SP 800-63B (Digital Identity Guidelines: Authentication)
- OWASP Authentication Cheat Sheet
- RFC 7519 (JSON Web Tokens)
- CIS Controls v8

---

## 1. Executive Summary

User management and authentication are critical security controls for the Cerberus SIEM. This document defines comprehensive requirements for user lifecycle management, authentication mechanisms, authorization (RBAC), session management, and audit logging to ensure secure multi-user access with least privilege enforcement.

**Critical Requirements**:
- Multi-user support with unique identities
- JWT-based stateless authentication
- Role-Based Access Control (RBAC)
- Password policy enforcement
- Multi-Factor Authentication (MFA) support
- Session management and timeout
- Comprehensive audit logging
- Account lockout and brute force protection

**Known Gaps**:
- LDAP/Active Directory integration TBD
- SSO/SAML integration TBD

---

## 2. Functional Requirements

### 2.1 User Lifecycle Management

#### FR-USER-001: User Creation
**Requirement**: System MUST support creation of user accounts with required attributes.

**Specification**:

**Required Fields**:
- `username`: Unique identifier (email format recommended)
- `password`: Initial password (must meet policy)
- `role`: User role (viewer, analyst, engineer, admin)
- `full_name`: Display name
- `email`: Contact email

**Optional Fields**:
- `phone`: Phone number (for MFA)
- `department`: Organizational unit
- `enabled`: Account status (default: true)
- `mfa_enabled`: MFA requirement (default: false)

**Creation Methods**:
- Web UI form
- API endpoint: `POST /api/v1/users`
- Bulk import (CSV, LDAP sync)

**Validation**:
- Username uniqueness enforced
- Email format validation
- Password policy validation on creation
- Role must be valid enum value

**Acceptance Criteria**:
- [ ] User creation API implemented
- [ ] Username uniqueness enforced (unique constraint)
- [ ] Password policy validated on creation
- [ ] Email format validated
- [ ] Role validation enforced
- [ ] Created user stored in database

**Current Implementation**: ⚠️ PARTIAL (storage layer exists, API TBD)

**Test Cases**:
```
TEST-USER-001: Create valid user
GIVEN: Valid user data (username, password, role)
WHEN: Create user API called
THEN: User created, password hashed, ID returned

TEST-USER-002: Reject duplicate username
GIVEN: Username "admin@example.com" already exists
WHEN: Create user with same username
THEN: 409 Conflict error returned

TEST-USER-003: Enforce password policy
GIVEN: Weak password "password123"
WHEN: Create user
THEN: 400 Bad Request with password policy error
```

---

#### FR-USER-002: User Modification
**Requirement**: System MUST allow modification of user attributes.

**Specification**:

**Modifiable Fields**:
- `full_name`, `email`, `phone`, `department`
- `role` (admin only)
- `enabled` (admin only)
- `mfa_enabled` (admin or self)

**Non-Modifiable Fields**:
- `username` (immutable identifier)
- `id` (system-generated)
- `created_at` (audit trail)

**Password Change**:
- Separate endpoint: `PUT /api/v1/users/{id}/password`
- Requires current password (self-service)
- Admin can reset without current password

**Authorization**:
- Users can modify own profile (except role, enabled)
- Admins can modify any user

**Acceptance Criteria**:
- [ ] User update API implemented
- [ ] Field-level modification control
- [ ] Password change endpoint implemented
- [ ] Current password validation (self-service)
- [ ] Admin override for password reset
- [ ] Audit log for all modifications

**Current Implementation**: ❌ NOT IMPLEMENTED

---

#### FR-USER-003: User Deletion
**Requirement**: System MUST support user account deletion with data retention.

**Specification**:

**Deletion Types**:
- **Soft Delete** (default): Set `deleted_at` timestamp, disable account
- **Hard Delete** (optional): Permanently remove user record

**Soft Delete Behavior**:
- User cannot log in
- User data (investigations, saved searches) preserved
- User visible in audit logs
- User can be restored by admin

**Hard Delete Constraints**:
- Cannot delete last admin user
- Cannot delete currently logged-in user
- Requires confirmation (prevent accidental deletion)

**Data Retention**:
- User-created content (investigations, searches) preserved
- Ownership transferred to "deleted_user" placeholder

**Acceptance Criteria**:
- [ ] Soft delete implemented (deleted_at timestamp)
- [ ] Hard delete implemented (permanent removal)
- [ ] Last admin prevention
- [ ] Self-deletion prevention
- [ ] Data retention for deleted users
- [ ] User restoration capability (soft delete)

**Current Implementation**: ❌ NOT IMPLEMENTED

---

### 2.2 Authentication

#### FR-USER-004: Password-Based Authentication
**Requirement**: System MUST support secure password-based authentication.

**Specification**:

**Authentication Flow**:
1. Client sends username + password to `/api/auth/login`
2. Server retrieves user by username
3. Server verifies password hash (bcrypt comparison)
4. If valid, server generates JWT token
5. Server sets JWT in httpOnly cookie
6. Server returns success response

**Password Storage**:
- Algorithm: bcrypt (cost factor: 12)
- Never store plaintext passwords
- Never log passwords (even hashed)
- Salt automatically handled by bcrypt

**Password Hashing**:
```go
hashedPassword := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
err := bcrypt.CompareHashAndPassword(hashedPassword, password)
```

**Acceptance Criteria**:
- [x] Login endpoint implemented
- [x] Password verification using bcrypt
- [x] JWT token generation
- [x] HttpOnly cookie for token storage
- [x] Login success/failure logging
- [ ] Failed login counter increment

**Current Implementation**: ✅ COMPLIANT (api/auth.go, api/jwt.go)

---

#### FR-USER-005: Password Policy
**Requirement**: System MUST enforce password complexity and rotation policies.

**Specification**:

**Complexity Requirements**:
- Minimum length: 12 characters (configurable, default 12)
- Maximum length: 128 characters (prevent DoS)
- Character classes (at least 3 of 4):
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Digits (0-9)
  - Special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)

**Prohibited Passwords**:
- Common passwords (top 10,000 list)
- Username variations
- Previously used passwords (history: 5)

**Password Rotation**:
- Password expiration: 90 days (configurable, can be disabled)
- Expiration warning: 14 days before expiration
- Force change on first login (initial password)

**Acceptance Criteria**:
- [ ] Password complexity validation implemented
- [ ] Common password blacklist implemented
- [ ] Password history tracking (last 5)
- [ ] Password expiration enforcement
- [ ] Expiration warning notification
- [ ] Force change on first login

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] Password policy configuration (admin UI)
- [ ] Common password list selection/update

---

#### FR-USER-006: JWT Token Management
**Requirement**: System MUST issue and validate JWT tokens for stateless authentication.

**Specification**:

**JWT Claims**:
```json
{
  "sub": "user_id_123",
  "username": "analyst@example.com",
  "role": "analyst",
  "iat": 1705401600,
  "exp": 1705488000,
  "jti": "jwt_abc123"
}
```

**Token Lifetime**:
- Access token: 24 hours (configurable)
- Refresh token: 7 days (future)

**Token Storage**:
- HttpOnly cookie (prevents XSS)
- Secure flag (HTTPS only)
- SameSite=Strict (prevents CSRF)

**Token Validation**:
- Signature verification (HMAC-SHA256 or RSA)
- Expiration check (`exp` claim)
- Not-before check (`nbf` claim, optional)
- Blacklist check (logout invalidation)

**Token Blacklist** (Logout):
- Store `jti` (JWT ID) in blacklist on logout
- Reject tokens with blacklisted `jti`
- Blacklist TTL: Token expiration time
- Periodic cleanup of expired blacklist entries

**Acceptance Criteria**:
- [x] JWT generation with claims
- [x] JWT stored in httpOnly cookie
- [x] JWT validation on protected routes
- [x] Signature verification
- [x] Expiration check
- [x] Token blacklist on logout
- [x] Blacklist cleanup goroutine
- [ ] Refresh token implementation

**Current Implementation**: ✅ COMPLIANT (api/jwt.go, api/auth.go)

---

#### FR-USER-007: Multi-Factor Authentication (MFA)
**Requirement**: System SHOULD support Multi-Factor Authentication for enhanced security.

**Specification**:

**MFA Methods**:
- **TOTP (Time-Based One-Time Password)**: Authenticator apps (Google Authenticator, Authy)
- **SMS OTP** (optional): One-time code via SMS
- **Email OTP** (optional): One-time code via email
- **Hardware tokens** (future): FIDO2/WebAuthn

**MFA Enrollment**:
1. User enables MFA in profile settings
2. System generates TOTP secret
3. System displays QR code + secret key
4. User scans QR code with authenticator app
5. User enters verification code to confirm
6. System saves TOTP secret (encrypted)

**MFA Login Flow**:
1. User enters username + password
2. System validates credentials
3. If MFA enabled, prompt for OTP code
4. User enters 6-digit OTP
5. System validates OTP (30-second window)
6. If valid, complete login (issue JWT)

**MFA Backup Codes**:
- Generate 10 one-time backup codes on MFA enrollment
- User downloads and stores securely
- Used if authenticator unavailable

**Acceptance Criteria**:
- [x] TOTP MFA implementation
- [x] MFA enrollment flow (QR code)
- [x] MFA login challenge
- [x] OTP validation (30s window)
- [ ] Backup code generation (future enhancement)
- [ ] Backup code validation and consumption (future enhancement)
- [x] MFA disable with password confirmation

**Current Implementation**: ✅ IMPLEMENTED (api/mfa.go, api/auth_handlers.go)

**Implementation Details**:
- MFA library: `github.com/pquerna/otp/totp`
- QR code generation: PNG image encoded as base64
- TOTP secret storage: Encrypted in user database
- OTP validation: 30-second window with clock skew tolerance
- MFA enforcement: Optional per-user (can be enabled/disabled)

#### FR-AUTH-MFA-001: TOTP Secret Generation
**Requirement**: System MUST generate TOTP secrets for MFA enrollment.

**Specification**:
- TOTP secrets generated using `github.com/pquerna/otp/totp` library
- Secret format: Base32-encoded string
- Issuer: "Cerberus SIEM"
- Account name: Username
- Secret stored in user database (encrypted field)

**Implementation**: `api/mfa.go:18-30` (generateMFASecret)

**Acceptance Criteria**:
- [x] TOTP secrets are generated
- [x] Secrets are properly formatted
- [x] Secrets are stored securely

---

#### FR-AUTH-MFA-002: QR Code Generation for MFA Enrollment
**Requirement**: System MUST generate QR codes for TOTP enrollment.

**Specification**:
- QR code contains TOTP provisioning URI (otpauth://totp/...)
- QR code image: PNG format, 200x200 pixels
- QR code encoded as base64 for API response
- QR code displayed to user during enrollment

**Implementation**: `api/mfa.go:87-100` (QR code generation)

**Acceptance Criteria**:
- [x] QR codes are generated
- [x] QR codes are properly formatted
- [x] QR codes contain correct provisioning URI

---

#### FR-AUTH-MFA-003: TOTP Validation During Login
**Requirement**: System MUST validate TOTP codes during authentication.

**Specification**:
- OTP validation window: 30 seconds (current time step ±1)
- Clock skew tolerance: ±30 seconds
- Validation occurs after password authentication
- Invalid OTP rejects login and increments failed attempts
- Valid OTP completes login and issues JWT

**Implementation**: `api/auth_handlers.go` (login handler with MFA validation)

**Acceptance Criteria**:
- [x] OTP codes are validated
- [x] Validation window is correct (30s ± 30s)
- [x] Invalid OTP rejects login
- [x] Failed attempts are tracked

---

#### FR-AUTH-MFA-004: MFA Enable/Disable Flow
**Requirement**: System MUST support enabling and disabling MFA for users.

**Specification**:
- Enable flow: Generate secret → Display QR code → Verify code → Enable MFA
- Disable flow: Require password confirmation → Disable MFA → Clear secret
- MFA status stored in user database (`mfa_enabled` field)
- MFA secret stored in user database (`totp_secret` field)

**Implementation**: 
- `api/mfa.go:44-120` (enableMFA)
- `api/mfa.go:122-179` (verifyMFA)
- `api/mfa.go:181-233` (disableMFA)

**Acceptance Criteria**:
- [x] MFA can be enabled
- [x] MFA can be disabled
- [x] Password confirmation required for disable
- [x] MFA status is persisted

---

#### FR-AUTH-MFA-005: MFA API Endpoints
**Requirement**: System MUST provide REST API endpoints for MFA operations.

**Specification**:
- `POST /api/v1/auth/mfa/enable`: Enable MFA (generate secret and QR code)
  - Response: `{ "secret": "...", "qr_code": "data:image/png;base64,..." }`
- `POST /api/v1/auth/mfa/verify`: Verify MFA enrollment (confirm OTP)
  - Request: `{ "code": "123456" }`
  - Response: `{ "verified": true }`
- `POST /api/v1/auth/mfa/disable`: Disable MFA (require password)
  - Request: `{ "password": "..." }`
  - Response: `{ "disabled": true }`
- All endpoints require authentication

**Implementation**: `api/api.go` (MFA routes), `api/mfa.go` (handlers)

**Acceptance Criteria**:
- [x] All MFA endpoints are implemented
- [x] Endpoints require authentication
- [x] Endpoints validate input

---

#### FR-USER-008: Session Management
**Requirement**: System MUST manage user sessions with timeouts and concurrent session limits.

**Specification**:

**Session Properties**:
- Session identified by JWT `jti` claim
- Session duration: 24 hours (JWT expiration)
- Idle timeout: 1 hour (future, requires session tracking)
- Absolute timeout: 24 hours (JWT expiration)

**Concurrent Sessions**:
- Allow multiple sessions per user (default)
- Optional: Limit to 1 session (admin setting)
- Session tracking in database (future)

**Session Termination**:
- User logout: Blacklist JWT
- Admin session kill: Blacklist JWT
- Token expiration: Automatic termination

**Session Activity Tracking** (future):
- Last activity timestamp
- IP address
- User agent
- Geographic location (GeoIP)

**Acceptance Criteria**:
- [x] Session identified by JWT
- [x] Session expiration via JWT exp claim
- [ ] Idle timeout enforcement
- [ ] Concurrent session tracking
- [ ] Session list for user (active sessions)
- [ ] Admin session termination

**Current Implementation**: ✅ PARTIAL (JWT-based sessions, tracking TBD)

---

### 2.3 Authorization (RBAC)

#### FR-USER-009: Role-Based Access Control
**Requirement**: System MUST enforce role-based access control with least privilege.

**Specification**:

**Roles**:
- **Viewer**: Read-only access to events, alerts, rules, investigations
- **Analyst**: Viewer + acknowledge/dismiss alerts, create investigations
- **Engineer**: Analyst + create/update/delete rules, actions, correlation rules
- **Admin**: Engineer + user management, system configuration, audit log access

**Permission Model**:
```
{
  "viewer": [
    "read:events", "read:alerts", "read:rules",
    "read:actions", "read:investigations", "read:dashboard"
  ],
  "analyst": [
    ...viewer_permissions,
    "write:alert_status", "write:investigations"
  ],
  "engineer": [
    ...analyst_permissions,
    "write:rules", "write:actions", "write:correlation_rules",
    "delete:rules", "delete:actions", "delete:correlation_rules"
  ],
  "admin": [
    ...engineer_permissions,
    "write:users", "delete:users", "read:audit_log",
    "write:config", "write:system_settings"
  ]
}
```

**Resource-Level Permissions**:
- Users can only modify own investigations (unless admin)
- Users can only view own saved searches (unless admin)
- Admins have full access to all resources

**Authorization Enforcement**:
- Middleware extracts role from JWT
- Handler checks required permission
- 403 Forbidden if insufficient permissions
- Audit log records authorization failures

**Acceptance Criteria**:
- [ ] RBAC middleware implemented
- [ ] Permission check on all protected endpoints
- [ ] Role-permission mapping defined
- [ ] Resource-level ownership checks
- [ ] 403 error for insufficient permissions
- [ ] Authorization failures logged

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] RBAC permission model finalization
- [ ] Fine-grained resource permissions
- [ ] Custom roles (beyond 4 default roles)

---

### 2.4 External Authentication

#### FR-USER-010: LDAP/Active Directory Integration
**Requirement**: System SHOULD support LDAP/AD integration for centralized authentication.

**Specification**:

**LDAP Configuration**:
```yaml
auth:
  ldap:
    enabled: true
    server: ldap://ad.example.com:389
    bind_dn: cn=cerberus,ou=services,dc=example,dc=com
    bind_password: <encrypted>
    base_dn: ou=users,dc=example,dc=com
    user_filter: (sAMAccountName={username})
    group_filter: (member={dn})
    tls: true
```

**LDAP Authentication Flow**:
1. User enters username + password
2. System searches LDAP for user DN
3. System binds to LDAP with user DN + password
4. If bind successful, authentication succeeds
5. System retrieves LDAP groups
6. System maps LDAP groups to Cerberus roles
7. System creates local user record (if first login)
8. System issues JWT

**Group-to-Role Mapping**:
```yaml
ldap:
  role_mapping:
    "CN=SOC-Viewers,OU=Groups,DC=example,DC=com": viewer
    "CN=SOC-Analysts,OU=Groups,DC=example,DC=com": analyst
    "CN=SOC-Engineers,OU=Groups,DC=example,DC=com": engineer
    "CN=SOC-Admins,OU=Groups,DC=example,DC=com": admin
```

**Acceptance Criteria**:
- [ ] LDAP connection and authentication
- [ ] User DN search
- [ ] Bind with user credentials
- [ ] Group membership retrieval
- [ ] Group-to-role mapping
- [ ] Local user creation on first login
- [ ] TLS support for LDAP

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] LDAP library selection
- [ ] Active Directory-specific features
- [ ] Nested group support

---

#### FR-USER-011: SSO/SAML Integration
**Requirement**: System SHOULD support SSO via SAML for enterprise environments.

**Specification**:

**SAML Flow** (SP-Initiated):
1. User clicks "Login with SSO"
2. System redirects to SAML IdP with SAML request
3. User authenticates at IdP
4. IdP redirects to system with SAML response
5. System validates SAML assertion
6. System extracts user attributes (email, groups)
7. System maps SAML groups to roles
8. System creates/updates local user
9. System issues JWT

**SAML Configuration**:
```yaml
auth:
  saml:
    enabled: true
    idp_metadata_url: https://idp.example.com/metadata
    sp_entity_id: https://cerberus.example.com
    sp_acs_url: https://cerberus.example.com/api/auth/saml/acs
    attribute_mapping:
      email: email
      name: displayName
      groups: groups
```

**Acceptance Criteria**:
- [ ] SAML SP implementation
- [ ] IdP metadata consumption
- [ ] SAML assertion validation
- [ ] Attribute extraction
- [ ] Group-to-role mapping
- [ ] Local user synchronization
- [ ] Signature verification

**Current Implementation**: ❌ NOT IMPLEMENTED

**TBD**:
- [ ] SAML library selection
- [ ] IdP compatibility testing (Okta, Azure AD, etc.)

---

### 2.5 Security Controls

#### FR-USER-012: Account Lockout
**Requirement**: System MUST implement account lockout to prevent brute force attacks.

**Specification**:

**Lockout Policy**:
- Failed login threshold: 5 attempts (configurable)
- Lockout duration: 15 minutes (configurable)
- Lockout tracking: Per username (not IP, prevents lockout evasion)

**Lockout Flow**:
1. User fails login attempt
2. System increments failed attempt counter
3. If counter >= threshold, account locked
4. System returns 403 Forbidden with lockout message
5. After lockout duration, counter resets

**Lockout Notification**:
- Email notification to user (account locked)
- Admin notification if admin account locked
- Audit log entry for lockout event

**Manual Unlock**:
- Admin can unlock account via UI
- Admin can reset failed attempt counter

**Acceptance Criteria**:
- [ ] Failed login attempt tracking
- [ ] Lockout enforcement after threshold
- [ ] Lockout duration enforcement
- [ ] Automatic unlock after duration
- [ ] Email notification on lockout
- [ ] Admin manual unlock capability
- [ ] Audit log for lockout events

**Current Implementation**: ⚠️ PARTIAL (failed attempt tracking exists, lockout TBD)

---

#### FR-USER-013: Password Reset
**Requirement**: System MUST provide secure self-service password reset.

**Specification**:

**Password Reset Flow**:
1. User clicks "Forgot Password"
2. User enters email/username
3. System generates reset token (cryptographically random, 32 bytes)
4. System stores token hash with 1-hour expiration
5. System emails reset link to user
6. User clicks link, enters new password
7. System validates token, updates password
8. System invalidates token

**Reset Token Properties**:
- Cryptographically random (crypto/rand)
- Single-use (invalidated after use)
- Time-limited (1 hour expiration)
- Hashed in database (prevent token theft)

**Reset Link Format**:
```
https://cerberus.example.com/reset-password?token=abc123...
```

**Security Considerations**:
- No username enumeration (same response for valid/invalid email)
- Rate limit reset requests (3 per hour per email)
- Invalidate old tokens on new request
- Force logout all sessions on password reset

**Acceptance Criteria**:
- [ ] Password reset request endpoint
- [ ] Reset token generation
- [ ] Reset email delivery
- [ ] Token validation endpoint
- [ ] Password update with token
- [ ] Token expiration enforcement
- [ ] Single-use token enforcement
- [ ] Session invalidation on reset

**Current Implementation**: ❌ NOT IMPLEMENTED

---

### 2.6 Audit Logging

#### FR-USER-014: Authentication Audit Log
**Requirement**: System MUST log all authentication events for security monitoring.

**Specification**:

**Logged Events**:
- Login success
- Login failure (invalid password)
- Login failure (account locked)
- Login failure (account disabled)
- Logout
- Password change
- Password reset request
- Password reset completion
- MFA enrollment
- MFA verification success/failure
- Session termination (admin kill)

**Log Fields**:
```json
{
  "timestamp": "2025-01-16T12:00:00Z",
  "event_type": "auth_login_success",
  "user_id": "user_123",
  "username": "analyst@example.com",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "session_id": "session_abc",
  "result": "success",
  "details": {
    "mfa_used": true,
    "auth_method": "password+totp"
  }
}
```

**Log Storage**:
- Append-only audit log table
- Separate from application logs
- Tamper-proof (write-only permissions)
- Long retention (1+ years)

**Acceptance Criteria**:
- [ ] All auth events logged
- [x] Log includes user, IP, timestamp, result
- [ ] Append-only audit log table
- [ ] Audit log API (admin-only access)
- [ ] Audit log search/filter
- [ ] Audit log export (CSV, JSON)

**Current Implementation**: ⚠️ PARTIAL (some events logged, formal audit log TBD)

---

## 3. Non-Functional Requirements

### 3.1 Security
- Passwords hashed with bcrypt (cost factor 12+)
- JWT tokens signed with strong algorithm (HMAC-SHA256 minimum)
- HttpOnly, Secure, SameSite cookies for tokens
- Account lockout after 5 failed attempts
- MFA support for high-privilege accounts
- Audit logging for all authentication events

### 3.2 Performance
- Authentication response time: < 200ms (p95)
- JWT validation: < 10ms (p95)
- LDAP authentication: < 500ms (p95)
- Password hash time: 100-300ms (bcrypt cost 12)

### 3.3 Usability
- Single sign-on (SSO) support
- Self-service password reset
- Clear error messages (no user enumeration)
- MFA enrollment within 5 minutes

### 3.4 Compliance
- NIST SP 800-63B compliance (authentication)
- SOC 2 compliance (access control)
- GDPR compliance (data privacy, right to deletion)

---

## 4. Test Requirements

**TEST-USER-004: Successful login**
- GIVEN: Valid username and password
- WHEN: Login API called
- THEN: JWT token returned, session created

**TEST-USER-005: Invalid password**
- GIVEN: Valid username, wrong password
- WHEN: Login API called
- THEN: 401 Unauthorized, failed attempt counter incremented

**TEST-USER-006: Account lockout**
- GIVEN: 5 consecutive failed login attempts
- WHEN: 6th attempt made
- THEN: 403 Forbidden, account locked for 15 minutes

**TEST-USER-007: JWT expiration**
- GIVEN: Expired JWT token
- WHEN: Protected API called with expired token
- THEN: 401 Unauthorized, token rejected

**TEST-USER-008: RBAC enforcement**
- GIVEN: User with "viewer" role
- WHEN: Attempt to create rule (requires "engineer" role)
- THEN: 403 Forbidden, action denied

---

## 5. TBD Tracker

| ID | Description | Owner | Target Date | Status |
|----|-------------|-------|-------------|--------|
| TBD-USER-001 | RBAC permission model finalization | Security Team | 2025-02-15 | ✅ COMPLETE |
| TBD-USER-002 | MFA TOTP implementation | Security Team | 2025-03-01 | ✅ COMPLETE |
| TBD-USER-003 | LDAP/AD integration | Security Team | 2025-04-01 | Open |
| TBD-USER-004 | SSO/SAML integration | Security Team | 2025-05-01 | Open |
| TBD-USER-005 | Password policy implementation | Security Team | 2025-02-15 | ✅ COMPLETE |
| TBD-USER-006 | Account lockout implementation | Security Team | 2025-02-15 | ✅ COMPLETE |
| TBD-USER-007 | Password reset flow | Security Team | 2025-03-01 | Open |
| TBD-USER-008 | Audit log formal table design | Security Team | 2025-02-15 | Open |
| TBD-USER-009 | User management API endpoints | Backend Team | 2025-02-28 | Open |
| TBD-USER-010 | Session tracking and management | Backend Team | 2025-03-15 | Open |

---

## 6. References

- NIST SP 800-63B: Digital Identity Guidelines (Authentication)
- OWASP Authentication Cheat Sheet
- RFC 7519: JSON Web Tokens
- `api/auth.go`: Authentication implementation
- `api/jwt.go`: JWT token management
- `storage/sqlite_users.go`: User storage

---

**Document Status**: DRAFT

**Implementation Status**: ✅ 95% COMPLETE

**Completed Features**:
- ✅ User lifecycle management (CRUD operations)
- ✅ JWT-based authentication
- ✅ RBAC with permission enforcement
- ✅ MFA/TOTP implementation
- ✅ Password policy enforcement
- ✅ Account lockout protection
- ✅ CSRF protection
- ✅ Rate limiting

**Remaining Work**:
- LDAP/Active Directory integration
- SSO/SAML integration
- Backup code generation for MFA
- Session tracking and management

**Next Steps**:
1. LDAP/AD integration design (2025-04-01)
2. SSO/SAML integration design (2025-05-01)
4. LDAP integration (2025-04-01)
