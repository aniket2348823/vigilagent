# API Changelog - Vigilagent

Complete version history and changes to the Vigilagent API.

---

## Table of Contents

1. [Version 5.0](#version-50-current)
2. [Version 4.x](#version-4x-legacy)
3. [Migration Guides](#migration-guides)
4. [Breaking Changes](#breaking-changes)
5. [Deprecation Notices](#deprecation-notices)

---

## Version 5.0 (Current)

**Release Date**: May 26, 2026  
**Status**: Stable  
**API Version**: `v1`

### Major Changes

#### 1. Security Enhancements

**CSRF Protection** (NEW)
- All state-changing endpoints now require CSRF tokens
- Token generation: `POST /api/csrf/token`
- Token validation: Automatic via middleware

```bash
# Get CSRF token
curl -X POST http://localhost:8000/api/csrf/token \
  -H "Content-Type: application/json"

# Use token in request
curl -X POST http://localhost:8000/api/scans \
  -H "X-CSRF-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

**Rate Limiting** (NEW)
- All endpoints now have rate limits
- Default: 100 requests per minute per IP
- Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

```bash
# Response headers
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1653580800
```

**URL Validation** (ENHANCED)
- SSRF protection on all URL inputs
- Blocks cloud metadata endpoints
- Blocks internal network ranges
- Validates URL format and protocol

#### 2. Browser Infrastructure

**Context Management** (NEW)
- Browser contexts now pooled and reused
- Automatic cleanup of idle contexts
- Memory monitoring and limits

**Endpoints**:
```bash
# Get context statistics
GET /api/browser/stats

# Force context cleanup
POST /api/browser/cleanup
```

**Response**:
```json
{
  "active_contexts": 3,
  "pooled_contexts": 2,
  "memory_usage_mb": 450,
  "memory_threshold_mb": 500
}
```

#### 3. Agent Enhancements

**New Agents**:
- **Zeta Agent**: Browser context lifecycle management
- **Prism Agent**: HTTP security header analysis
- **Chi Agent**: Deceptive UI and event prevention

**Enhanced Agents**:
- **Alpha Agent**: Improved SPA detection
- **Beta Agent**: 4 new CSRF bypass techniques
- **Gamma Agent**: Network traffic analysis
- **Sigma Agent**: Framework detection (React, Vue, Angular)
- **Delta Agent**: Hybrid browser engine coordination

#### 4. Forensics & Session Management

**Forensic Encryption** (NEW)
- All forensic data now encrypted at rest
- Fernet encryption (AES-128-CBC + HMAC)
- PBKDF2 key derivation

**Session Sanitization** (NEW)
- Automatic sanitization of sensitive data
- Masks tokens, passwords, API keys
- Regex-based pattern detection

**Endpoints**:
```bash
# Get forensic data (decrypted)
GET /api/scans/{scan_id}/forensics

# Get session data (sanitized)
GET /api/scans/{scan_id}/session
```

#### 5. API Improvements

**WebSocket Events** (ENHANCED)
- Real-time scan progress updates
- Finding notifications
- Agent status updates

**Event Types**:
```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8000/ws');

// Listen for events
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  switch(data.type) {
    case 'scan.started':
      // Scan started
      break;
    case 'scan.progress':
      // Progress update
      break;
    case 'finding.discovered':
      // New finding
      break;
    case 'scan.completed':
      // Scan completed
      break;
  }
};
```

**Pagination** (NEW)
- All list endpoints now support pagination
- Query parameters: `page`, `per_page`, `sort`, `order`

```bash
# Get paginated scans
GET /api/scans?page=1&per_page=20&sort=created_at&order=desc
```

**Response**:
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 150,
    "pages": 8
  }
}
```

### New Endpoints

#### Security

```bash
# CSRF Token Management
POST   /api/csrf/token          # Generate CSRF token
DELETE /api/csrf/token          # Invalidate CSRF token

# Rate Limit Status
GET    /api/rate-limit/status   # Check rate limit status
```

#### Browser Management

```bash
# Browser Statistics
GET    /api/browser/stats       # Get browser statistics
POST   /api/browser/cleanup     # Force context cleanup

# Context Management
GET    /api/browser/contexts    # List active contexts
DELETE /api/browser/contexts/{id} # Close specific context
```

#### Forensics

```bash
# Forensic Data
GET    /api/scans/{id}/forensics           # Get forensic data
GET    /api/scans/{id}/forensics/screenshots # Get screenshots
GET    /api/scans/{id}/forensics/network    # Get network logs
```

#### Session Management

```bash
# Session Data
GET    /api/scans/{id}/session             # Get session data
GET    /api/scans/{id}/session/cookies     # Get cookies
GET    /api/scans/{id}/session/storage     # Get storage data
```

### Modified Endpoints

#### Scans

**POST /api/scans** (MODIFIED)
- Added CSRF token requirement
- Added URL validation
- Added rate limiting

**Before**:
```json
{
  "target_url": "https://example.com"
}
```

**After**:
```json
{
  "target_url": "https://example.com",
  "config": {
    "depth": 3,
    "timeout": 300,
    "agents": ["alpha", "beta", "gamma"]
  }
}
```

**GET /api/scans** (MODIFIED)
- Added pagination support
- Added filtering options
- Added sorting options

**Query Parameters**:
```
page: int (default: 1)
per_page: int (default: 20, max: 100)
status: string (running|completed|failed)
sort: string (created_at|updated_at|status)
order: string (asc|desc)
```

#### Reports

**POST /api/reports/{scan_id}/generate** (MODIFIED)
- Added rate limiting
- Added format options
- Added customization options

**Request**:
```json
{
  "format": "pdf|json|sarif",
  "include_screenshots": true,
  "include_payloads": true,
  "severity_filter": ["critical", "high"]
}
```

### Deprecated Endpoints

The following endpoints are deprecated and will be removed in v6.0:

```bash
# Deprecated (use /api/scans instead)
GET    /api/scan/list
POST   /api/scan/create
DELETE /api/scan/delete/{id}

# Deprecated (use /api/reports instead)
GET    /api/report/generate/{id}
```

### Response Format Changes

**Error Responses** (STANDARDIZED)

**Before**:
```json
{
  "error": "Invalid URL"
}
```

**After**:
```json
{
  "error": {
    "code": "INVALID_URL",
    "message": "Invalid URL format",
    "details": {
      "url": "not-a-url",
      "reason": "Missing protocol"
    }
  }
}
```

**Success Responses** (STANDARDIZED)

**Before**:
```json
{
  "scan_id": "123",
  "status": "running"
}
```

**After**:
```json
{
  "data": {
    "scan_id": "123",
    "status": "running",
    "created_at": "2026-05-26T10:00:00Z"
  },
  "meta": {
    "version": "5.0",
    "timestamp": "2026-05-26T10:00:00Z"
  }
}
```

---

## Version 4.x (Legacy)

### Version 4.2

**Release Date**: March 15, 2026  
**Status**: Deprecated

**Changes**:
- Added Delta agent
- Improved browser automation
- Bug fixes

### Version 4.1

**Release Date**: January 10, 2026  
**Status**: Deprecated

**Changes**:
- Added Kappa and Omega agents
- Improved reporting
- Performance optimizations

### Version 4.0

**Release Date**: November 1, 2025  
**Status**: Deprecated

**Changes**:
- Complete rewrite
- New agent architecture
- WebSocket support

---

## Migration Guides

### Migrating from 4.x to 5.0

#### 1. Update CSRF Token Handling

**Before (4.x)**:
```javascript
// No CSRF token required
fetch('/api/scans', {
  method: 'POST',
  body: JSON.stringify({target_url: 'https://example.com'})
});
```

**After (5.0)**:
```javascript
// Get CSRF token first
const tokenResponse = await fetch('/api/csrf/token', {
  method: 'POST'
});
const {token} = await tokenResponse.json();

// Use token in request
fetch('/api/scans', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': token
  },
  body: JSON.stringify({target_url: 'https://example.com'})
});
```

#### 2. Handle Rate Limiting

**Before (4.x)**:
```javascript
// No rate limiting
for (let i = 0; i < 1000; i++) {
  await fetch('/api/scans');
}
```

**After (5.0)**:
```javascript
// Check rate limit headers
const response = await fetch('/api/scans');
const remaining = response.headers.get('X-RateLimit-Remaining');

if (remaining < 10) {
  // Slow down or wait
  const reset = response.headers.get('X-RateLimit-Reset');
  await sleep(reset - Date.now());
}
```

#### 3. Update Pagination

**Before (4.x)**:
```javascript
// Get all scans (no pagination)
const response = await fetch('/api/scans');
const scans = await response.json();
```

**After (5.0)**:
```javascript
// Use pagination
const response = await fetch('/api/scans?page=1&per_page=20');
const {data, pagination} = await response.json();

// Handle pagination
for (let page = 1; page <= pagination.pages; page++) {
  const response = await fetch(`/api/scans?page=${page}&per_page=20`);
  const {data} = await response.json();
  // Process data
}
```

#### 4. Update Error Handling

**Before (4.x)**:
```javascript
try {
  const response = await fetch('/api/scans');
  const data = await response.json();
} catch (error) {
  console.error(error.message);
}
```

**After (5.0)**:
```javascript
try {
  const response = await fetch('/api/scans');
  
  if (!response.ok) {
    const {error} = await response.json();
    console.error(`${error.code}: ${error.message}`);
    console.error('Details:', error.details);
  }
  
  const {data} = await response.json();
} catch (error) {
  console.error('Network error:', error);
}
```

#### 5. Update WebSocket Events

**Before (4.x)**:
```javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // Handle event
};
```

**After (5.0)**:
```javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  // Check event type
  switch(data.type) {
    case 'scan.started':
      handleScanStarted(data.payload);
      break;
    case 'scan.progress':
      handleScanProgress(data.payload);
      break;
    case 'finding.discovered':
      handleFinding(data.payload);
      break;
  }
};
```

---

## Breaking Changes

### Version 5.0

1. **CSRF Token Required**
   - All POST, PUT, DELETE requests require CSRF token
   - **Impact**: All clients must be updated
   - **Migration**: Add CSRF token to requests

2. **Rate Limiting Enforced**
   - All endpoints have rate limits
   - **Impact**: High-volume clients may be throttled
   - **Migration**: Implement rate limit handling

3. **Response Format Changed**
   - All responses now wrapped in `{data: ..., meta: ...}`
   - **Impact**: Response parsing must be updated
   - **Migration**: Update response handlers

4. **Pagination Required**
   - List endpoints no longer return all results
   - **Impact**: Clients must implement pagination
   - **Migration**: Add pagination logic

5. **Error Format Changed**
   - Errors now structured as `{error: {code, message, details}}`
   - **Impact**: Error handling must be updated
   - **Migration**: Update error handlers

---

## Deprecation Notices

### Deprecated in 5.0 (Removal in 6.0)

1. **Legacy Scan Endpoints**
   ```bash
   GET    /api/scan/list          # Use /api/scans
   POST   /api/scan/create        # Use /api/scans
   DELETE /api/scan/delete/{id}   # Use /api/scans/{id}
   ```

2. **Legacy Report Endpoints**
   ```bash
   GET    /api/report/generate/{id}  # Use /api/reports/{id}/generate
   ```

3. **Unversioned Endpoints**
   - All endpoints without `/v1/` prefix
   - **Migration**: Add `/v1/` to all API calls

### Deprecated in 4.0 (Removed in 5.0)

1. **Synchronous Scan API**
   ```bash
   POST /api/scan/sync  # Removed, use async API
   ```

2. **XML Response Format**
   ```bash
   GET /api/scans?format=xml  # Removed, use JSON
   ```

---

## API Versioning

### Current Version

**Version**: `v1`  
**Base URL**: `http://localhost:8000/api/v1`

### Version Support Policy

- **Current version (v1)**: Fully supported
- **Previous version (v0)**: Deprecated, removed in 6.0
- **Support duration**: 12 months after deprecation

### Version Header

All requests should include API version:

```bash
curl -H "Accept: application/vnd.vigilagent.v1+json" \
  http://localhost:8000/api/scans
```

---

## Rate Limits

### Default Limits

| Endpoint Type | Limit | Window |
|--------------|-------|--------|
| Read (GET) | 100/min | 60s |
| Write (POST/PUT) | 50/min | 60s |
| Delete (DELETE) | 20/min | 60s |
| Reports | 10/min | 60s |

### Rate Limit Headers

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1653580800
```

### Rate Limit Errors

**Status Code**: `429 Too Many Requests`

**Response**:
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded",
    "details": {
      "limit": 100,
      "window": 60,
      "reset_at": "2026-05-26T10:01:00Z"
    }
  }
}
```

---

## Authentication

### API Key Authentication

**Header**: `X-API-Key`

```bash
curl -H "X-API-Key: your-api-key" \
  http://localhost:8000/api/scans
```

### JWT Authentication

**Header**: `Authorization: Bearer <token>`

```bash
# Get token
curl -X POST http://localhost:8000/api/auth/login \
  -d '{"username": "user", "password": "pass"}'

# Use token
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/scans
```

---

## Status Codes

### Success Codes

- `200 OK` - Request successful
- `201 Created` - Resource created
- `202 Accepted` - Request accepted (async)
- `204 No Content` - Successful deletion

### Client Error Codes

- `400 Bad Request` - Invalid request
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation error
- `429 Too Many Requests` - Rate limit exceeded

### Server Error Codes

- `500 Internal Server Error` - Server error
- `502 Bad Gateway` - Upstream error
- `503 Service Unavailable` - Service down
- `504 Gateway Timeout` - Timeout

---

## Support

For API questions:
- Documentation: https://docs.vigilagent.com
- Support: api-support@vigilagent.com
- GitHub Issues: https://github.com/vigilagent/issues

---

## References

- [API Reference](API_REFERENCE.md)
- [Configuration](CONFIGURATION.md)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md)

---

**Last Updated**: May 26, 2026  
**Current Version**: 5.0  
**API Version**: v1
