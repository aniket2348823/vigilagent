# Data Directory

Runtime data, scan results, and configuration files for Antigravity V5.

## 📁 Directory Structure

```
data/
├── config/              # User configuration files
│   ├── keyring.json    # Authentication keyring
│   ├── prd.json        # Product requirements
│   └── user_config.json # User preferences
├── scans/              # Scan results and artifacts
├── stats.json          # System statistics
├── graph.json          # Scan relationship graph
└── README.md           # This file
```

---

## 📄 File Descriptions

### Configuration Files (`config/`)

#### `keyring.json`
**Purpose:** Stores authentication credentials and API keys

**Format:**
```json
{
  "api_keys": {
    "service_name": "api_key_value"
  },
  "tokens": {
    "jwt": "token_value"
  }
}
```

**Security:** 
- ⚠️ **NEVER commit this file to version control**
- Included in `.gitignore`
- Contains sensitive credentials

---

#### `prd.json`
**Purpose:** Product requirements document in JSON format

**Format:**
```json
{
  "version": "1.0.0",
  "requirements": [],
  "features": [],
  "acceptance_criteria": []
}
```

**Usage:** Referenced by planning and specification tools

---

#### `user_config.json`
**Purpose:** User preferences and application settings

**Format:**
```json
{
  "theme": "dark",
  "notifications": true,
  "scan_defaults": {
    "timeout": 30000,
    "max_depth": 5
  }
}
```

**Usage:** Loaded at application startup

---

### Runtime Data Files

#### `stats.json`
**Purpose:** Real-time system statistics and metrics

**Format:**
```json
{
  "total_scans": 0,
  "active_scans": 0,
  "vulnerabilities_found": 0,
  "scans": []
}
```

**Updates:** Modified during scan execution  
**Persistence:** Saved to disk periodically

---

#### `graph.json`
**Purpose:** Scan relationship graph and attack paths

**Format:**
```json
{
  "nodes": [],
  "edges": [],
  "metadata": {}
}
```

**Usage:** 
- Visualizing scan relationships
- Attack path analysis
- Dependency mapping

---

### Scan Results (`scans/`)

Contains individual scan artifacts:
- Scan metadata
- Discovered endpoints
- Vulnerability reports
- Network traffic logs
- Screenshots and evidence

**Structure:**
```
scans/
├── [scan_id]/
│   ├── metadata.json
│   ├── endpoints.json
│   ├── vulnerabilities.json
│   └── evidence/
```

---

## 🔒 Security Considerations

### Sensitive Files
The following files contain sensitive information:
- `config/keyring.json` - API keys and credentials
- `config/user_config.json` - May contain tokens
- `scans/*/` - May contain target information

### Best Practices
1. **Never commit sensitive files** to version control
2. **Use environment variables** for production credentials
3. **Encrypt sensitive data** at rest
4. **Restrict file permissions** (chmod 600 for sensitive files)
5. **Regular cleanup** of old scan data

### .gitignore Entries
Ensure these patterns are in `.gitignore`:
```
data/config/keyring.json
data/config/user_config.json
data/scans/
data/stats.json
data/graph.json
```

---

## 🔄 Data Management

### Backup Strategy
- **Configuration:** Backup before major changes
- **Scan Results:** Archive after 30 days
- **Statistics:** Daily snapshots recommended

### Cleanup Policy
- **Old Scans:** Archive after 30 days, delete after 90 days
- **Temporary Files:** Clean up after scan completion
- **Logs:** Rotate weekly, keep 4 weeks

### Data Migration
When upgrading versions:
1. Backup all data files
2. Run migration scripts if provided
3. Verify data integrity
4. Test with non-production data first

---

## 📊 Data Formats

### JSON Schema Validation
All JSON files should be validated against schemas:
- `config/keyring.json` → `schemas/keyring.schema.json`
- `config/prd.json` → `schemas/prd.schema.json`
- `stats.json` → `schemas/stats.schema.json`

### Data Versioning
Include version field in all JSON files:
```json
{
  "version": "1.0.0",
  "data": {}
}
```

---

## 🛠️ Maintenance

### Regular Tasks
- **Daily:** Check disk space usage
- **Weekly:** Clean up old scan data
- **Monthly:** Backup configuration files
- **Quarterly:** Archive old scans

### Monitoring
Monitor these metrics:
- Disk space usage
- File count in scans/
- stats.json size
- Configuration file integrity

### Troubleshooting

**Issue:** stats.json corrupted
**Solution:** Restore from backup or regenerate from scan data

**Issue:** Disk space full
**Solution:** Clean up old scans in `scans/` directory

**Issue:** Permission denied
**Solution:** Check file permissions (should be 644 for data, 600 for config)

---

## 📝 Development

### Adding New Data Files
1. Document purpose and format
2. Add to `.gitignore` if sensitive
3. Create JSON schema if applicable
4. Update this README
5. Add to backup strategy

### Data Access Patterns
- **Read-heavy:** stats.json, graph.json
- **Write-heavy:** scans/
- **Occasional:** config files

### Performance Considerations
- Use streaming for large files
- Implement caching for frequently accessed data
- Consider database for high-volume scans

---

## 🔗 Related Documentation

- **[Architecture](../docs/ARCHITECTURE.md)** - System architecture
- **[Configuration Guide](../docs/CONFIGURATION.md)** - Configuration details (if exists)
- **[API Documentation](../README.md)** - API endpoints that use this data

---

**Last Updated:** May 24, 2026  
**Data Format Version:** 1.0.0  
**Maintained By:** Antigravity V5 Development Team
