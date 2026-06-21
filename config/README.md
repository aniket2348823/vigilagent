# Configuration Files

Project configuration files for build tools, linters, and testing frameworks.

## 📁 Configuration Files

### Frontend Build Configuration

#### `vite.config.js`
**Purpose:** Vite build tool configuration

**Key Settings:**
- Build output directory
- Dev server configuration
- Plugin configuration
- Alias paths

**Usage:** Automatically loaded by Vite during `npm run dev` or `npm run build`

---

#### `tailwind.config.js`
**Purpose:** TailwindCSS utility-first CSS framework configuration

**Key Settings:**
- Content paths for purging
- Theme customization
- Custom utilities
- Plugin configuration

**Usage:** Automatically loaded by PostCSS during build

---

#### `postcss.config.js`
**Purpose:** PostCSS CSS processing configuration

**Key Settings:**
- TailwindCSS plugin
- Autoprefixer
- CSS optimization

**Usage:** Automatically loaded during CSS processing

---

### Code Quality Configuration

#### `.eslintrc.cjs`
**Purpose:** ESLint JavaScript/TypeScript linting configuration

**Key Settings:**
- Parser options
- Extends configurations
- Rules
- Environment settings

**Usage:**
```bash
# Run linter
npm run lint

# Fix auto-fixable issues
npm run lint:fix
```

---

### Testing Configuration

#### `pytest.ini`
**Purpose:** Pytest Python testing framework configuration

**Key Settings:**
- Test paths
- Test file patterns
- Markers
- Coverage settings

**Usage:**
```bash
# Run tests
pytest

# Run with coverage
pytest --cov=backend
```

---

### Code Analysis Configuration

#### `sonar-project.properties`
**Purpose:** SonarQube code quality analysis configuration

**Key Settings:**
- Project key
- Source directories
- Exclusions
- Coverage paths

**Usage:** Automatically loaded by SonarQube scanner

---

## 🔧 Configuration Management

### Modifying Configurations

**Before modifying:**
1. Backup current configuration
2. Test changes in development
3. Document changes
4. Update this README if needed

**After modifying:**
1. Test build process
2. Run linters/tests
3. Commit changes with descriptive message

---

### Configuration Hierarchy

Some tools support configuration hierarchy:

**ESLint:**
- Project root: `config/.eslintrc.cjs`
- Directory-specific: `.eslintrc.js` in subdirectories
- File-specific: Inline comments

**Pytest:**
- Project root: `config/pytest.ini`
- Directory-specific: `conftest.py` files

---

## 📝 Adding New Configuration Files

When adding new configuration files:

1. **Place in config/ directory**
2. **Update this README**
3. **Document purpose and key settings**
4. **Add usage examples**
5. **Update .gitignore if needed**

---

## 🔗 Configuration File Locations

### Root Directory
- `.env` - Environment variables (not in config/ for security)
- `.env.example` - Environment template
- `.gitignore` - Git ignore patterns
- `.gitattributes` - Git attributes

### Config Directory
- `config/.eslintrc.cjs` - ESLint configuration
- `config/pytest.ini` - Pytest configuration
- `config/vite.config.js` - Vite configuration
- `config/tailwind.config.js` - Tailwind configuration
- `config/postcss.config.js` - PostCSS configuration
- `config/sonar-project.properties` - SonarQube configuration

### Package Configuration
- `package.json` - NPM package configuration (root)
- `requirements.txt` - Python dependencies (root)

---

## 🛠️ Tool-Specific Documentation

### Vite
- **Docs:** https://vitejs.dev/config/
- **Config File:** `vite.config.js`
- **CLI:** `vite --help`

### TailwindCSS
- **Docs:** https://tailwindcss.com/docs/configuration
- **Config File:** `tailwind.config.js`
- **CLI:** `npx tailwindcss --help`

### ESLint
- **Docs:** https://eslint.org/docs/user-guide/configuring/
- **Config File:** `.eslintrc.cjs`
- **CLI:** `eslint --help`

### Pytest
- **Docs:** https://docs.pytest.org/en/stable/reference/customize.html
- **Config File:** `pytest.ini`
- **CLI:** `pytest --help`

### SonarQube
- **Docs:** https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/
- **Config File:** `sonar-project.properties`
- **CLI:** `sonar-scanner --help`

---

## 🔒 Security Considerations

### Sensitive Configuration
- **Never commit secrets** to configuration files
- **Use environment variables** for sensitive data
- **Use .env files** for local development (gitignored)
- **Use .env.example** as template without secrets

### Configuration Files to Gitignore
- `.env` - Local environment variables
- `*.local.js` - Local overrides
- `*-local.*` - Local configuration files

---

## 📊 Configuration Validation

### Validate Configurations

**ESLint:**
```bash
npx eslint --print-config config/.eslintrc.cjs
```

**Vite:**
```bash
npx vite --config config/vite.config.js --mode development
```

**Pytest:**
```bash
pytest --collect-only
```

---

## 🔄 Configuration Updates

### When to Update

**Vite:**
- When adding new plugins
- When changing build output
- When modifying dev server settings

**TailwindCSS:**
- When adding custom colors/fonts
- When extending theme
- When adding plugins

**ESLint:**
- When adding new rules
- When changing code style
- When adding plugins

**Pytest:**
- When adding new test directories
- When adding markers
- When changing test patterns

---

## 🔗 Related Documentation

- **[Architecture](../docs/ARCHITECTURE.md)** - System architecture
- **[Development Guide](../docs/DEVELOPMENT.md)** - Development setup (if exists)
- **[Contributing](../CONTRIBUTING.md)** - Contributing guidelines (if exists)

---

**Last Updated:** May 24, 2026  
**Configuration Files:** 6  
**Maintained By:** Vigilagent V5 Development Team
