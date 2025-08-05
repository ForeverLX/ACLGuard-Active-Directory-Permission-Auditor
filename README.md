# ACLGuard

**ACLGuard** is a C-based cybersecurity tool that connects to Active Directory, analyzes user permissions, and provides risk assessment based on group memberships and privileges.

⚠️ This is a learning/demo project — not production-ready.

---

## 🚀 Current Version: v1.0

ACLGuard v1.0 is now complete with full permission analysis and risk assessment capabilities!

### Key Features:
- **LDAP/AD Connection**: Connects to Active Directory servers
- **Permission Analysis**: Analyzes 7 types of high-risk permissions
- **Risk Scoring**: Calculates risk scores (0-100) with color-coded levels
- **Export Capabilities**: Exports results to CSV and JSON formats
- **Professional Output**: Clean, informative display with security summary

### Quick Start:
```bash
# Build
make clean && make

# Configure (create config_ad.env)
export ACLGUARD_LDAP_URI="ldap://your-ad-server:389"
export ACLGUARD_BIND_DN="Administrator@domain.local"
export ACLGUARD_BIND_PW="password"
export ACLGUARD_BASE_DN="dc=domain,dc=local"

# Run
source config_ad.env && ./aclguard

# Export results
./aclguard --export-csv --export-json
```

---

## 📚 Documentation

- **[Complete Documentation](README_v1.0.md)** - Full v1.0 documentation
- **[Wiki](wiki/)** - Detailed guides and architecture documentation

---

## 🎯 Project Goals

This project demonstrates:
- **Cybersecurity Knowledge**: Understanding of AD permissions and attack vectors
- **C Programming Skills**: System programming, LDAP integration, data structures
- **Tool Development**: Complete end-to-end security tool creation
- **Professional Quality**: Clean code, documentation, and user interface

Perfect for showcasing on GitHub, LinkedIn, and in cybersecurity job applications!

---

## 🔒 Security Note

This tool is for educational purposes only. It uses unencrypted LDAP connections and is not production-ready.

---

**ACLGuard v1.0** - A cybersecurity learning project by ForeverLX