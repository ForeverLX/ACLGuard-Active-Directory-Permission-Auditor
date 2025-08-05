# ACLGuard Wiki

Welcome to the ACLGuard documentation wiki! This comprehensive guide will help you understand, build, and use ACLGuard effectively.

## 📖 Table of Contents

### Getting Started
- **[Getting Started Guide]( Getting-Started.md)** - Quick setup and first run
- **[Lab Setup Guide]( Lab-Setup-Guide.md)** - Setting up test environments
- **[Beginners Guide]( BEGINNERS_GUIDE.md)** - Perfect for newcomers

### Technical Documentation
- **[Architecture Overview]( ARCHITECTURE.md)** - System design and components
- **[ACL Concepts Explained]( ACL-Concepts-Explained.md)** - Understanding Active Directory permissions
- **[Development Log]( Development-Log,md)** - Project development history

### Advanced Topics
- **[White Paper]( WHITE_PAPER.md)** - Technical deep dive and security analysis

## 🎯 What is ACLGuard?

ACLGuard is a cybersecurity tool designed to analyze Active Directory permissions and assess security risks. It helps security professionals:

- **Identify Overprivileged Accounts**: Find users with excessive permissions
- **Assess Security Risks**: Calculate risk scores based on group memberships
- **Export Findings**: Generate reports in CSV and JSON formats
- **Understand AD Security**: Learn about common permission vulnerabilities

## 🚀 Quick Start

1. **Build the tool**: `make clean && make`
2. **Configure connection**: Set up your AD server credentials
3. **Run analysis**: `./aclguard --export-csv --export-json`
4. **Review results**: Check the generated reports

## 🔧 Key Features

- **Real-time AD Analysis**: Connects to live Active Directory servers
- **Permission Mapping**: Identifies 7 types of high-risk permissions
- **Risk Scoring**: Provides actionable security insights
- **Professional Output**: Clean, enterprise-ready interface
- **Export Capabilities**: Integration with SIEM and reporting tools

## 📊 Use Cases

### Security Teams
- **Threat Hunting**: Identify potential attack vectors
- **Incident Response**: Quick assessment during security incidents
- **Compliance Auditing**: Regular permission reviews
- **Penetration Testing**: Understanding target environments

### Learning & Development
- **Cybersecurity Education**: Understanding AD security concepts
- **Tool Development**: Learning C programming and LDAP integration
- **Portfolio Projects**: Demonstrating technical skills

## 🔒 Security Considerations

- **Educational Purpose**: This tool is for learning and demonstration
- **Not Production Ready**: Missing security hardening features
- **Use Responsibly**: Only test on systems you own or have permission to test

## 📞 Support

- **Documentation**: Check the wiki pages for detailed guides
- **Issues**: Report bugs or request features via GitHub issues
- **Learning**: Use this as a foundation for your own security tools

---

**ACLGuard v1.0** - Empowering cybersecurity professionals through education and practical tools.
