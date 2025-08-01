# ACLGuard-Active-Directory-Permission-Auditor
_A lightweight tool written in C to identify risky permissions in Windows Active Directory._

**Why?**
Attackers exploit excessive AD privileges for lateral movement. ACLGuard help defenders spot:
- Password reset vulnerabilities
- WriteDACL misconfigurations
- Other high-risk permissions

**Status:** 
In development for DEFCON 33! 
Code drops August 7-10

**How to Use:**
1. Compile with MinGW: 'gcc src/*.c -l wldap32 -o ACLGuard.exe'
2. Run: './ACLGuard -d yourdomain.local'

**Contribute:** 
Open to any feedback(Improvements,bugs,possible additions/changes)! Open issues or DM me

#ADsecurity #C #DEFCON33
