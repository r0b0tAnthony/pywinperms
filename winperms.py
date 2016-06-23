import os, sys
import win32api
import win32security
import ntsecuritycon as con

filename = os.path.join(os.path.dirname(__file__), 'benchtree')
jobs, domain, type = win32security.LookupAccountName ("", "JOBS")
admins, domain, type = win32security.LookupAccountName ("", "Administrators")
sd = win32security.GetFileSecurity (filename, win32security.DACL_SECURITY_INFORMATION)
dacl = win32security.ACL ()
dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_GENERIC_READ, admins)
dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, con.OBJECT_INHERIT_ACE, con.FILE_ALL_ACCESS, jobs)

if dacl.IsValid():
    print "Valid ACL"
    sd.SetSecurityDescriptorDacl (1, dacl, 0)
    win32security.SetFileSecurity(filename, win32security.DACL_SECURITY_INFORMATION, sd)
else:
    print "Invalid ACL"
