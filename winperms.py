import os, sys, inspect
import optparse
import pprint
import json
import timeit
import win32api
import win32security
import ntsecuritycon as con

pp = pprint.PrettyPrinter(indent=4)
'''
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
'''

def get_cache(sec_obj, users = {}, acls = {}):
    print "Running process_security"
    #pp.pprint(sec_obj)
    for key in sec_obj:
        print key
        current_obj = sec_obj[key]

        if not current_obj.has_key('owner'):
            raise Exception("'%s' is not a valid security object! Missing owner parameter." % key)
        try:
            if current_obj['type'] not in ['file', 'folder', 'all']:
                raise Exception("Valid type values are file, folder, all. On '%s' security obj" % key)
        except KeyError:
                raise KeyError("'%s' is not a valid security object! Missing type parameter." % key)

        try:
            if len(current_obj['acl']) > 0:
                for acl_index  in range(len(current_obj['acl'])):
                    print "ACLs for %s" % key
                    ace = current_obj['acl'][acl_index]
                    try:
                        user_key = ace['account']['domain'] + '/' + ace['account']['name']
                        if not users.has_key(user_key.lower()):
                            sid, domain, account_type = win32security.LookupAccountName(ace['account']['domain'], ace['account']['name'])
                            users[user_key.lower()] = sid
                    except KeyError:
                        raise KeyError('Invalid acl object!')

            else:
                raise Exception('acl paramter list is empty')
        except KeyError:
            raise KeyError("'%s' is not a valid security object! Missing acl parameter." % key)


        if current_obj.has_key('children'):
            print "Has Children"
            pp.pprint(current_obj['children'])
            get_cache(current_obj['children'], users, acls)
    return (users, acls)
def winperm(root_dir, perm_path):
    perm_fo = open(perm_path, 'r')
    perm_obj = json.load(perm_fo)
    #pp.pprint(perm_obj)

    users = {}
    explicit_perms = {}
    print "Looping"
    (sec_users, sec_exp_perms) = get_cache(perm_obj)
    pp.pprint(sec_users)
    print "End Loop"



if __name__ == '__main__':
    parser_usage = "winperms.py -h root_dir perms_file"
    parser = optparse.OptionParser(usage=parser_usage)

    parser.add_option('-l', '--log', type='choice', choices=[1,2,3,4,5], default=1,
                      help='level of log verbosity "%default"')
    options, args = parser.parse_args()

    if len(args) < 2:
        raise Exception('Please provide a root path,root_dir, and json permissions file, perms_file. winperms.py /path/to/root /path/to/perms.json')
    else:
        root_dir = os.path.abspath(args[0])
        if not os.path.isdir(root_dir):
            raise Exception("root_dir, %s, arg is not a directory" % root_dir)

        perms_file = os.path.abspath(args[1])
        if not os.path.isfile(perms_file) or os.path.splitext(perms_file)[1] != '.json':
            raise Exception("perms_file, %s, is either not a file or does not end with json ext." % perms_file)

        winperm(root_dir,perms_file)
