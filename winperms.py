import os, sys, inspect
import optparse
import pprint
import json
import timeit
import win32api
import win32security
import ntsecuritycon as con
from functools import partial
import copy

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
def get_account_sids(accounts, users = {}):
    for x in range(len(accounts)):
        
        account = accounts[x]['account']
        try:
            user_key = account['domain'] + '/' + account['name']
            if not users.has_key(user_key.lower()):
                sid = get_account(account['name'], account['domain'])[0]
                users[user_key.lower()] = sid
        except KeyError:
            raise KeyError('Invalid account object!')
    return users
def get_account(name, domain = ''):
    return win32security.LookupAccountName(domain, name)

def get_user_cache(sec_obj, users = {}, acls = {}):
    for key in sec_obj:
        current_obj = sec_obj[key]
        effective_acl = {}
        accounts = []
        try:
            accounts += [ {"account": current_obj['owner']} ]
            users.update(get_account_sids(accounts, users))
            
        except KeyError:
            pp.pprint(current_obj['owner'])
            raise KeyError("'%s' is not a valid security object! Missing owner parameter." % key)

        try:
            if len(current_obj['acl']) > 0:
                accounts += current_obj['acl']
                users.update(get_account_sids(accounts, users))
                
            else:
                raise Exception('acl paramter list is empty')
        except KeyError:
            raise KeyError("'%s' is not a valid security object! Missing acl parameter." % key)
        try:
            accounts += current_obj['audit']
        except KeyError:
            pass
        
        users.update(get_account_sids(accounts, users))
        
        if current_obj.has_key('children'):
            #pp.pprint(current_obj['children'])
            get_user_cache(current_obj['children'], users, acls)
    return (users, acls)
    
def get_acl_cache(sec_obj, users = {}, acls = {}, inherit = {}):
    for key in sec_obj:
        current_inherit = copy.deepcopy(inherit)
        current_obj = sec_obj[key]
        try:
            if current_obj['type'] not in ['file', 'folder', 'all']:
                raise Exception("Valid type values are file, folder, all. On '%s' security obj" % key)
        except KeyError:
            raise KeyError("'%s' is not a valid security object! Missing type parameter." % key)
        print "Inherited: %s" % key
        pp.pprint(current_inherit)
        try:
            #pp.pprint(current_obj['acl'])
            for x in range(len(current_obj['acl'])):
                ace = current_obj['acl'][x]
                try:
                    if ace['inherit'] == 'true':
                        if not current_inherit.has_key('acl'):
                            current_inherit['acl'] = []
                        current_inherit['acl'] += [ace]
                except KeyError:
                    pass
        except KeyError:
            raise KeyError("'%s' is not a valid security object! Missing acl parameter." % key)
        '''try:
            
        except KeyError:
            pass'''
        
        if current_obj.has_key('children'):
            #pp.pprint(current_obj['children'])
            get_acl_cache(current_obj['children'], users, acls, current_inherit)
    return (users, acls)
def winperm(root_dir, perm_path):
    perm_fo = open(perm_path, 'r')
    perm_obj = json.load(perm_fo)
    #pp.pprint(perm_obj)

    users = {}
    explicit_perms = {}
    print "Looping"
    user_cache_times = timeit.Timer(partial(get_user_cache, perm_obj)).repeat(3, 1000)
    user_cache_time = min(user_cache_times) / 1000
    print "User Cache Time: %s" % user_cache_time
    get_acl_cache(perm_obj)
    #pp.pprint(sec_users)
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
