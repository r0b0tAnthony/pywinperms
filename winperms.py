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
import re

import warnings
with warnings.catch_warnings(record=True):
    import scandir
#translation to ntsecuritycon constants
access_bits = {
    'READ_DATA': con.FILE_READ_DATA,
    'LIST_DIRECTORY': con.FILE_LIST_DIRECTORY,
    'WRITE_DATA': con.FILE_WRITE_DATA,
    'ADD_FILE': con.FILE_ADD_FILE,
    'APPEND_DATA': con.FILE_APPEND_DATA,
    'ADD_SUBDIRECTORY': con.FILE_ADD_SUBDIRECTORY,
    'CREATE_PIPE_INSTANCE': con.FILE_CREATE_PIPE_INSTANCE,
    'READ_EA': con.FILE_READ_EA,
    'WRITE_EA': con.FILE_WRITE_EA,
    'EXECUTE': con.FILE_EXECUTE,
    'TRAVERSE': con.FILE_TRAVERSE,
    'DELETE_CHILD': con.FILE_DELETE_CHILD,
    'READ_ATTRIBUTES': con.FILE_READ_ATTRIBUTES,
    'WRITE_ATTRIBUTES': con.FILE_WRITE_ATTRIBUTES,
    'ALL_ACCESS': con.FILE_ALL_ACCESS,
    'GENERIC_READ': con.FILE_GENERIC_READ,
    'GENERIC_WRITE': con.FILE_GENERIC_WRITE,
    'GENERIC_EXECUTE': con.FILE_GENERIC_EXECUTE,
    'WRITE_DAC': con.WRITE_DAC,
    'WRITE_OWNER': con.WRITE_OWNER,
    'SYNCHRONIZE': con.SYNCHRONIZE,
    'OBJECT_INHERIT': con.OBJECT_INHERIT_ACE,
    'CONTAINER_INHERIT': con.CONTAINER_INHERIT_ACE,
    'NO_PROPOGATE_INHERIT': con.NO_PROPAGATE_INHERIT_ACE,
    'INHERIT_ONLY': con.INHERIT_ONLY_ACE,
    'VALID_INHERIT_FLAGS': con.VALID_INHERIT_FLAGS,
    'INHERITED_ACE': win32security.INHERITED_ACE,
    'DACL_SECURITY_INFO': win32security.DACL_SECURITY_INFORMATION,
    'SACL_SECURITY_INFO': win32security.SACL_SECURITY_INFORMATION,
    'OWNER_SECURITY_INFO': win32security.OWNER_SECURITY_INFORMATION,
    'GROUP_SECURITY_INFO': win32security.GROUP_SECURITY_INFORMATION,
    'UNPROTECTED_DACL': win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
    'UNPROTECTED_SACL': win32security.UNPROTECTED_SACL_SECURITY_INFORMATION,
    'PROTECTED_DACL': win32security.PROTECTED_DACL_SECURITY_INFORMATION,
    'PROTECTED_SACL': win32security.PROTECTED_SACL_SECURITY_INFORMATION
}

pp = pprint.PrettyPrinter(indent=4)
'''
import win32api
import win32security
import ntsecuritycon as con

filename = os.path.join(os.path.dirname(__con.FILE__), 'benchtree')
jobs, domain, type = win32security.LookupAccountName ("", "JOBS")
admins, domain, type = win32security.LookupAccountName ("", "Administrators")
sd = win32security.GetFileSecurity (filename, win32security.DACL_SECURITY_INFORMATION)
dacl = win32security.ACL ()
dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.con.FILE_GENERIC_READ, admins)
dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, con.OBJECT_INHERIT_ACE, con.con.FILE_ALL_ACCESS, jobs)

if dacl.IsValid():
    print "Valid ACL"
    sd.SetSecurityDescriptorDacl (1, dacl, 0)
    win32security.SetFileSecurity(filename, win32security.DACL_SECURITY_INFORMATION, sd)
else:
    print "Invalid ACL"
'''

def get_mask(keys):
    mask = 0
    for key in keys:
        try:
            mask = mask | access_bits[key]
        except KeyError:
            raise KeyError("The follow access mask key doesn't exist: %s" % key)
        except:
            pass

    return mask

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
def get_ace(ace, users, pyacl_obj):
    access_mask = get_mask(ace['mask'])
    sid = users[str(ace['account']['domain'] + '/' + ace['account']['name']).lower()]
    inherit_mask = 0
    try:
        inherit_mask = get_mask(ace['inherit'])
    except KeyError:
        pass
    if ace['type'] == 'allow':
        pyacl_obj.AddAccessAllowedAceEx(win32security.ACL_REVISION, inherit_mask, access_mask, sid)
    elif ace['type'] == 'deny':
        pyacl_obj.AddAccessDeniedAceEx(win32security.ACL_REVISION, inherit_mask, access_mask, sid)
    else:
        raise ValueError('ACE access type must be allow or deny!')
    return pyacl_obj
def get_acl_cache(sec_obj, users = {}, acls = {}):
    for key in sec_obj:
        current_obj = sec_obj[key]
        accounts = []
        try:
            accounts += [ {"account": current_obj['owner']} ]
            users.update(get_account_sids(accounts, users))
            current_obj['owner_sid'] = users[str(current_obj['owner']['domain'] + '/' + current_obj['owner']['name']).lower()]
        except KeyError:
            pp.pprint(current_obj['owner'])
            raise KeyError("'%s' is not a valid security object! Missing owner parameter." % key)
        try:
            if current_obj['type'] not in ['file', 'folder', 'all']:
                raise Exception("Valid type values are file, folder, all. On '%s' security obj" % key)
        except KeyError:
            raise KeyError("'%s' is not a valid security object! Missing type parameter." % key)
        dacl = win32security.ACL()
        try:
            accounts += current_obj['acl']
            users.update(get_account_sids(accounts, users))
            for x in range(len(current_obj['acl'])):
                ace = current_obj['acl'][x]
                dacl = get_ace(ace, users, dacl)
        except KeyError as e:
            raise
        else:
            current_obj['dacl'] = dacl
        sacl =  win32security.ACL();
        try:
            accounts += current_obj['acl']
            users.update(get_account_sids(accounts, users))
            for x in range(len(current_obj['audit'])):
                ace = current_obj['audit'][x]
                sacl = get_ace(ace, users, sacl)
        except KeyError:
            pass
        current_obj['sacl'] = sacl

        if current_obj.has_key('children'):
            #pp.pprint(current_obj['children'])
            get_acl_cache(current_obj['children'], users, acls)
    return (users, acls)
def set_security_info(path, security_info, owner = None, group = None, dacl = None, sacl = None):
    security_info_mask = get_mask(security_info)
    #sd = win32security.GetFileSecurity (path, win32security.DACL_SECURITY_INFORMATION)
    #sd.SetSecurityDescriptorDacl (1, dacl, 0)
    win32security.SetNamedSecurityInfo(path, win32security.SE_FILE_OBJECT, security_info_mask, owner, group, dacl, sacl)

def set_acl(name, full_path, entry_type, sec_obj):
    children = {}
    matched = False
    security_info = ['DACL_SECURITY_INFO', 'UNPROTECTED_DACL', 'OWNER_SECURITY_INFO']
    if len(sec_obj) > 1:
        for needle in sec_obj:
            current_obj = sec_obj[needle]
            try:
                if (current_obj['type'] == 'all' or entry_type == current_obj['type']) and re.match(needle, name):
                    try:
                        children = current_obj['children']
                    except KeyError:
                        children = {needle: current_obj}
                        pass
                    print needle
                    matched = current_obj
                    break
            except TypeError:
                print "Current_obj"
                pp.pprint(current_obj)
                print "sec_obj"
                pp.pprint(sec_obj)
                raise

    if not matched:
        try:
            matched = sec_obj['__DEFAULT__']
            print '__DEFAULT__'
            try:
                children = sec_obj['__DEFAULT__']['children']
            except KeyError:
                children = {'__DEFAULT__': sec_obj['__DEFAULT__']}
                pass
        except KeyError:
            raise KeyError("Security obj is missing '__DEFAULT__' key.")
    try:
        if matched['skip']:
            print '!!Skipping!!'
            return False
    except KeyError:
        pass

    try:
        if matched['sacl']:
            security_info += ['SACL_SECURITY_INFO', 'UNPROTECTED_SACL']
    except KeyError:
        matched['sacl'] = None
        pass
    try:
        if matched['group_sid']:
            security_info += ['GROUP_SECURITY_INFO']
    except KeyError:
        matched['group_sid'] = None
        pass
    try:
        if matched['ignore_inheritance']:
            security_info.remove('UNPROTECTED_DACL')
            security_info += ['PROTECTED_DACL']
            try:
                security_info.remove('UNPROTECTED_SACL')
                security_info += ['PROTECTED_SACL']
            except Exception:
                pass
    except KeyError:
        pass

    set_security_info(full_path, security_info, matched['owner_sid'], matched['group_sid'], matched['dacl'], matched['sacl'])

    return children

def set_acls(sec_obj, path):
    try:
        for entry in scandir.scandir(path):
            if entry.is_symlink():
                pass
            elif entry.is_dir():
                full_path = os.path.join(path, entry.name)
                print full_path
                children = set_acl(entry.name, full_path, 'folder', sec_obj)
                if children:
                    set_acls(children, full_path)
            else:
                full_path = os.path.join(path, entry.name)
                print full_path
                set_acl(entry.name, full_path, 'file', sec_obj)
    except OSError:
        pass
def winperm(root_dir, perm_path):
    perm_fo = open(perm_path, 'r')
    perm_obj = json.load(perm_fo)
    #pp.pprint(perm_obj)

    users = {}
    acls = {}
    print "Looping"
    '''acl2_cache_times = timeit.Timer(partial(get_acl_cache, perm_obj)).repeat(3, 1000)
    acl2_cache_time = min(acl2_cache_times) / 1000
    print "ACL2 Cache Time: %s" % acl2_cache_time'''
    users, acls = get_acl_cache(perm_obj)
    set_acls(perm_obj, root_dir)
    #pp.pprint(sec_users)




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
