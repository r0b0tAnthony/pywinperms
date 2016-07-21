import os, sys, inspect
import optparse
import pprint
import json
import timeit
import win32api
import win32security
import pywintypes
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
    'DELETE': con.DELETE,
    'READ_CONTROL': con.READ_CONTROL,
    'READ_ATTRIBUTES': con.FILE_READ_ATTRIBUTES,
    'WRITE_ATTRIBUTES': con.FILE_WRITE_ATTRIBUTES,
    'CUSTOM_ALL_ACCESS': (
        con.STANDARD_RIGHTS_REQUIRED | con.SYNCHRONIZE | con.FILE_READ_DATA | con.FILE_LIST_DIRECTORY |
        con.FILE_WRITE_DATA | con.FILE_ADD_FILE | con.FILE_APPEND_DATA | con.FILE_ADD_SUBDIRECTORY |
        con.FILE_CREATE_PIPE_INSTANCE | con.FILE_READ_EA | con.FILE_WRITE_EA | con.FILE_EXECUTE |
        con.FILE_TRAVERSE | con.FILE_DELETE_CHILD | con.FILE_READ_ATTRIBUTES | con.FILE_WRITE_ATTRIBUTES
    ),
    'CUSTOM_MODIFY': (
        con.DELETE | con.READ_CONTROL | con.SYNCHRONIZE | con.FILE_READ_DATA | con.FILE_LIST_DIRECTORY |
        con.FILE_WRITE_DATA | con.FILE_ADD_FILE | con.FILE_APPEND_DATA | con.FILE_ADD_SUBDIRECTORY |
        con.FILE_CREATE_PIPE_INSTANCE | con.FILE_READ_EA | con.FILE_WRITE_EA | con.FILE_EXECUTE |
        con.FILE_TRAVERSE | con.FILE_DELETE_CHILD | con.FILE_READ_ATTRIBUTES | con.FILE_WRITE_ATTRIBUTES
    ),
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

pywinerrors = list()
empty_acl = win32security.ACL()

pp = pprint.PrettyPrinter(indent=4)
#For program level logging, not security obj level logging
loglevel = 0

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
                #First part of returned tuple is the SID
                sid = get_account(account['name'], account['domain'])[0]
                users[user_key.lower()] = sid
        except KeyError:
            raise KeyError('Invalid account object!')
    return users
def get_account(name, domain = ''):
    return win32security.LookupAccountName(domain, name)
def get_ace(ace, users, pyacl_obj):
    #Compute the bits for access_mask
    access_mask = get_mask(ace['mask'])
    #Find cached user SID
    sid = users[str(ace['account']['domain'] + '/' + ace['account']['name']).lower()]
    inherit_mask = 0
    try:
        inherit_mask = get_mask(ace['inherit'])
    except KeyError:
        pass
    #Determine is the ACE is an allow or deny
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
        current_obj['security_info'] = ['DACL_SECURITY_INFO', 'UNPROTECTED_DACL', 'OWNER_SECURITY_INFO']
        try:
            if current_obj['loglevel'] > 1:
                print "Start Processing ACL Cache for %s" % key
        except KeyError:
            pass
        try:
            #Add to accounts list which is used to process out SIDs
            accounts += [ {"account": current_obj['owner']} ]
            #Update the user SID cache
            users.update(get_account_sids(accounts, users))
            current_obj['owner_sid'] = users[str(current_obj['owner']['domain'] + '/' + current_obj['owner']['name']).lower()]
            try:
                if current_obj['loglevel'] > 2:
                    print 'Set SID for Owner'
            except KeyError:
                pass
        except KeyError:
            raise KeyError("'%s' is not a valid security object! Missing owner parameter." % key)

        #Make sure security_obj type is valid
        try:
            if current_obj['type'] not in ['file', 'folder', 'all']:
                raise Exception("Valid type values are file, folder, all. On '%s' security obj" % key)
        except KeyError:
            raise KeyError("'%s' is not a valid security object! Missing type parameter." % key)
        #Initialize a blank PyACL
        dacl = win32security.ACL()
        try:
            #Add to accounts list which is used to process out SIDs
            accounts += current_obj['acl']
            #Update the user SID cache
            users.update(get_account_sids(accounts, users))
            for x in range(len(current_obj['acl'])):
                ace = current_obj['acl'][x]
                dacl = get_ace(ace, users, dacl)

            if not dacl.IsValid():
                raise Exception('DACL is not valid!')
        except KeyError as e:
            raise
        else:
            current_obj['dacl'] = dacl
            try:
                if current_obj['loglevel'] > 2:
                    print 'Set DACL'
            except KeyError:
                pass
        #Initialize a blank PyACL
        sacl =  win32security.ACL()
        try:
            accounts += current_obj['sacl']
            users.update(get_account_sids(accounts, users))
            for x in range(len(current_obj['audit'])):
                ace = current_obj['audit'][x]
                sacl = get_ace(ace, users, sacl)

            if not sacl.IsValid():
                raise Exception('DACL is not valid!')
        except KeyError:
            current_obj['sacl'] = None
            pass
        else:
            current_obj['sacl'] = sacl
            current_obj['security_info'] += ['SACL_SECURITY_INFO', 'UNPROTECTED_SACL']
            try:
                if current_obj['loglevel'] > 2:
                    print 'Set SACL'
            except KeyError:
                pass

        try:
            if current_obj['group_sid']:
                current_obj['security_info'] += ['GROUP_SECURITY_INFO']
        except KeyError:
            current_obj['group_sid'] = None
            pass
        try:
            if current_obj['ignore_inheritance']:
                current_obj['security_info'].remove('UNPROTECTED_DACL')
                current_obj['security_info'] += ['PROTECTED_DACL']
                try:
                    current_obj['security_info'].remove('UNPROTECTED_SACL')
                    current_obj['security_info'] += ['PROTECTED_SACL']
                except Exception:
                    pass
        except KeyError:
            pass

        current_obj['security_info'] = get_mask(current_obj['security_info'])

        if current_obj.has_key('children'):
            #pp.pprint(current_obj['children'])
            get_acl_cache(current_obj['children'], users, acls)
        try:
            if current_obj['loglevel'] > 1:
                print "Finished Processing ACL Cache for %s" % key
        except KeyError:
            pass
    return (users, acls)

def set_security_info(path, security_info, owner = None, group = None, dacl = None, sacl = None):
    try:
        win32security.SetNamedSecurityInfo(path, win32security.SE_FILE_OBJECT, security_info, owner, group, dacl, sacl)
    except pywintypes.error as e:
        set_pywin_errors(path, e)
        pass
def set_pywin_errors(path, error):
    global pywinerrors
    pywinerrors += [{'path': path, 'error': error}]

def print_pywin_errors(errors):
    for x in range(len(errors)):
        if x == 0:
            print 'The following pywintypes.errors occured in set_security_info:'
        print "- Error: '%s' on path %s" % (errors[x]['error'][2], errors[x]['path'])

def set_acl(name, full_path, entry_type, sec_obj):
    children = {}
    #will be False or the sec_obj that matches
    matched = False
    #Setup the default security_info which says we are writing an unprotected DACL and Owner info
    if loglevel > 1:
        print "Full Path: %s" % full_path
    # We can assume that if is less than 2, then the sec_obj is __DEFAULT__
    if len(sec_obj) > 1:
        for needle in sec_obj:
            current_obj = sec_obj[needle]
            try:
                #Check that security obj's type is all or matches the entry's type and that the regex is a match
                if (current_obj['type'] == 'all' or entry_type == current_obj['type']) and re.match(needle, name):
                    #Pass the matched security object's children on sub-containers will receive proper security objs
                    try:
                        if current_obj['loglevel'] > 1:
                            print "Matched %s to %s" % (full_path, needle)
                    except KeyError:
                        pass

                    try:
                        children = current_obj['children']
                    except KeyError:
                        try:
                            if not current_obj['computed']:
                                #If there are no children, take the current obj and set it as __DEFAULT__ so it applies for all sub-containers
                                children = {'__DEFAULT__': copy.copy(current_obj)}
                                #Set to empty ACL
                                children['__DEFAULT__']['dacl'] = empty_acl
                                children['__DEFAULT__']['sacl'] = empty_acl
                                children['__DEFAULT__']['security_info'] = children['__DEFAULT__']['security_info'] ^ (access_bits['PROTECTED_SACL'] | access_bits['PROTECTED_DACL'])
                                children['__DEFAULT__']['computed'] = True
                        except KeyError:
                            children = {'__DEFAULT__': current_obj}
                            pass
                        pass
                    matched = current_obj

                    break
            except TypeError:
                raise
    #If no regex or type matches, apply the __DEFAULT__
    if not matched:
        try:
            matched = sec_obj['__DEFAULT__']
            try:
                #Pass along __DEFAULT__ obj children to sub-containers
                children = sec_obj['__DEFAULT__']['children']
            except KeyError:
                try:
                    if not children['__DEFAULT__']['computed']:
                        #If no children defined, pass along current __DEFAULT__
                        children = {'__DEFAULT__': copy.copy(matched)}
                        children['__DEFAULT__']['dacl'] = empty_acl
                        children['__DEFAULT__']['sacl'] = empty_acl
                        children['__DEFAULT__']['security_info'] = children['__DEFAULT__']['security_info'] ^ (access_bits['PROTECTED_SACL'] | access_bits['PROTECTED_DACL'])
                        children['__DEFAULT__']['computed'] = True
                except KeyError:
                    children = {'__DEFAULT__': sec_obj['__DEFAULT__']}
                    pass
                pass
            else:
                try:
                    if matched['loglevel'] > 1:
                        print "Matched %s to %s" % (full_path, '__DEFAULT__')
                except KeyError:
                    pass
        except KeyError:
            raise
    try:
        if matched['loglevel'] > 1:
            print "Type: %s" % entry_type
            if matched['loglevel'] > 2:
                if matched['loglevel'] > 3:
                    print "Security Object"
                    pp.pprint(sec_obj)
                print "Matched Security Obj"
                pp.pprint(matched)
                print "Security Object Children"
                pp.pprint(children)
    except KeyError:
        pass

    #Skip any matching security obj and don't go into sub-container
    try:
        if matched['skip']:
            try:
                if matched['loglevel'] > 1:
                    print 'Skipping'
            except KeyError:
                pass
            return False
    except KeyError:
        pass

    set_security_info(full_path, matched['security_info'], matched['owner_sid'], matched['group_sid'], matched['dacl'], matched['sacl'])

    try:
        if matched['loglevel'] > 1:
            if matched['loglevel'] > 2:
                print "Security Information Bits"
                pp.pprint(security_info)
            print "set_security_info successful for %s" % full_path
    except KeyError:
        pass

    return children

def set_acls(sec_obj, path):
    try:
        #Use scandir to accelerate going thru files
        for entry in scandir.scandir(path):
            if entry.is_symlink():
                pass
            elif entry.is_dir():
                full_path = os.path.join(path, entry.name)
                children = set_acl(entry.name, full_path, 'folder', sec_obj)
                #Only go into sub-container if not True/security_obj
                if children:
                    set_acls(children, full_path)
                else:
                    print "No Children"
            else:
                full_path = os.path.join(path, entry.name)
                set_acl(entry.name, full_path, 'file', sec_obj)
    except OSError:
        pass
def winperm(root_dir, perm_path):
    print "Starting to Set Permissions in %s" % root_dir
    #Read in perm_path json file
    if loglevel > 1:
        print 'Reading in Security Obj JSON'
    perm_fo = open(perm_path, 'r')
    perm_obj = json.load(perm_fo)
    if loglevel > 3:
        print 'Processed Security Obj JSON'
        pp.pprint(perm_obj)

    users = {}
    acls = {}
    print "Looping"
    '''acl2_cache_times = timeit.Timer(partial(get_acl_cache, perm_obj)).repeat(3, 1000)
    acl2_cache_time = min(acl2_cache_times) / 1000
    print "ACL2 Cache Time: %s" % acl2_cache_time'''
    if loglevel > 1:
        print 'Starting get_acl_cache'
    users, acls = get_acl_cache(perm_obj)
    if loglevel > 1:
        print 'Starting set_acls'

    set_acls(perm_obj, root_dir)
    acl_time = 1000000000000
    N = 3
    for i in range(N):
        print('Benchmarking walks on {0}, repeat {1}/{2}...'.format(
            root_dir, i + 1, N))
        acl_time = min(acl_time,
                                timeit.timeit(partial(set_acls, perm_obj, root_dir), number=1))
    print('took {0:.3f}s'.format(
          acl_time))
    print_pywin_errors(pywinerrors)
    print 'Finished Setting Permissions'

if __name__ == '__main__':
    parser_usage = "winperms.py -h root_dir perms_file"
    parser = optparse.OptionParser(usage=parser_usage)

    parser.add_option('-l', '--log', type='choice', choices=["1","2","3","4","5"], default=1,
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

        try:
            loglevel = options.log
        except Exception:
            pass

        winperm(root_dir,perms_file)
