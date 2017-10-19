#PYWINPERMS

## What is pywinperms?
Pywinperms is a python 2.7.x command line program that can hierarchically and dynamically apply Windows DACL and Ownership.

## Prerequisites
* 2.7.x Python Installed
* Scandir Installed with C Compiled version
* pywin32 Installed
* Run As A User With Access to Set Permissions and Ownership

## How Does pywinperms work?

### Overview
Pywinperms works using the pywin32 library, specifically win32security, and scandir, which is faster on file objects than 2.7.x regular os.walk(). Pywinperms reads in a JSON file that hierarchically represents folder and/or files you want permissions applied to, known as security objects. It can dynamically match security objects using regex against the current file or folder's name, not the entire path.

### The Security Object JSON
Security Objects follow the JSON standard for syntax.

#### Example
    {
      "[regex]_\\d+matcher":
          "type": "all",
          "owner": {"account": {"name": "Administrators", "domain": "NYC"}},
          "acl": [
              {"account": {"name": "Producers", "domain": "NYC"}, "mask": ["GENRIC_READ", "CUSTOM_MODIFY"], "type": "allow"},
              {"account": {"name": "everybody", "domain": "NYC"}, "mask": ["CUSTOM_ALL_ACCESS"], "type": "deny", "inherit": ["OBJECT_INHERIT", "NO_PROPOGATE_INHERIT"]}
          ]
          "children": {
            "needle": {
              "type": "file",
              "owner": {"account": {"name": "Administrators", "domain": "NYC"}},
              "acl": []
            },
            "__DEFAULT__": {
              "type": "all",
              "owner": {"account": {"name": "Administrators", "domain": "NYC"}},
              "acl": [],
              "skip": "true",
              "loglevel": 2
            }
          },
          "__DEFAULT__": {
            "type": "all",
            "owner": {"account": {"name": "Administrators", "domain": "NYC"}},
            "acl": [
                {"account": {"name": "staff", "domain": "NYC"}, "mask": ["CUSTOM_MODIFY"], "type": "allow", "inherit": ["OBJECT_INHERIT", "CONTAINER_INHERIT"]}
            ],
            "ignore_inheritance": "true"
            children: {
                "__DEFAULT__": {
                  "type": "all",
                  "owner": {"account": {"name": "Administrators", "domain": "NYC"}},
                  "acl": []
                }
            }
          }
    }

#### Security Object Properties:
**Matched/needle:** a regex needle that is matched against a file and/or folder. *There is also a special `__DEFAULT__` that is REQUIRED to be at each hierarchical level. It is defaulted to when no match is found.* **REQUIRED**

**type:** valid values are either `file`, `folder`, or `all`. *`__DEFAULT__` must be a type of all.* **REQUIRED**

**owner:** An account object setting either a user or group as the owner of this object. **REQUIRED**

`{"account": {"name": "Account Name", "domain": "NYC"}}`

**acl:** A list/array of ACE objects. **REQUIRED**

`{"account": {"name": "Account Name", "domain": "NYC"}, "mask": ["GENERIC_READ", "GENERIC_WRITE"], "type": "allow", "inherit": ["OBJECT_INHERIT", "CONTAINER_INHERIT", "NO_PROPOGATE_INHERIT"]}`

**children:** An object/dictionary of security objects.

**skip:** A boolean string that will skip any matching objects and their children.

**ignore_inheritance:** A boolean string that cause inheritance from the parents to be ignored by protecting the ACL.

**loglevel:** An integer 1 thru 5 that set's logging on a per security object basis.

#### ACE Object Properties
**account:** A dictionary with a `name` and `domain` key. **REQUIRED**

**mask:** A list of access flags. **REQUIRED**

Valid flags: `READ_DATA`, `LIST_DIRECTORY`, `WRITE_DATA`, `ADD_FILE`, `APPEND_DATA`, `ADD_SUBDIRECTORY`, `CREATE_PIPE_INSTANCE`, `READ_EA`, `WRITE_EA`, `EXECUTE`, `TRAVERSE`, `DELETE_CHILD`, `DELETE`, `READ_CONTROL`, `READ_ATTRIBUTES`, `WRITE_ATTRIBUTES`, `CUSTOM_ALL_ACCESS`, `CUSTOM_MODIFY`, `GENERIC_READ`, `GENERIC_WRITE`, `GENERIC_EXECUTE`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`

**type:** Either `allow` or `deny`. **REQUIRED**

**inherit:** A list of inherit flags.

Valid flags: `OBJECT_INHERIT`, `CONTAINER_INHERIT`, `NO_PROPOGATE_INHERIT`, `INHERIT_ONLY`

### Command line

#### Example
`python winperms.py C:\path\to\folder C:\path\to\security_obj.json`

#### Parameters
**{1}:** An absolute path to the containing folder you want permissions applied to. i.e. `C:\foo\bar` will not apply permissions to `bar` but the contents inside `bar`

**{2}:** An absolute path to the JSON file containing security objects.

#### flags
**-h** Help flag

**-l** Set the global logging level. `1` thru `5`, where one is minimal logging. Does *not* affect security object level logging.

## Security Object JSON Schema Generator
pywinperms relies on a Security Object Schema that is based on JSON. To facilitate the creation of the JSON Schema, you can use `secobj_hierarchy_construct.py` to generate the JSON with existing folder structures.

```
usage: secobj_hierarchy_constructor.py [-h] [-v] -s STARTPATH -t TARGETPATHS
                                       [TARGETPATHS ...] -o JSONOUTPUT

Generate Security Object JSON Schemas from Existing Directory Structures

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -s STARTPATH, --start STARTPATH
                        Start/root directory from which relative path
                        structures will be computed.
  -t TARGETPATHS [TARGETPATHS ...], --target TARGETPATHS [TARGETPATHS ...]
                        Absolute paths to target directories that are relative
                        to start directory(-s).
  -o JSONOUTPUT, --output JSONOUTPUT
                        Path to write generated json schema. Must end in
                        .json.
```
