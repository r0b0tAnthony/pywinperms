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
Pywinperms works using the pywin32 library, specifically win32security, and scandir, which is faster on file objects than 2.7.x regular os.walk(). Pywinperms reads in a JSON file that hierarchically represents folder and/or files you want permissions applied to, known as security objects. It can dynamically match names using regex the current file or folder's name, not the entire path.

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
            "acl": [],
            "ignore_inheritance": "true"
          }
    }
