import os
import sys
import argparse
import json
import re
from collections import OrderedDict
import copy

version = '1.5'

def merge(a, b, path=None):
    "merges b into a"
    if path is None: path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass # same leaf value
            else:
                raise Exception('Conflict at %s' % '.'.join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a

def getDefaultSecObj():
    settings = getSecObjSettings()
    settings['__DEFAULT__'] = copy.deepcopy(settings)
    return settings


def getSecObjSettings():
    settings = OrderedDict()
    settings['type'] = 'all'
    settings['owner'] = {"account": {"name": "Domain Admins", "domain": "NYC"}}
    settings['acl'] = []
    settings['skip'] = 'true'

    return settings


def get_sec_obj(name, children=None):
    sec_obj = {name: getDefaultSecObj()}

    if len(children) >= 1:
        sec_obj[name]['children'] = children

    return sec_obj


def build_sec_obj(relative_path):
    path_components = relative_path.split(os.sep)
    path_components.reverse()
    sec_obj = OrderedDict()

    for component in path_components:
        sec_obj = get_sec_obj(component, sec_obj)

    return sec_obj


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate Security Object JSON Schemas from Existing Directory Structures',
        version=version)
    parser.add_argument(
        '-s',
        '--start',
        help='Start/root directory from which relative path structures will be computed.',
        dest='startPath',
        required=True
    )
    parser.add_argument(
        '-t',
        '--target',
        nargs='+',
        help='Absolute paths to target directories that are relative to start directory(-s).',
        dest='targetPaths',
        required=True
    )
    parser.add_argument(
        '-o',
        '--output',
        help='Path to write generated json schema. Must end in .json.',
        dest='jsonOutput',
        type=argparse.FileType('w'),
        required=True
    )
    args = parser.parse_args()

    start_path = os.path.abspath(args.startPath)
    schema_dict = {'__DEFAULT__': getSecObjSettings()}
    for targetPath in args.targetPaths:
        try:
            relative_path = os.path.relpath(
                os.path.abspath(targetPath), start_path)
        except ValueError:
            raise ValueError(
                'The target_dir must be a path that is relative to the start path!')
        else:
            if relative_path[0] == '.':
                raise ValueError(
                    'target_path must be a path to a child under start_path!')
        merge(schema_dict, build_sec_obj(relative_path))

    json.dump(schema_dict, args.jsonOutput, indent=4, separators=(',', ': '))
    print "Wrote Schema to %s" % os.path.abspath(args.jsonOutput.name)
    args.jsonOutput.close()
