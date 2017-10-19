import os, sys
import argparse
import pprint
import json
import re
from collections import OrderedDict
import copy
def get_sec_obj(name, children = None):
    settings = OrderedDict()
    settings['type'] = 'all'
    settings['owner'] = {"account": {"name": "Domain Admins", "domain": "NYC"}}
    settings['acl'] = []
    settings['skip'] = 'true'

    sec_obj = OrderedDict()
    sec_obj[name] = settings
    sec_obj['__DEFAULT__'] = copy.deepcopy(settings)

    if children != None or len(children) > 1:
        sec_obj[name]['children'] = children

    return sec_obj


def build_sec_obj(relative_path):
    path_components = relative_path.split(os.sep)
    path_components.reverse()
    pprint.pprint(path_components)
    sec_obj = OrderedDict()

    for component in path_components:
        sec_obj = get_sec_obj(component, sec_obj)

    return sec_obj


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate Security Object JSON Schemas from Existing Directory Structures')
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
        help='Absolute paths to target directories that are relative to start directory(-s).',
        dest='targetPath',
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

    try:
        relative_path = os.path.relpath(os.path.abspath(args.targetPath), start_path)
    except ValueError:
        raise ValueError('The target_dir must be a path that is relative to the start path!')
    else:
        if relative_path[0] == '.':
            raise ValueError('target_path must be a path to a child under start_path!')
    print relative_path

    secSchema = build_sec_obj(relative_path)
