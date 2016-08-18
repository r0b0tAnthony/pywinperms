import os, sys
import optparse
import pprint
import json
import re

def get_sec_obj(name, children = None):
    sec_obj = {
        name: {
        },
        '__DEFAULT__':{
            'type': 'all',
            "owner": {"account": {"name": "Domain Admins", "domain": "NYC"}},
            "acl": [],
            'skip': 'true'
        }
    }
    if children != None or len(children) > 1:
        sec_obj[name]['children'] = children

    return sec_obj


def build_sec_obj(relative_path, json_path):
    path_components = relative_path.split(os.sep)
    path_components.reverse()
    pprint.pprint(path_components)
    sec_obj = {}

    for component in path_components:
        sec_obj = get_sec_obj(component, sec_obj)

    with open(json_path, 'w') as f:
        json.dump(sec_obj, f, indent=4, separators=(',', ': '), ensure_ascii=False, sort_keys=True)


if __name__ == '__main__':
    parser_usage = "winperms.py -h start_dir target_dir output_file"
    parser = optparse.OptionParser(usage=parser_usage)
    options, args = parser.parse_args()

    if len(args) < 3:
        raise Exception('You must provide a path from which to construct the security objects and a path to save the json file.')
    else:

        start_path = os.path.abspath(args[0])
        try:
            relative_path = os.path.relpath(os.path.abspath(args[1]), start_path)
        except ValueError:
            raise ValueError('The target_dir must be a path that is relative to the start path!')
        else:
            if relative_path[0] == '.':
                raise ValueError('target_path must be a path to a child under start_path!')
        print relative_path
        json_path = os.path.abspath(args[2])

        build_sec_obj(relative_path, json_path)
