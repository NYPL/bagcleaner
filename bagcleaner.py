import argparse
import os
import hashlib
import json
import re
import sys
import logging
from collections import defaultdict
import bagit



LOGGER = logging.getLogger(__name__)

DEFAULT_RULES = {
    "Thumbs.db": {
        "regex": "[Tt]humbs\\.db$",
        "match": False
    },
    "DS_Store": {
        "regex": "\\.DS_Store$",
        "match": False
    },
    "Appledouble": {
        "regex": "\\._.+$",
        "match": False
    },
    "Icon": {
        "regex": "(I|i)con(|\r)$",
        "match": False
    }
}


def validate_rules(rules_dict):
    """ Check that each rule entry only has a regex field and a match field."""
    for rule in rules_dict.values():
        assert len(rule) == 2
        assert isinstance(rule["regex"], str), "Rule for {0} does not have regex string".format(rule)
        assert isinstance(rule["match"], bool), "Rule for {0} does not have match boolean".format(rule)
    logging.info("Format of rules JSON validated")


class CleanerBag(bagit.Bag):

    def __init__(self, bag_path, rules_dict):
        """Extend Bag class with rules for unwanted files"""
        super().__init__(bag_path)
        logging.info("Loaded the following bag: {0}"
                     .format(bag_path))
        self.rules = rules_dict
        logging.info("Loaded the following rules: {0}"
                     .format(list(self.rules.keys())))
        self._find_unwanted()


    def _find_unwanted(self):
        """Sort files in payload and payload manifests and call comparison"""
        self.unwanted = {}
        self.unwanted_count = 0
        self.unknown = {}
        self.unknown_count = 0

        files_on_fs = set(self.payload_files())
        files_in_manifest = set(self.payload_entries().keys())

        path_sets = [["In manifests, in data/",
                      list(files_in_manifest & files_on_fs)],
                     ["In manifests, not in data/",
                      list(files_in_manifest - files_on_fs)],
                     ["Not in manifests, in data/",
                      list(files_on_fs - files_in_manifest)]]

        for path_set in path_sets:
            self.unwanted[path_set[0]] = {}
            self.unknown[path_set[0]] = {}
            for path in path_set[1]:
                rules_broken = self._check_path(path)
                if rules_broken:
                    self.unwanted[path_set[0]][path] = rules_broken
                    self.unwanted_count += 1
                elif path_set[0] != "In manifests, in data/":
                    self.unknown[path_set[0]][path] = ["No rule broken"]
                    self.unknown_count += 1

        logging.info("Found potential {0} unwanted files and {1} unknown files"
                     .format(self.unwanted_count, self.unknown_count))


    def _check_path(self, path):
        """Compare a path against every rule in the loaded dictionary"""
        rules_broken = list()
        for rulename, rule in self.rules.items():
            if bool(re.search(rule["regex"], path)) != rule["match"]:
                rules_broken.append(rulename)
        if rules_broken:
            return rules_broken


    def delete_payload(self, unwanted_key, change_oxum = False):
        """Delete selected payload files
        Keep track of bytes and count
        Update the bag oxum"""
        deleted_bytes = 0
        deleted_count = 0

        for path in set(self.unwanted[unwanted_key].keys()):
            path = os.path.join(self.path, path)
            file_bytes = os.stat(path).st_size
            try:

                os.remove(path)
                logging.info("Deleted {0}".format(path))
            except OSError:
                logging.error("Could not delete {0}"
                                  .format(path))
            deleted_bytes += file_bytes
            deleted_count += 1

        if change_oxum:
            self.update_oxum(deleted_bytes, deleted_count)
            self.update_baginfo()


    def delete_manifestentries(self, unwanted_key):
        """Delete selected manifest entries
        Call a rewrite of manifest files"""
        for path in self.unwanted[unwanted_key]:
            self.entries.pop(path, None)
        self.update_manifest()


    def update_oxum(self, removed_bytes, removed_files):
        """Compare the supplied bag oxum with the expected oxum
        Update the oxum as needed"""
        oxum = self.info.get("Payload-Oxum")

        if oxum is None:
            logging.info("Oxum not updated becasue no oxum found")
            return

        # If multiple Payload-Oxum tags (bad idea)
        # use the first listed in bag-info.txt
        if isinstance(oxum, list):
            oxum = oxum[0]

        byte_count, file_count = oxum.split(".", 1)

        if not byte_count.isdigit() or not file_count.isdigit():
            raise BagError("Invalid oxum: %s" % oxum)

        byte_count = int(byte_count) - removed_bytes
        file_count = int(file_count) - removed_files

        # Check that the oxum file count is valid
        payload_file_count = len(set(self.payload_files()))
        if payload_file_count != file_count:
            raise BagError("Invalid oxum: {0} files in oxum, {1} files in data".
                           format(payload_file_count, file_count))



        self.info["Payload-Oxum"] = "{}.{}".format(byte_count, file_count)


    def update_manifest(self):
        "Rewrite the manifest file for each algorithm used"
        for alg in set(self.algs):
            manifest_file = os.path.join(self.path,
                                         "manifest-{}.txt".format(alg))
            with open(manifest_file, "w") as manifest:
                for entry, hashes in self.entries.items():
                    if entry.startswith("data/"):
                        manifest.write("{0}\t{1}\n"
                                       .format(hashes[alg], entry))
            logging.info("Rewrote {0}".format(manifest_file))
            bagit._make_tagmanifest_file(alg, self.path)


    def update_baginfo(self):
        "Rewrite the bag-info file"
        info_file = os.path.join(self.path, self.tag_file_name)
        bagit._make_tag_file(info_file, self.info)
        logging.info("Rewrote {0}".format(info_file))
        for alg in set(self.algs):
            checksum = hashlib.md5(open(info_file,"rb").read()).hexdigest()
            self.entries[self.tag_file_name] = checksum


class RuleError(Exception):
    pass






# code for command line interface

class BagArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        """Borrowed from bagit.py. Not sure why they have this class"""
        self.bag_info = {}
        argparse.ArgumentParser.__init__(self, *args, **kwargs)


def _make_parser():
    parser = BagArgumentParser()
    parser.description = "find unwanted files and delete them"
    parser.add_argument("-b", "--bagpath",
                        required = True,
                        help = "path to the base directory of the bag")
    parser.add_argument("-r", "--rules",
                        help = "path to json file of rules")
    parser.add_argument("--validate",
                        action = "store_true",
                        help = "validate user defined rules")
    ''' TO DO option to unlock deletion
    parser.add_argument("--safe",
                        action = "store_true",
                        help="Do not delete files")
    '''
    parser.add_argument("-v", "--verbose",
                        action = "store_true",
                        help = "print more information")
    parser.add_argument("--log",
                        help = "The name of the log file")
    parser.add_argument("--quiet",
                        help = "Only log errors")


    return parser


def _configure_logging(opts):
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    if opts.quiet:
        level = logging.ERROR
    else:
        level = logging.INFO
    if opts.log:
        logging.basicConfig(filename=opts.log, level=level, format=log_format)
    else:
        logging.basicConfig(level=level, format=log_format)

'''
def query():
    """User interface for command line"""
    prompt = "\nChoose group to delete [1, 2, 3, 4]:\n"
    prompt += "1. Do not delete files\n"
    prompt += "2. Delete unwanted files only in data/\n"
    prompt += "3. Delete unwanted files only in manifest\n"
    prompt += "4. Delete unwanted files in payload and manifest\n\n"

    while True:

        sys.stdout.write(prompt)
        choice = input()
        choice = int(choice)
        if 0 < choice < 5:
            return choice
        else:
            sys.stdout.write("Please respond with 1, 2, 3, or 4.\n\n")
'''

def report_error(error_string, arg, error_code):
    """Lazy error reporting for command line"""
    error = error_string.format(arg, error_code)
    LOGGER.error(error)
    print(error)
    sys.exit(1)


def print_files(file_dict):
    """Prettier printing of unwanted files for command line"""
    for group, paths in file_dict.items():
        if len(file_dict[group]) > 0:
            print("\n== {0} ==".format(group))
            for path, rules in paths.items():
                print("{0}: {1}".format(encode_filename(path), rules))

def encode_filename(s):
    s = s.replace("\r", "%0D")
    s = s.replace("\n", "%0A")
    return s


def main():

    parser = _make_parser()
    args = parser.parse_args()
    _configure_logging(args)

    if args.rules:
        try:
            with open(args.rules, "r") as f:
                rules_dict = json.load(f)
        except FileNotFoundError as e:
            report_error("{0} is not a valid JSON file: {1}",
                         args.bagpath,
                         e)
    else:
        rules_dict = DEFAULT_RULES

    if args.validate:
        try:
            validate_rules(rules_dict)
        except RuleError as e:
            report_error("Rules are not the expected format: {1}",
                         None,
                         e)

    bagpath = os.path.abspath(args.bagpath)
    try:
        bag = CleanerBag(bagpath, rules_dict)
    except bagit.BagError as e:
        report_error("{0} is not a bag: {1}",
                     args.bagpath,
                     e)

    if bag.unwanted_count == 0 & bag.unknown_count == 0:
        print("Bag does not contain unwanted or unknown files")
        return

    if bag.unknown_count > 0:
        print("\n### The following files are not in the manifest or data/, but also did not violate a rule")
        print_files(bag.unknown)

    if bag.unwanted_count > 0:
        print("\n### The following files may be unwanted")
        print_files(bag.unwanted)



'''
 TO DO deletion interface
    if bag.unwanted_count > 0:
        print("\n### The following files may be unwanted")
        print_files(bag.unwanted)

        if not args.safe:
            choice = query()

            if choice == 2:
                key = "Not in manifests, in data/"
                bag.delete_payload(key)
                msg = "Deleted files in payload: {}".format(
                    list(bag.unwanted[key].keys()))
            elif choice == 3:
                key = "In manifests, not in data/"
                bag.delete_manifestentries(key)
                msg = "Deleted entries in manifest: {}".format(
                    list(bag.unwanted[key].keys()))
            elif choice == 4:
                key = "In manifests, in data/"
                bag.delete_payload(key, change_oxum = True)
                bag.delete_manifestentries(key)
                msg = "Deleted files in payload and entries in manifest: {}".format(
                    list(bag.unwanted[key].keys()))
            else:
                msg = "No files or entries deleted"

            logging.info(msg)
            print(msg)



    try:
        bag.validate(fast = True)
    except bagit.BagValidationError as e:
        report_error("{0} is not a valid bag: {1}",
                     args.bagpath,
                     e)
'''

if __name__ == "__main__":
    main()
