# Bag Cleaner
Python 3 module to find (and eventually remove) unwanted files in a bag's manifest and data directory.

Unwanted files are files defined as:

* those in the manifest and not present in the data directory
* those not in the manifest and present in the data directory
* system files present in the manifest and the data directory

Unwanted files are further classified by type according to a user-definable rule dictionary

## Requirements
Python 3
[bagit-python](https://github.com/LibraryOfCongress/bagit-python)

## Usage
Identify unwanted files with default dictionary rules

```
python3 bagcleaner.py -b path/to/bag
```

Identify unwanted files according to custom rules

```
python3 bagcleaner.py -b path/to/bag -r path/to/rules.json
```
