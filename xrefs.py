#!/usr/bin/env python
'''xrefs.py - Container for an instruction's code and data cross references.'''

__author__ = 'huku <huku@grhack.net>'


class XRefs(object):
    '''Container for an instruction's code and data cross references.'''

    def __init__(self):
        # Set of `long' values holding code cross references.
        self.code = set()

        # Set of tuples with address-size pairs holding data references.
        self.data = set()

    def __iadd__(self, other):
        self.code.update(other.code)
        self.data.update(other.data)
        return self

