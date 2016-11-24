'''
:mod:`em_shadow_memory` -- Shadow memory implementation on external memory
==========================================================================

.. module: em_shadow_memory
   :platform: Unix, Windows
   :synopsis: Shadow memory implementation on external memory
.. moduleauthor:: huku <huku@grhack.net>


About
-----
Simple 1-1 shadow memory implementation implemented on top of external memory
lists. Shadow memory techniques are widely used in various binary analysis
schemes. For a good overview, have a look at [1] published by the Valgrind team.

[1] http://valgrind.org/docs/shadow-memory2007.pdf


Classes
-------
'''

__author__ = 'huku <huku@grhack.net>'


import sys

try:
    import pyrsistence
except ImportError:
    sys.exit('Pyrsistence not installed?')



M_NONE = 0                  # Address hasn't been analyzed yet
M_ANALYZED = 1              # Address has been analyzed
M_CODE = 2                  # Address holds executable code
M_BASIC_BLOCK_LEADER = 4    # Address is a basic block leader
M_FUNCTION = 8              # Address is a function entry point
M_DATA = 16                 # Address holds data
M_HEAD = 32                 # Address holds code or data head
M_RELOCATED = 64            # Address holds relocated value
M_RELOCATED_LEAF = 128      # Address holds last relocated value in a chain


class EMShadowMemory(object):
    '''
    A class that implements a simple 1-1 shadow memory model.

    .. automethod:: __init__
    '''

    def __init__(self, dirname, start_address, end_address):
        '''
        :param dirname: Directory where the shadow memory will be stored.
        :param start_address: Address of first byte in shadow memory.
        :param end_address: Address of last byte in shadow memory.
        '''

        # Compute size of shadow memory.
        size = end_address - start_address + 1

        # Initialize external memory list holding the shadow memory contents and
        # mark all elements as unanalyzed.
        shadow = pyrsistence.EMList(dirname)
        while len(shadow) < size:
            shadow.append(M_NONE)

        self.start_address = start_address
        self.end_address = end_address
        self.size = end_address - start_address + 1
        self.dirname = dirname
        self.shadow = shadow

    def __del__(self):
        self.shadow.close()

    def __str__(self):
        return '<EMShadowMemory %#x-%#x>' % (self.start_address, self.end_address)


    # Low level getter and setter for marks.

    def _get_mark(self, address):
        try:
            mark = self.shadow[address - self.start_address]
        except IndexError:
            mark = 0
        return mark

    def _set_mark(self, address, mark):
        try:
            self.shadow[address - self.start_address] = mark
        except IndexError:
            pass


    # Low level methods for adding and removing marks from a single address.

    def _mark(self, address, mark):
        new_mark = self._get_mark(address)
        new_mark |= mark
        self._set_mark(address, new_mark)

    def _unmark(self, address, mark):
        new_mark = self._get_mark(address)
        new_mark &= ~mark
        self._set_mark(address, new_mark)


    # Low level methods for adding, removing and testing marks of address ranges.

    def _mark_range(self, address, length, mark):
        for i in xrange(length):
            self._mark(address + i, mark)

    def _unmark_range(self, address, length, mark):
        for i in xrange(length):
            self._unmark(address + i, mark)

    def _is_marked_range(self, address, length, mark):
        r = 0
        for i in xrange(length):
            if self._get_mark(address + i) & mark == mark:
                r += 1
        return r


    # Public API begins here.

    # Standard interface to `open()' and `close()'.

    def open(self):
        '''Open, or re-open, shadow memory.'''
        self.shadow.open(self.filename)

    def close(self):
        '''Close shadow memory.'''
        self.shadow.close()


    def mark_as_analyzed(self, address, length=1):
        '''
        Mark address range as analyzed.

        :param address: Address to start marking from.
        :param length: Number of bytes to mark.
        '''
        self._mark_range(address, length, M_ANALYZED)


    def mark_as_code(self, address, length=1):
        '''
        Mark address range as code region. First byte is also marked as head.

        :param address: Address to start marking from.
        :param length: Number of bytes to mark.
        '''
        self._mark(address, M_HEAD | M_CODE)
        self._mark_range(address + 1, length - 1, M_CODE)


    def mark_as_basic_block_leader(self, address):
        '''
        Mark address as basic block leader.

        :param address: Address to mark.
        '''
        self._mark(address, M_HEAD | M_CODE | M_BASIC_BLOCK_LEADER)


    def mark_as_function(self, address):
        '''
        Mark address as function entry point.

        :param address: Address to mark.
        '''
        self._mark(address, M_HEAD | M_CODE | M_BASIC_BLOCK_LEADER | M_FUNCTION)


    def mark_as_data(self, address, length=1):
        '''
        Mark address range as data region. First byte is also marked as head.

        :param address: Address to start marking from.
        :param length: Number of bytes to mark.
        '''
        self._mark(address, M_HEAD | M_DATA)
        self._mark_range(address + 1, length - 1, M_DATA)


    def mark_as_head(self, address):
        '''
        Mark address range as head.

        :param address: Address to mark.
        '''
        self._mark(address, M_HEAD)


    def mark_as_relocated(self, address):
        '''
        Mark address to indicate that it holds a relocated element.

        :param address: Address to mark.
        '''
        self._mark(address, M_RELOCATED)


    def mark_as_relocated_leaf(self, address):
        '''
        Mark address to indicate that it holds a relocated leaf element (an
        element which is not further relocated).

        :param address: Address to mark.
        '''
        self._mark(address, M_RELOCATED_LEAF)


    # Remove mark combinations from single address or address range.

    def unmark_as_analyzed(self, address, length=1):
        '''
        Unmark address range as analyzed.

        :param address: Address to start unmarking from.
        :param length: Number of bytes to unmark.
        '''
        self._unmark_range(address, length, M_ANALYZED)


    def unmark_as_code(self, address, length=1):
        '''
        Unmark address range as code region. First byte's head mark is also
        removed.

        :param address: Address to start unmarking from.
        :param length: Number of bytes to unmark.
        '''
        self._unmark(address, M_HEAD | M_CODE)
        self._unmark_range(address + 1, length - 1, M_CODE)


    def unmark_as_basic_block_leader(self, address):
        '''
        Unmark address as basic block leader.

        :param address: Address to unmark.
        '''
        self._unmark(address, M_BASIC_BLOCK_LEADER)


    def unmark_as_function(self, address):
        '''
        Unmark address as function entry point.

        :param address: Address to unmark.
        '''
        self._unmark(address, M_FUNCTION)


    def unmark_as_data(self, address, length=1):
        '''
        Unmark address range as data region. First byte's head mark is also
        removed.

        :param address: Address to start unmarking from.
        :param length: Number of bytes to unmark.
        '''
        self._unmark(address, M_HEAD | M_DATA)
        self._unmark_range(address + 1, length - 1, M_DATA)


    def unmark_as_head(self, address):
        '''
        Unmark address as head.

        :param address: Address to unmark.
        '''
        self._unmark(address, M_HEAD)


    def unmark_as_relocated(self, address):
        '''
        Unmark address as relocated.

        :param address: Address to unmark.
        '''
        self._unmark(address, M_RELOCATED)


    def unmark_as_relocated_leaf(self, address):
        '''
        Unmark address as relocated leaf.

        :param address: Address to unmark.
        '''
        self._unmark(address, M_RELOCATED_LEAF)


    # Check mark of single address or address range.

    def is_marked_as_analyzed(self, address, length=1):
        '''
        Check if address range is marked as analyzed.

        :param address: Address to start checking from.
        :param length: Number of bytes to check.
        :returns: Number of bytes actually marked as analyzed.
        :rtype: ``int``
        '''
        return self._is_marked_range(address, length, M_ANALYZED)


    def is_marked_as_code(self, address, length=1):
        '''
        Check if address range is marked as code region.

        :param address: Address to start checking from.
        :param length: Number of bytes to check.
        :returns: Number of bytes actually marked as code.
        :rtype: ``int``
        '''
        return self._is_marked_range(address, length, M_CODE)


    def is_marked_as_basic_block_leader(self, address):
        '''
        Check if address is marked as basic block leader.

        :param address: Address to check.
        :returns: ``True`` if marked as basic block leader, ``False`` otherwise.
        :rtype: ``bool``
        '''
        return self._get_mark(address) & M_BASIC_BLOCK_LEADER


    def is_marked_as_function(self, address):
        '''
        Check if address is marked as function entry point.

        :param address: Address to check.
        :returns: ``True`` if marked as function entry point, ``False`` otherwise.
        :rtype: ``bool``
        '''
        return self._get_mark(address) & M_FUNCTION


    def is_marked_as_data(self, address, length=1):
        '''
        Check if address range is marked as data region.

        :param address: Address to start checking from.
        :param length: Number of bytes to check.
        :returns: Number of bytes actually marked as data.
        :rtype: ``int``
        '''
        return self._is_marked_range(address, length, M_DATA)


    def is_marked_as_head(self, address):
        '''
        Check if address is marked as head.

        :param address: Address to check.
        :returns: ``True`` if marked as head, ``False`` otherwise.
        :rtype: ``bool``
        '''
        return self._get_mark(address) & M_HEAD


    def is_marked_as_relocated(self, address):
        '''
        Check if address is marked as relocated.

        :param address: Address to check.
        :returns: ``True`` if marked as relocated, ``False`` otherwise.
        :rtype: ``bool``
        '''
        return self._get_mark(address) & M_RELOCATED


    def is_marked_as_relocated_leaf(self, address):
        '''
        Check if address is marked as relocated leaf.

        :param address: Address to check.
        :returns: ``True`` if marked as relocated leaf, ``False`` otherwise.
        :rtype: ``bool``
        '''
        return self._get_mark(address) & M_RELOCATED_LEAF

