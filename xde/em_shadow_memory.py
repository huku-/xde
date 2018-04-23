'''
:mod:`em_shadow_memory` -- Shadow memory implementation on external memory
==========================================================================

.. module: em_shadow_memory
   :platform: Unix, Windows
   :synopsis: Shadow memory implementation on external memory
.. moduleauthor:: huku <huku@grhack.net>


About
-----
Simple, sparse, 1-1 shadow memory implementation implemented on top of external
memory lists. Shadow memory techniques are widely used in various binary analysis
schemes. For a good overview, have a look at [1] published by the Valgrind team.

[1] http://valgrind.org/docs/shadow-memory2007.pdf


Classes
-------
'''

__author__ = 'huku <huku@grhack.net>'


import sys
import os

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
    A class that implements a simple, sparse, 1-1 shadow memory model.

    .. automethod:: __init__
    .. automethod:: _merge_memory_ranges
    .. automethod:: _make_shadow_memory
    .. automethod:: _get_shadow_memory_coordinates
    .. automethod:: _mark
    .. automethod:: _unmark
    .. automethod:: _is_marked
    .. automethod:: _mark_range
    .. automethod:: _unmark_range
    .. automethod:: _is_marked_range
    '''

    def __init__(self, dirname, memory_ranges):
        '''
        :param dirname: Directory where various external memory list files will
            be stored. The directory is created if it does not exist.
        :param memory_ranges: Memory ranges that will be shadowed.
        '''

        # Create container directory if not there.
        if os.access(dirname, os.F_OK) == False:
            os.makedirs(dirname, 0750)

        # Merge given memory ranges into maximally contiguous chunks.
        memory_ranges = self._merge_memory_ranges(memory_ranges)

        # Create shadow memory for each of the above chunks.
        shadows = []
        for memory_range in memory_ranges:
            shadows.append(self._make_shadow_memory(dirname, memory_range))

        self.memory_ranges = memory_ranges
        self.dirname = dirname
        self.shadows = shadows


    def __del__(self):
        for shadow in self.shadows:
            shadow.close()



    def _merge_memory_ranges(self, memory_ranges):
        '''
        Given a list of memory ranges, merge contiguous elements and return a
        new, possibly smaller list, of memory ranges.

        :param memory_ranges: Memory ranges that will be merged.
        :returns: List of merged memory ranges.
        :rtype: ``list``

        .. warning:: This is a private function, don't use it directly.
        '''

        merged_memory_ranges = []
        for memory_range in memory_ranges:
            new_start_address, new_end_address = memory_range

            for i, (start_address, end_address) in enumerate(merged_memory_ranges):
                if new_start_address <= start_address <= new_end_address or \
                        new_start_address <= end_address + 1 <= new_end_address:
                    start_address = min(new_start_address, start_address)
                    end_address = max(new_end_address, end_address)
                    merged_memory_ranges[i] = (start_address, end_address)
                    break
            else:
                merged_memory_ranges.append(memory_range)

        return sorted(merged_memory_ranges)


    def _make_shadow_memory(self, dirname, memory_range):
        '''
        Make shadow memory for the given memory range.

        :param dirname: Directory where external memory list will be stored. The
            directory is created if it does not exist.
        :param memory_range: Memory range to be shadowed.
        :returns: External memory list holding *memory_range*'s shadow bytes.
        :rtype: ``pyrsistence.EMList``

        .. warning:: This is a private function, don't use it directly.
        '''

        start_address, end_address = memory_range
        filename = '%s/%#x-%#x' % (dirname, start_address, end_address)

        shadow = pyrsistence.EMList(filename)
        size = end_address - start_address + 1
        while len(shadow) < size:
            shadow.append(M_NONE)

        return shadow


    def _get_shadow_memory_coordinates(self, address):
        '''
        Given an arbitrary address, return the index of the shadowed memory
        range that contains it and the index of the addressed byte in the memory
        range. Those two indices are the *shadow memory coordinates* of address
        *address*.

        Raises ``RuntimeError`` if *address* is not backed by this shadow memory.

        :param address: The address whose coordinates to return.
        :returns: A tuple holding the *shadow memory coordinates* of *address*.
        :rtype: ``tuple``

        .. warning:: This is a private function, don't use it directly.
        '''

        for i, (start_address, end_address) in enumerate(self.memory_ranges):
            if start_address <= address <= end_address:
                return (i, end_address - address)

        raise RuntimeError('Address %#x not backed by shadow memory' % address)


    def _mark(self, address, mark):
        i, j = self._get_shadow_memory_coordinates(address)
        shadow = self.shadows[i]
        new_mark = shadow[j]
        if new_mark & mark != mark:
            new_mark |= mark
            shadow[j] = new_mark


    def _unmark(self, address, mark):
        i, j = self._get_shadow_memory_coordinates(address)
        shadow = self.shadows[i]
        new_mark = shadow[j]
        if new_mark & mark != 0:
            new_mark &= ~mark
            shadow[j] = new_mark


    def _is_marked(self, address, mark):
        i, j = self._get_shadow_memory_coordinates(address)
        shadow = self.shadows[i]
        return shadow[j] & mark == mark


    def _mark_range(self, address, length, mark):
        i, j = self._get_shadow_memory_coordinates(address)
        shadow = self.shadows[i]
        limit = min(j + length, len(shadow))
        while j < limit:
            new_mark = shadow[j]
            if new_mark & mark != mark:
                new_mark |= mark
                shadow[j] = new_mark
            j += 1


    def _unmark_range(self, address, length, mark):
        i, j = self._get_shadow_memory_coordinates(address)
        shadow = self.shadows[i]
        limit = min(j + length, len(shadow))
        while j < limit:
            new_mark = shadow[j]
            if new_mark & mark != 0:
                new_mark &= ~mark
                shadow[j] = new_mark
            j += 1


    def _is_marked_range(self, address, length, mark):

        i, j = self._get_shadow_memory_coordinates(address)
        shadow = self.shadows[i]
        limit = min(j + length, len(shadow))

        r = 0
        while j < limit and shadow[j] & mark == mark:
            r += 1
            j += 1

        return r



    # Public API begins here.

    def open(self):
        '''Open, or re-open, shadow memory.'''
        for i, (start_address, end_address) in enumerate(self.memory_ranges):
            filename = '%s/%#x-%#x' % (self.dirname, start_address, end_address)
            self.shadow[i].open(filename)

    def close(self):
        '''Close shadow memory.'''
        for shadow in self.shadows:
            shadow.close()


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
        return self._is_marked(address, M_BASIC_BLOCK_LEADER)


    def is_marked_as_function(self, address):
        '''
        Check if address is marked as function entry point.

        :param address: Address to check.
        :returns: ``True`` if marked as function entry point, ``False`` otherwise.
        :rtype: ``bool``
        '''
        return self._is_marked(address, M_FUNCTION)


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
        return self._is_marked(address, M_HEAD)


    def is_marked_as_relocated(self, address):
        '''
        Check if address is marked as relocated.

        :param address: Address to check.
        :returns: ``True`` if marked as relocated, ``False`` otherwise.
        :rtype: ``bool``
        '''
        return self._is_marked(address, M_RELOCATED)


    def is_marked_as_relocated_leaf(self, address):
        '''
        Check if address is marked as relocated leaf.

        :param address: Address to check.
        :returns: ``True`` if marked as relocated leaf, ``False`` otherwise.
        :rtype: ``bool``
        '''
        return self._is_marked(address, M_RELOCATED_LEAF)

