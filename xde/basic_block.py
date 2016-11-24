'''
:mod:`basic_block` -- A class representing a basic block
========================================================

.. module: basic_block
   :platform: Unix, Windows
   :synopsis: A class representing a basic block
.. moduleauthor:: huku <huku@grhack.net>

About
-----
A simple ``cPickle`` friendly class representing a basic block of assembly code.

Classes
-------
'''

__author__ = 'huku <huku@grhack.net>'


class BasicBlock(object):
    '''
    Represents a basic block in the CFG.

    .. automethod:: __init__
    '''

    def __init__(self, start_address, end_address, instructions):
        '''
        :param start_address: Address of first instruction in basic block.
        :param end_address: Address of first instruction in physically bordering
            basic block.
        :param instructions: List of instruction addresses in basic block (used
            for identifying instruction boundaries without disassembling them
            again and again).
        '''
        self.start_address = start_address
        self.end_address = end_address
        self.instructions = instructions

    def __str__(self):
        return '<BasicBlock 0x%x-0x%x>' % (self.start_address, self.end_address)

    def __eq__(self, other):
        return self.start_address == other.start_address and \
            self.end_address == other.end_address

    def __hash__(self):
        return self.start_address

    def __contains__(self, address):
        return self.start_address <= address < self.end_address

