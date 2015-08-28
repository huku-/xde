#!/usr/bin/env python
'''basic_block.py - Basic block class.'''

__author__ = 'huku <huku@grhack.net>'


class BasicBlock(object):
    '''Represents a basic block in the CFG.'''

    def __init__(self, start_address, end_address, instructions):
        self.start_address = start_address
        self.end_address = end_address
        self.instructions = instructions

    def __str__(self):
        return '<BasicBlock 0x%x-0x%x>' % (self.start_address, self.end_address)

    def __hash__(self):
        return self.start_address

    def __contains__(self, address):
        return self.start_address <= address < self.end_address

