#!/usr/bin/env python
'''basic_block.py - Basic block class.'''

__author__ = 'huku <huku@grhack.net>'



class BasicBlock(object):
    '''Represents a basic block in the CFG.'''

    def __init__(self):
        self.instructions = []

    def __str__(self):
        return '<BasicBlock 0x%x-0x%x>' % \
            (self.instructions[0], self.instructions[-1])

    def __hash__(self):
        return self.instructions[0]

    def __contains__(self, address):
        return self.instructions[0] <= address <= self.instructions[-1]

