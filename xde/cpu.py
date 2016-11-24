#!/usr/bin/env python
'''
:mod:`cpu` - Definitions for IA-32 and AMD64 CPUs
=================================================

.. module: cpu
   :platform: Unix, Windows
   :synopsis: Definitions for IA-32 and AMD64 CPUs
.. moduleauthor:: huku <huku@grhack.net>


About
-----
Exports class :class:`CPU` which provides a simple abstraction layer over the
various CPU configurations (WIP).


Classes
-------
'''

__author__ = 'huku <huku@grhack.net>'


import pyxed


X86_MODE_REAL = 1
X86_MODE_PROTECTED_32BIT = 2
X86_MODE_PROTECTED_64BIT = 3


class CPU(object):
    '''
    Represents an IA-32 or AMD64 CPU.

    .. automethod:: __init__
    '''

    def __init__(self, mode):
        '''
        :param mode: Mode of the instantiated CPU. May be :data:`X86_MODE_REAL`,
            :data:`X86_MODE_PROTECTED_32BIT` or :data:`X86_MODE_PROTECTED_64BIT`.
        '''
        self.mode = mode

    def __str__(self):
        name = '?'
        if self.mode == X86_MODE_REAL:
            name = 'X86_MODE_REAL'
        elif self.mode == X86_MODE_PROTECTED_32BIT:
            name = 'X86_MODE_PROTECTED_32BIT'
        elif self.mode == X86_MODE_PROTECTED_64BIT:
            name = 'X86_MODE_PROTECTED_64BIT'
        return '<CPU %s>' % name


    def get_program_counter_name(self):
        '''
        Get name of program counter register.

        :returns: Name of program counter register.
        :rtype: ``int``
        '''

        name = None
        if self.mode == X86_MODE_REAL:
            name = pyxed.XED_REG_IP
        elif self.mode == X86_MODE_PROTECTED_32BIT:
            name = pyxed.XED_REG_EIP
        elif self.mode == X86_MODE_PROTECTED_64BIT:
            name = pyxed.XED_REG_RIP
        return name


    def get_stack_pointer_name(self):
        '''
        Get name of stack pointer register.

        :returns: Name of stack pointer register.
        :rtype: ``int``
        '''

        name = None
        if self.mode == X86_MODE_REAL:
            name = pyxed.XED_REG_SP
        elif self.mode == X86_MODE_PROTECTED_32BIT:
            name = pyxed.XED_REG_ESP
        elif self.mode == X86_MODE_PROTECTED_64BIT:
            name = pyxed.XED_REG_RSP
        return name


    def get_segment_register_names(self):
        '''
        Get set of segment register names.

        :returns: Set of segment register names.
        :rtype: ``set``
        '''

        names = set()

        if self.mode == X86_MODE_REAL:
            names.update([pyxed.XED_REG_CS, pyxed.XED_REG_DS, pyxed.XED_REG_ES,
                pyxed.XED_REG_SS])

        elif self.mode == X86_MODE_PROTECTED_32BIT:
            names.update([pyxed.XED_REG_CS, pyxed.XED_REG_DS, pyxed.XED_REG_ES,
                pyxed.XED_REG_FS, pyxed.XED_REG_GS, pyxed.XED_REG_SS])

        elif self.mode == X86_MODE_PROTECTED_64BIT:
            names.update([pyxed.XED_REG_CS, pyxed.XED_REG_DS, pyxed.XED_REG_ES,
                pyxed.XED_REG_FS, pyxed.XED_REG_GS, pyxed.XED_REG_SS])

        return names


    def get_general_purpose_register_names(self):
        '''
        Get set of general purpose register names.

        :returns: Set of general purpose register names.
        :rtype: ``set``
        '''

        names = set()

        if self.mode == X86_MODE_REAL:
            names.update([pyxed.XED_REG_AL, pyxed.XED_REG_BL,
                pyxed.XED_REG_CL, pyxed.XED_REG_DL, pyxed.XED_REG_BPL,
                pyxed.XED_REG_DIL, pyxed.XED_REG_SIL, pyxed.XED_REG_AH,
                pyxed.XED_REG_BH, pyxed.XED_REG_CH, pyxed.XED_REG_DH,
                pyxed.XED_REG_AX, pyxed.XED_REG_BX, pyxed.XED_REG_CX,
                pyxed.XED_REG_DX, pyxed.XED_REG_BP, pyxed.XED_REG_SI,
                pyxed.XED_REG_DI])

        elif self.mode == X86_MODE_PROTECTED_32BIT:
            names.update([pyxed.XED_REG_AL, pyxed.XED_REG_BL,
                pyxed.XED_REG_CL, pyxed.XED_REG_DL, pyxed.XED_REG_BPL,
                pyxed.XED_REG_DIL, pyxed.XED_REG_SIL, pyxed.XED_REG_AH,
                pyxed.XED_REG_BH, pyxed.XED_REG_CH, pyxed.XED_REG_DH,
                pyxed.XED_REG_AX, pyxed.XED_REG_BX, pyxed.XED_REG_CX,
                pyxed.XED_REG_DX, pyxed.XED_REG_BP, pyxed.XED_REG_SI,
                pyxed.XED_REG_DI, pyxed.XED_REG_EAX, pyxed.XED_REG_EBX,
                pyxed.XED_REG_ECX, pyxed.XED_REG_EDX, pyxed.XED_REG_EBP,
                pyxed.XED_REG_ESI, pyxed.XED_REG_EDI])

        elif self.mode == X86_MODE_PROTECTED_64BIT:
            names.update([pyxed.XED_REG_AL, pyxed.XED_REG_BL,
                pyxed.XED_REG_CL, pyxed.XED_REG_DL, pyxed.XED_REG_BPL,
                pyxed.XED_REG_DIL, pyxed.XED_REG_SIL, pyxed.XED_REG_R8B,
                pyxed.XED_REG_R9B, pyxed.XED_REG_R10B, pyxed.XED_REG_R11B,
                pyxed.XED_REG_R12B, pyxed.XED_REG_R13B, pyxed.XED_REG_R14B,
                pyxed.XED_REG_R15B, pyxed.XED_REG_AH, pyxed.XED_REG_BH,
                pyxed.XED_REG_CH, pyxed.XED_REG_DH, pyxed.XED_REG_AX,
                pyxed.XED_REG_BX, pyxed.XED_REG_CX, pyxed.XED_REG_DX,
                pyxed.XED_REG_BP, pyxed.XED_REG_SI, pyxed.XED_REG_DI,
                pyxed.XED_REG_R8W, pyxed.XED_REG_R9W, pyxed.XED_REG_R10W,
                pyxed.XED_REG_R11W, pyxed.XED_REG_R12W, pyxed.XED_REG_R13W,
                pyxed.XED_REG_R14W, pyxed.XED_REG_R15W, pyxed.XED_REG_EAX,
                pyxed.XED_REG_EBX, pyxed.XED_REG_ECX, pyxed.XED_REG_EDX,
                pyxed.XED_REG_EBP, pyxed.XED_REG_ESI, pyxed.XED_REG_EDI,
                pyxed.XED_REG_R8D, pyxed.XED_REG_R9D, pyxed.XED_REG_R10D,
                pyxed.XED_REG_R11D, pyxed.XED_REG_R12D, pyxed.XED_REG_R13D,
                pyxed.XED_REG_R14D, pyxed.XED_REG_R15D, pyxed.XED_REG_RAX,
                pyxed.XED_REG_RBX, pyxed.XED_REG_RCX, pyxed.XED_REG_RDX,
                pyxed.XED_REG_RBP, pyxed.XED_REG_RSI, pyxed.XED_REG_RSI,
                pyxed.XED_REG_R8, pyxed.XED_REG_R9, pyxed.XED_REG_R10,
                pyxed.XED_REG_R11, pyxed.XED_REG_R12, pyxed.XED_REG_R13,
                pyxed.XED_REG_R14, pyxed.XED_REG_R15])

        return names

