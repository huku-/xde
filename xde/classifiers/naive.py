#!/usr/bin/env python
'''
:mod:`naive` - Naive classifier
===============================

.. module: naive
   :platform: Unix, Windows
   :synopsis: Naive classifier
.. moduleauthor:: huku <huku@grhack.net>


About
-----
Uses a naive method to determine if a series of decoded instructions is indeed
code or data that was erroneously treated as an instruction stream. The method
implemented is based on a simple heuristic that tries to guess if the series of
decoded instructions look like a function prologue or not.

Functions
---------
'''

__author__ = 'huku <huku@grhack.net>'


import pyxed


# Instruction classes usually present in function prologues.
PROLOGUE_ICLASSES = [
    pyxed.XED_ICLASS_CALL_NEAR,
    pyxed.XED_ICLASS_RET_NEAR,
    pyxed.XED_ICLASS_PUSH,
    pyxed.XED_ICLASS_POP,
    pyxed.XED_ICLASS_CMP,
    pyxed.XED_ICLASS_TEST,
    pyxed.XED_ICLASS_SETBE,
    pyxed.XED_ICLASS_SETB,
    pyxed.XED_ICLASS_SETLE,
    pyxed.XED_ICLASS_SETL,
    pyxed.XED_ICLASS_SETNBE,
    pyxed.XED_ICLASS_SETNB,
    pyxed.XED_ICLASS_SETNLE,
    pyxed.XED_ICLASS_SETNL,
    pyxed.XED_ICLASS_SETNS,
    pyxed.XED_ICLASS_SETNZ,
    pyxed.XED_ICLASS_SETS,
    pyxed.XED_ICLASS_SETZ,
    pyxed.XED_ICLASS_JB,
    pyxed.XED_ICLASS_JBE,
    pyxed.XED_ICLASS_JL,
    pyxed.XED_ICLASS_JLE,
    pyxed.XED_ICLASS_JMP,
    pyxed.XED_ICLASS_JNB,
    pyxed.XED_ICLASS_JNBE,
    pyxed.XED_ICLASS_JNL,
    pyxed.XED_ICLASS_JNLE,
    pyxed.XED_ICLASS_JNO,
    pyxed.XED_ICLASS_JNP,
    pyxed.XED_ICLASS_JNS,
    pyxed.XED_ICLASS_JNZ,
    pyxed.XED_ICLASS_JO,
    pyxed.XED_ICLASS_JP,
    pyxed.XED_ICLASS_JS,
    pyxed.XED_ICLASS_JZ,
    pyxed.XED_ICLASS_LEA,
    pyxed.XED_ICLASS_SUB,
    pyxed.XED_ICLASS_AND,
    pyxed.XED_ICLASS_XOR,
    pyxed.XED_ICLASS_MOV,
    pyxed.XED_ICLASS_MOVSX,
    pyxed.XED_ICLASS_MOVZX,
    pyxed.XED_ICLASS_FLD,
    pyxed.XED_ICLASS_FLDZ,
    pyxed.XED_ICLASS_FST,
    pyxed.XED_ICLASS_FSTP
]


WINDOW_SIZE = 4


def is_code(insns):
    '''
    Implements a naive classification heuristic.

    :param insns: An array of decoded instruction objects to classify as either
        code or data.
    :returns: ``True`` if the instructions look like a valid function prologue
        and ``False`` otherwise.
    :rtype: ``bool``
    '''

    r = True

    # Examine at most `WINDOW_SIZE' instructions from the instruction stream.
    for insn in insns[:WINDOW_SIZE]:
        if insn.get_iclass() not in PROLOGUE_ICLASSES:
            r = False
            break

    return r

