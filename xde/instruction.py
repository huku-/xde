#!/usr/bin/env python
'''
:mod:`instruction` - Wrapper class for disassembled instructions
================================================================

.. module: disassembler
   :platform: Unix, Windows
   :synopsis: Wrapper class for disassembled instructions
.. moduleauthor:: huku <huku@grhack.net>


About
-----
This module defines a class that wraps a ``pyxed.Instruction`` instance and
provides higher level methods (WIP). We actually use the *delegate* design
pattern to forward method calls to the wrapped ``pyxed.Instruction`` object.


Classes
-------
'''

__author__ = 'huku <huku@grhack.net>'


import pyxed


class Instruction(object):
    '''
    Wraps a ``pyxed.Instruction`` object to offer more functionality. Implements
    the *delegate* design pattern.

    .. automethod:: __init__
    .. automethod:: __getattr__
    '''

    def __init__(self, instruction, cpu):
        '''
        :param instruction: The ``pyxed.Instruction`` instance to be wrapped.
        :param cpu: The :class:`cpu.CPU` instance corresponding to the CPU that
            has decoded instruction *instruction*.
        '''

        # Wrapped delegate `pyxed.Instruction' object should be private.
        self._instruction = instruction

        # We also need this for private purposes.
        self._cpu = cpu


    def __getattr__(self, name):
        '''
        When an attribute is not found here, look for it in ``pyxed.Instruction``.
        This function is the actual delegation link.
        '''
        return getattr(self._instruction, name)

    def __str__(self):
        return '<Instruction 0x%x>' % self.runtime_address

    def __hash__(self):
        return self.runtime_address


    def get_next_instruction_address(self):
        '''
        Get the absolute address of the instruction immediately following the
        current one.

        :returns: Next instruction's absolute address.
        :rtype: ``long``
        '''
        return self.runtime_address + self.get_length()


    def get_read_registers(self):
        '''
        Get set of registers read by this instruction.

        :returns: Set of read registers.
        :rtype: ``set``
        '''

        regs = set()
        for i in range(self.get_noperands()):
            operand = self.get_operand(i)
            if operand.is_register() and operand.is_read():
                regs.add(self.get_reg(operand.get_name()))
        return regs


    def get_written_registers(self):
        '''
        Get set of registers written by this instruction.

        :returns: Set of written registers.
        :rtype: ``set``
        '''

        regs = set()
        for i in range(self.get_noperands()):
            operand = self.get_operand(i)
            if operand.is_register() and operand.is_written():
                regs.add(self.get_reg(operand.get_name()))
        return regs


    def get_registers(self):
        '''
        Get instruction's register operands.

        :returns: Set of instruction's register operands.
        :rtype: ``set``
        '''

        regs = set()
        for i in range(self.get_noperands()):
            operand = self.get_operand(i)
            if operand.is_register():
                regs.add(self.get_reg(operand.get_name()))
        return regs


    def get_memory_displacement(self, i):
        '''
        Attempt to compute absolute address of instruction's *i*-th memory
        operand.

        :param i: Index of memory operand whose memory displacement to compute.
        :returns: The absolute memory address of the *i*-th memory operand or
            ``None`` if it can't be computed in the current context.
        :rtype: ``long``
        '''

        # Get memory operand's attributes.
        seg_reg = self.get_seg_reg(i)
        base_reg = self.get_base_reg(i)
        displacement = self._instruction.get_memory_displacement(i)

        # If this is a RIP or EIP relative addressing instruction, compute the
        # absolute address by adding next instruction's address to the memory
        # displacement.
        if base_reg == self._cpu.get_program_counter_name():
            displacement += self.get_next_instruction_address()
        elif base_reg != pyxed.XED_REG_INVALID:
            displacement = None

        # If segment register is one of SS, FS or FS, we can't do anything to
        # compute the absolute target address.
        if seg_reg in [pyxed.XED_REG_SS, pyxed.XED_REG_FS, pyxed.XED_REG_GS]:
            displacement = None

        return displacement


    def get_memory_operand(self, i):
        '''
        Get instruction's *i*-th memory operand. Returns a tuple holding the
        memory operand's segment register, base register, index register, scale,
        memory displacement and length in this order.

        :param i: Index of memory operand to return.
        :returns: A 6-tuple describing the memory operand.
        :rtype: ``tuple``
        '''
        memop = (
            self.get_seg_reg(i),
            self.get_base_reg(i),
            self.get_index_reg(i),
            self.get_scale(i),
            self.get_memory_displacement(i),
            self.get_memory_operand_length(i)
        )
        return memop


    def get_read_memory_operands(self):
        '''
        Get set of memory operands read by this instruction.

        :returns: Set of read memory operands.
        :rtype: ``set``
        '''

        memops = set()
        for i in range(self.get_number_of_memory_operands()):
            if self.mem_is_read(i):
               memops.add(self.get_memory_operand(i))
        return memops


    def get_written_memory_operands(self):
        '''
        Get set of memory operands written by this instruction.

        :returns: Set of written memory operands.
        :rtype: ``set``
        '''

        memops = set()
        for i in range(self.get_number_of_memory_operands()):
            if self.mem_is_written(i):
               memops.add(self.get_memory_operand(i))
        return memops


    def get_memory_operands(self):
        '''
        Get instruction's memory operands.

        :returns: Set of instruction's memory operands.
        :rtype: ``set``
        '''

        memops = set()
        for i in range(self.get_number_of_memory_operands()):
               memops.add(self.get_memory_operand(i))
        return memops


    def get_branch_displacement(self):
        '''
        Compute the absolute branch displacement of this instruction. This, of
        course, makes sense only if the current instruction is a direct branch
        instruction.

        :returns: The absolute branch displacement.
        :rtype: ``long``
        '''

        displacement = self._instruction.get_branch_displacement()

        # If it's a far control transfer, the branch displacement is absolute.
        # Otherwise, the branch displacement is relative to the address of the
        # next instruction.
        if not self.get_attribute(pyxed.XED_ATTRIBUTE_FAR_XFER):

            # Branch displacement is a 32-bit value even in long mode.
            displacement = -(displacement & 0x80000000) + \
                (displacement & 0x7fffffff)

            # Branch displacement is relative to next instruction's address.
            displacement += self.get_next_instruction_address()

        return displacement

