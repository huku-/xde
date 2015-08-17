#!/usr/bin/env python
'''instruction.py - Wrapper class for disassembled instructions.'''

__author__ = 'huku <huku@grhack.net>'


import struct

import pyxed


class Instruction(object):
    '''
    Wraps a `pyxed.Instruction' object to offer more functionality. Implements
    the "delegate" design pattern.
    '''

    def __init__(self, instruction, disassembler):

        # Wrapped delegate `pyxed.Instruction' object should be private.
        self._instruction = instruction

        # Owning disassembler object should be public.
        self.disassembler = disassembler


    def __getattr__(self, name):
        '''
        When an attribute is not found here, look for it in `pyxed.Instruction'.
        This function is the actual delegation link.
        '''
        return getattr(self._instruction, name)

    def __str__(self):
        return '<Instruction 0x%x>' % self.runtime_address



    def get_indirect_code_refs(self):
        '''
        Get list of indirect references to code segment (e.g. arrays of function
        pointers etc).
        '''

        target_addresses = set()

        # Read unsigned immediate and, if within an executable section, add
        # it in the set of target addresses.
        displacement = self.get_unsigned_immediate()
        if self.disassembler.is_memory_executable(displacement):
            target_addresses.add(displacement)

        # Now look for memory operands whose displacement points to a loaded
        # section. This might be the start of an array of pointers to the
        # code segment.
        for i in range(self.get_number_of_memory_operands()):
            displacement = self.get_memory_displacement(i)

            # The memory displacement should point to a loaded section.
            if self.disassembler.is_memory_loaded(displacement):

                # Figure out the length of each element in the array.
                length = self.get_memory_operand_length(i)

                # Translate element length to `struct.unpack()' format.
                fmt = {
                    1: 'B', 2: 'H', 4: 'I', 6: '=HI', 8: 'Q', 10: '=HQ'
                }[length]

                # Keep reading possible target addresses until there no more
                # data to read or a value outside any executable section is
                # read.
                while True:
                    data = self.disassembler.read_memory(displacement, length)
                    if data is None:
                        break

                    target_address = long(struct.unpack(fmt, data)[-1])
                    if not self.disassembler.is_memory_executable(target_address):
                        break

                    target_addresses.add(target_address)
                    displacement += length

        return target_addresses


    def get_call_target_addresses(self):
        '''
        Returns the set of absolute target addresses of a `call' instruction.
        '''

        target_addresses = set()

        iform = self.get_iform()

        if self.get_attribute(pyxed.XED_ATTRIBUTE_FAR_XFER):
            if iform == pyxed.XED_IFORM_CALL_FAR_MEMp2:
                # XXX: Not tested!
                target_addresses = self.get_indirect_code_refs()

            # Direct far call with 48-bit pointer operand.
            elif iform == pyxed.XED_IFORM_CALL_FAR_PTRp_IMMw:
                # XXX: Ignore possible change in code segment?
                target_addresses.add(self.get_branch_displacement())

            else:
                raise RuntimeError('Unknown far call instruction form "%s"' % \
                    self.dump_intel_format())
        else:
            # Direct `call' with relative displacement.
            if iform in [pyxed.XED_IFORM_CALL_NEAR_RELBRz,
                    pyxed.XED_IFORM_CALL_NEAR_RELBRd]:

                displacement = self.get_branch_displacement()

                # Displacement is a signed 32-bit integer, even in long mode.
                displacement = -(displacement & 0x80000000) + \
                    (displacement & 0x7fffffff)

                # Compute absolute target address.
                displacement += self.runtime_address + self.get_length()
                target_addresses.add(displacement)

            # Indirect `call' with memory operand.
            elif iform == pyxed.XED_IFORM_CALL_NEAR_MEMv:
                target_addresses = self.get_indirect_code_refs()

            # Indirect `call' with register operand; do nothing for now.
            elif iform == pyxed.XED_IFORM_CALL_NEAR_GPRv:
                pass

            else:
                raise RuntimeError('Unknown near call instruction form "%s"' % \
                    self.dump_intel_format())

        return target_addresses


    def get_branch_target_addresses(self):
        '''
        Returns the set of absolute target addresses of a conditional and an
        unconditional branch instruction.
        '''

        target_addresses = set()

        iform = self.get_iform()

        if self.get_attribute(pyxed.XED_ATTRIBUTE_FAR_XFER):
            if iform == pyxed.XED_IFORM_JMP_MEMp2:
                # XXX: Not tested!
                target_addresses = self.get_indirect_code_refs()

            # Direct far branch with 48-bit pointer operand.
            elif iform == pyxed.XED_IFORM_JMP_FAR_PTRp_IMMw:
                # XXX: Ignore possible change in code segment?
                target_addresses.add(self.get_branch_displacement())

            else:
                raise RuntimeError('Unknown far branch instruction form')
        else:
            # Indirect branch with register.
            if iform == pyxed.XED_IFORM_JMP_GPRv:
                pass

            # Indirect branch with memory operand.
            elif iform == pyxed.XED_IFORM_JMP_MEMv:
                target_addresses = self.get_indirect_code_refs()

            # Direct branch with displacement.
            else:
                displacement = self.get_branch_displacement()

                # Displacement is a signed 32-bit integer, even in long mode.
                displacement = -(displacement & 0x80000000) + \
                    (displacement & 0x7fffffff)
                displacement += self.runtime_address + self.get_length()
                target_addresses.add(displacement)

        return target_addresses


    def get_next_instruction_address(self):
        '''
        Returns the absolute address of the instruction immediately following
        the current one.
        '''
        return self.runtime_address + self.get_length()



    def get_code_refs(self):
        '''Returns a list of code references from the current instruction.'''

        code_refs = set()
        code_refs.update(self.get_call_target_addresses())
        code_refs.update(self.get_branch_target_addresseses())
        code_refs.update(self.get_next_instruction_addresses())
        code_refs.update(self.get_indirect_code_refs())
        return code_refs

    def get_data_refs(self):
        '''Return a set of data references from the current instruction.'''

        data_refs = set()
        for i in range(self.get_number_of_memory_operands()):
            displacement = self.get_memory_displacement(i)
            if self.disassembler.is_memory_readable(displacement):
                data_refs.add(displacement)

        return data_refs


    def get_read_registers(self):
        '''Returns the set of registers read by this instruction.'''

        read_registers = set()
        for i in range(self.get_noperands()):
            operand = self.get_operand(i)
            if operand.is_register() and operand.is_read():
                read_registers.add(self.get_reg(operand.get_name()))
        return read_registers


    def get_written_registers(self):
        '''Returns the set of registers written by this instruction.'''

        written_registers = set()
        for i in range(self.get_noperands()):
            operand = self.get_operand(i)
            if operand.is_register() and operand.is_written():
                written_registers.add(self.get_reg(operand.get_name()))
        return written_registers

