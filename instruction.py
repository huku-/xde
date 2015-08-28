#!/usr/bin/env python
'''instruction.py - Wrapper class for disassembled instructions.'''

__author__ = 'huku <huku@grhack.net>'


import xde.xrefs as xrefs

import pyxed


class Instruction(object):
    '''
    Wraps a `pyxed.Instruction' object to offer more functionality. Implements
    the "delegate" design pattern.
    '''

    def __init__(self, instruction, disassembler):

        # Wrapped delegate `pyxed.Instruction' object should be private.
        self._instruction = instruction

        # Owning disassembler object should also be private.
        self._disassembler = disassembler


    def __getattr__(self, name):
        '''
        When an attribute is not found here, look for it in `pyxed.Instruction'.
        This function is the actual delegation link.
        '''
        return getattr(self._instruction, name)

    def __str__(self):
        return '<Instruction 0x%x>' % self.runtime_address

    def __hash__(self):
        return self.runtime_address


    def _get_indirect_xrefs(self):
        '''
        Resolve indirect code and data cross references. Returns `XRef' instance.
        '''

        # Initialize empty set of cross references.
        xr = xrefs.XRefs()

        # Read instruction's unsigned immediate. If it looks like an executable
        # memory address, add it in the set of code cross references. If it
        # looks like a readable address, mark it as a data cross reference of
        # unknown size (hence the 0).
        if self.get_immediate_width() > 0:
            displacement = self.get_unsigned_immediate()
            if self._disassembler.is_memory_executable(displacement):
                xr.code.add(displacement)
            elif self._disassembler.is_memory_mapped(displacement):
                xr.data.add((displacement, 0))

        # Now traverse the list of memory operands.
        for i in range(self.get_number_of_memory_operands()):
            displacement = self.get_memory_displacement(i)

            # The memory displacement should point to a loaded section.
            if self._disassembler.is_memory_mapped(displacement):

                # Figure out the length of each element in the array.
                length = self.get_memory_operand_length(i)

                # Add entry in data cross references set.
                xr.data.add((displacement, length))

        return xr


    def _get_call_xrefs(self):
        '''
        Resolve code and data cross references of a `call' instruction. Returns
        `XRef' instance.
        '''

        # Initialize empty set of cross references.
        xr = xrefs.XRefs()

        iform = self.get_iform()

        if self.get_attribute(pyxed.XED_ATTRIBUTE_FAR_XFER):
            if iform == pyxed.XED_IFORM_CALL_FAR_MEMp2:
                # Compute union with indirect cross references.
                # XXX: Not tested!
                xr += self._get_indirect_xrefs()

            # Direct far call with 48-bit pointer operand.
            elif iform == pyxed.XED_IFORM_CALL_FAR_PTRp_IMMw:
                # Add branch displacement in code cross references set.
                # XXX: Ignore possible change in code segment?
                xr.code.add(self.get_branch_displacement())

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

                # Compute absolute target address and add in set of code cross
                # references.
                displacement += self.runtime_address + self.get_length()
                xr.code.add(displacement)

            # Indirect `call' with memory operand.
            elif iform == pyxed.XED_IFORM_CALL_NEAR_MEMv:
                # Compute union with indirect cross references.
                xr += self._get_indirect_xrefs()

            # Indirect `call' with register operand; do nothing for now.
            elif iform == pyxed.XED_IFORM_CALL_NEAR_GPRv:
                pass

            else:
                raise RuntimeError('Unknown near call instruction form "%s"' % \
                    self.dump_intel_format())

        return xr


    def _get_branch_xrefs(self):
        '''
        Resolve code and data cross refereces of a branch instruction. Returns
        `XRef' instance.
        '''

        # Initialize empty set of cross references.
        xr = xrefs.XRefs()

        iform = self.get_iform()

        if self.get_attribute(pyxed.XED_ATTRIBUTE_FAR_XFER):
            if iform == pyxed.XED_IFORM_JMP_MEMp2:
                # Compute union with indirect cross references.
                # XXX: Not tested!
                xr += self._get_indirect_xrefs()

            # Direct far branch with 48-bit pointer operand.
            elif iform == pyxed.XED_IFORM_JMP_FAR_PTRp_IMMw:
                # Add branch displacement in code cross references set.
                # XXX: Ignore possible change in code segment?
                xr.code.add(self.get_branch_displacement())

            else:
                raise RuntimeError('Unknown far branch instruction form')
        else:
            # Indirect branch with register.
            if iform == pyxed.XED_IFORM_JMP_GPRv:
                pass

            # Indirect branch with memory operand.
            elif iform == pyxed.XED_IFORM_JMP_MEMv:
                # Compute union with indirect cross references.
                xr += self._get_indirect_xrefs()

            # Direct branch with displacement.
            else:
                displacement = self.get_branch_displacement()

                # Displacement is a signed 32-bit integer, even in long mode.
                displacement = -(displacement & 0x80000000) + \
                    (displacement & 0x7fffffff)

                # Compute absolute target address and add in set of code cross
                # references.
                displacement += self.runtime_address + self.get_length()
                xr.code.add(displacement)

        return xr


    def get_next_instruction_address(self):
        '''
        Returns the absolute address of the instruction immediately following
        the current one.
        '''
        return self.runtime_address + self.get_length()


    def get_xrefs(self):
        '''Resolve instruction cross references. Returns `XRefs()' instance.'''

        # Initialize empty set of cross references.
        xr = xrefs.XRefs()

        category = self.get_category()

        # Handle `call' instructions.
        if category == pyxed.XED_CATEGORY_CALL:
            xr += self._get_call_xrefs()

        # Handle conditional and unconditional branch instructions.
        elif category in [pyxed.XED_CATEGORY_COND_BR,
                pyxed.XED_CATEGORY_UNCOND_BR]:
            xr += self._get_branch_xrefs()

        # Handle any other case.
        else:
            xr += self._get_indirect_xrefs()

        # Don't add next instruction in code cross references. IDA does that and
        # it's pretty annoying.
        #
        # xr.code.add(self.get_next_instruction_addresses())
        return xr


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

