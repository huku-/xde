#!/usr/bin/env python
'''disassembler.py - Main class for analyzing executable code.'''

__author__ = 'huku <huku@grhack.net>'


import pyxed

import cpu
import sex_loader
import simple_graph
import instruction
import basic_block


class Disassembler(object):
    '''Main class that performs analysis of assembly code.'''

    def __init__(self, project_dir):

        # Load project created by "sex.sh".
        self.loader = sex_loader.SexLoader(project_dir)

        # Build list of executable and data sections.
        self._loaded_sections = []
        self._executable_sections = []
        self._data_sections = []
        for section in self.loader.sections:
            if 'l' in section.flags:
                self._loaded_sections.append(section)
                if 'x' in section.flags:
                    self._executable_sections.append(section)
                elif 'r' in section.flags:
                    self._data_sections.append(section)

        # Determine the CPU of the target executable.
        if self.loader.arch == 'i386':
            self.cpu = cpu.CPU(cpu.X86_MODE_PROTECTED_32BIT)
        elif self.loader.arch == 'x86_64':
            self.cpu = cpu.CPU(cpu.X86_MODE_PROTECTED_64BIT)

        # Initialize `pyxed' based decoder object.
        self.decoder = pyxed.Decoder()
        if self.cpu.mode == cpu.X86_MODE_REAL:
            self.decoder.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_16,
                pyxed.XED_ADDRESS_WIDTH_16b)
        elif self.cpu.mode == cpu.X86_MODE_PROTECTED_32BIT:
            self.decoder.set_mode(pyxed.XED_MACHINE_MODE_LEGACY_32,
                pyxed.XED_ADDRESS_WIDTH_32b)
        elif self.cpu.mode == cpu.X86_MODE_PROTECTED_64BIT:
            self.decoder.set_mode(pyxed.XED_MACHINE_MODE_LONG_64,
                pyxed.XED_ADDRESS_WIDTH_64b)

        # Initialize list of instructions.
        self._instructions = []

        # Initialize set of basic block leaders.
        self._leaders = set()

        # Initialize dictionary of basic blocks. Maps basic block start address
        # to `BasicBlock' instance.
        #
        # XXX: I don't really like this. It's a temporary solution.
        self.basic_blocks = {}

        # Initialize set of function entry points.
        self.functions = set()

        # Initialize set of data references.
        self.data_refs = set()

        # Initialize CFG.
        self.cfg = simple_graph.SimpleGraph()


    def __str__(self):
        return '<Disassembler %s %s>' % (str(self.cpu), str(self.loader))



    def is_memory_executable(self, address):
        '''Return true if `address' lies in an executable section.'''
        for section in self._executable_sections:
            if address >= section.start_address and address < section.end_address:
                return True
        return False

    def is_memory_readable(self, address):
        '''Return true if `address' lies in a data section.'''
        for section in self._data_sections:
            if address >= section.start_address and address < section.end_address:
                return True
        return False

    def is_memory_loaded(self, address):
        '''Return true if `address' lies in any loaded section.'''
        for section in self._loaded_sections:
            if address >= section.start_address and address < section.end_address:
                return True
        return False

    def read_memory(self, address, size):
        '''Read `size' bytes from memory address `address'.'''
        return self.loader.read(address, size)



    def _get_leaders_and_functions(self, section):
        '''
        Build set of basic block leaders, set of function entry points and a
        first version of the CFG.
        '''

        # Initialize decoder input.
        self.decoder.itext = section.data
        self.decoder.itext_offset = 0
        self.decoder.runtime_address = section.start_address

        # Program entry point is the leader of the very first basic block.
        self._leaders.add(self.decoder.runtime_address)

        # Keep a reference to the program counter register name.
        program_counter_name = self.cpu.get_program_counter_name()

        while True:
            # Decode until the end of the instruction stream is reached.
            try:
                insn = self.decoder.decode()
            except pyxed.InvalidInstructionError:
                insn = None
            except pyxed.InvalidOffsetError:
                insn = None

            if insn is None:
                break

            # Wrap `pyxed.Instruction' into an `instruction.Instruction' and
            # append the instruction address in the list of instructions.
            insn = instruction.Instruction(insn, self)
            self._instructions.append(insn.runtime_address)

            # Update set of data references.
            self.data_refs.update(insn.get_data_refs())

            category = insn.get_category()

            # Hadle `call' instructions.
            if category == pyxed.XED_CATEGORY_CALL:
                target_addresses = insn.get_call_target_addresses()

                if len(target_addresses):
                    # Notice that instructions following a `call' belong to the
                    # same basic block with the `call'; don't add `next_address'
                    # in `leaders'; we only need it to to detect PIC tricks (see
                    # following comment).
                    next_address = insn.get_next_instruction_address()

                    # Some compilers (e.g. LLVM) emit `call' instructions whose
                    # target address is the instruction immediatelly following
                    # the `call', usually a `pop'. This is a very common pattern
                    # for PIC code, which is used to read the current value of
                    # the program counter. In an attempt to be compatible with
                    # IDA Pro, don't mark the target address as a leader.
                    if len(target_addresses) > 1 or \
                            next_address not in target_addresses:
                        self._leaders.update(target_addresses)

                        # Target addresses are also function entry points.
                        self.functions.update(target_addresses)


            # Handle `ret' instructions.
            elif category == pyxed.XED_CATEGORY_RET:

                # Next instruction is a basic block leader.
                next_address = insn.get_next_instruction_address()
                self._leaders.add(next_address)


            # Handle conditional and unconditional branch instructions.
            elif category in [pyxed.XED_CATEGORY_COND_BR,
                    pyxed.XED_CATEGORY_UNCOND_BR]:

                # Branch targets mark the beginning of new basic blocks.
                target_addresses = insn.get_branch_target_addresses()
                if len(target_addresses):
                    self._leaders.update(target_addresses)

                    for target_address in target_addresses:
                        self.cfg.add_edge((insn.runtime_address, target_address))

                # Next instruction also marks a new basic block.
                next_address = insn.get_next_instruction_address()
                self._leaders.add(next_address)

                self.cfg.add_edge((insn.runtime_address, next_address))


            else:
                # If the instruction category does not belong to one of the
                # categories handled above, but yet it modifies the program
                # counter, raise a runtime error.
                written_registers = insn.get_written_registers()
                if program_counter_name in written_registers:
                    raise RuntimeError('Unknown control flow instruction "%s"' % \
                        insn.dump_intel_format())

                # Get set of possible indirect code references.
                target_addresses = insn.get_indirect_code_refs()
                if len(target_addresses) > 0:
                    self._leaders.update(target_addresses)

                    # XXX: For now, assume they are functions but we have to
                    # verify later.
                    self.functions.update(target_addresses)


    def _get_basic_blocks_and_cfg(self):
        '''Build basic block set and final version of the CFG.'''

        self._leaders = sorted(self._leaders, reverse=True)
        self._instructions = sorted(self._instructions, reverse=True)

        # Build basic block set.
        start_address = self._leaders.pop()
        while len(self._leaders):
            end_address = self._leaders.pop()

            # Populate basic block's instruction list.
            block = basic_block.BasicBlock()
            while len(self._instructions) and \
                    start_address <= self._instructions[-1] < end_address:
                block.instructions.append(self._instructions.pop())

            if len(block.instructions):
                # Map basic block start address to basic block object.
                self.basic_blocks[start_address] = block

            start_address = end_address


        # Now construct the final version of the CFG.
        cfg = simple_graph.SimpleGraph()

        for block in self.basic_blocks.values():

            # Get basic block's last instruction (this is a branch).
            last_address = block.instructions[-1]

            # Create a shallow copy of the outgoing links set; `self.cfg' is
            # modified in the following loop.
            target_addresses = self.cfg.outgoing[last_address].copy()
            for target_address in target_addresses:
                cfg.add_edge((block, self.basic_blocks[target_address]))
                self.cfg.del_edge((last_address, target_address))

        # Replace instance's CFG.
        self.cfg = cfg


    def analyze(self):
        '''Start code analysis.'''

        # Build leaders set from executable sections.
        for section in self._executable_sections:
            self._get_leaders_and_functions(section)

        # Build basic block set.
        self._get_basic_blocks_and_cfg()

        # Sort data references in ascending address order.
        self.data_refs = sorted(self.data_refs)

