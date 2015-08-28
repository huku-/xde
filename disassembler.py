#!/usr/bin/env python
'''disassembler.py - Main class for analyzing executable code.'''

__author__ = 'huku <huku@grhack.net>'


import struct

import xde.cpu as cpu
import xde.simple_graph as simple_graph
import xde.instruction as instruction
import xde.basic_block as basic_block

import sex_loader
import pyxed


# Maps memory operand sizes to `struct.unpack()' format strings.
_FMT_MAP = {1: 'B', 2: 'H', 4: 'I', 6: '=HI', 8: 'Q', 10: '=HQ'}


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

        # Map of instructions (`instruction.Instruction' objects) to their cross
        # references (`xrefs.XRefs' objects).
        self._xrefs = {}

        # Initialize set of basic block leaders.
        self._leaders = set()

        # Set of tuples holding address/size pairs pointing to data sections.
        # Kinda like the basic block leaders set, but for data accesses instead
        # of code.
        self._data_leaders = set()

        # Initialize dictionary of basic blocks. Maps basic block start address
        # to `BasicBlock' instance.
        self.basic_blocks = {}

        # Initialize set of function entry points.
        self.functions = set()

        # Initialize CFG.
        self.cfg = simple_graph.SimpleGraph()


    def __str__(self):
        return '<Disassembler %s %s>' % (str(self.cpu), str(self.loader))



    def is_memory_executable(self, address):
        '''Return true if `address' lies in an executable section.'''

        ret = False
        for section in self._executable_sections:
            if section.start_address <= address < section.end_address:
                ret = True
                break

        return ret


    def is_memory_readable(self, address):
        '''Return true if `address' lies in a data section.'''

        ret = False
        for section in self._data_sections:
            if section.start_address <= address < section.end_address:
                ret = True
                break

        return ret


    def is_memory_mapped(self, address):
        '''Return true if `address' lies in any loaded section.'''

        ret = False
        for section in self._loaded_sections:
            if section.start_address <= address < section.end_address:
                ret = True
                break

        return ret


    def read_memory(self, address, size):
        '''Read `size' bytes from memory address `address'.'''
        return self.loader.read(address, size)



    def _get_leaders_and_functions(self, section):
        '''
        Build set of basic block leaders, set of data leaders, set of function
        entry points and a first version of the CFG.
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
            # append the instruction in the list of instructions.
            insn = instruction.Instruction(insn, self)
            self._instructions.append(insn)

            # Get instruction's cross references set.
            xrefs = insn.get_xrefs()
            self._xrefs[insn] = xrefs

            category = insn.get_category()

            # Hadle `call' instructions.
            if category == pyxed.XED_CATEGORY_CALL:

                if len(xrefs.code):
                    # Notice that instructions following a `call' belong to the
                    # same basic block with the `call'; don't add `next_address'
                    # in `leaders'; we only need it to to detect PIC tricks (see
                    # following comment).
                    next_address = insn.get_next_instruction_address()

                    # Some compilers (e.g. LLVM) emit `call' instructions whose
                    # target address is the instruction immediately following
                    # the `call', usually a `pop'. This is a very common pattern
                    # for PIC code, which is used to read the current value of
                    # the program counter. In an attempt to be compatible with
                    # IDA Pro, don't mark the target address as a leader.
                    if len(xrefs.code) > 1 or \
                            next_address not in xrefs.code:
                        self._leaders.update(xrefs.code)

                        # Target addresses are also function entry points.
                        self.functions.update(xrefs.code)

                # Update set of data leaders.
                self._data_leaders.update(xrefs.data)


            # Handle `ret' instructions.
            elif category == pyxed.XED_CATEGORY_RET:

                # Next instruction is a basic block leader.
                next_address = insn.get_next_instruction_address()
                self._leaders.add(next_address)


            # Handle conditional and unconditional branch instructions.
            elif category in [pyxed.XED_CATEGORY_COND_BR,
                    pyxed.XED_CATEGORY_UNCOND_BR]:

                # Branch targets mark the beginning of new basic blocks.
                if len(xrefs.code):
                    self._leaders.update(xrefs.code)

                    for address in xrefs.code:
                        # Ignore possible tail call optimizations.
                        if address not in self.functions:
                            self.cfg.add_edge((insn.runtime_address, address))

                # Next instruction also marks a new basic block.
                next_address = insn.get_next_instruction_address()
                self._leaders.add(next_address)

                # Add CFG link to next address only for conditional branches.
                if category == pyxed.XED_CATEGORY_COND_BR:
                    self.cfg.add_edge((insn.runtime_address, next_address))

                # Update set of data leaders.
                self._data_leaders.update(xrefs.data)


            else:
                # If the instruction category does not belong to one of the
                # categories handled above, but yet it modifies the program
                # counter, raise a runtime error.
                written_registers = insn.get_written_registers()
                if program_counter_name in written_registers:
                    raise RuntimeError('Unknown control flow instruction "%s"' % \
                        insn.dump_intel_format())

                # Instructions that don't modify the program counter may have
                # indirect references to code. Consider the case of a `push'
                # pushing a function pointer on the stack.
                if len(xrefs.code):
                    self._leaders.update(xrefs.code)

                    # XXX: For now, assume they are functions, but we have to
                    # verify later.
                    self.functions.update(xrefs.code)

                # Update set of data leaders.
                self._data_leaders.update(xrefs.data)


    def _get_indirect_leaders_and_functions(self):
        '''
        Analyze control flow instructions with memory operands to data sections
        for possible basic block leaders and functions.
        '''

        # Sort set of data leaders by address and convert to a list.
        self._data_leaders = sorted(self._data_leaders)

        # Keep a reference to the program counter register name.
        program_counter_name = self.cpu.get_program_counter_name()

        for insn in self._instructions:
            # Look for instructions that can affect the control flow.
            if program_counter_name in insn.get_written_registers():

                category = insn.get_category()

                # Get instruction's cross references set.
                xrefs = self._xrefs[insn]

                # Iterate through instruction's data references.
                for address, size in xrefs.data:

                    # Locate next address greater than `address'.
                    right = len(self._data_leaders) - 1
                    left = 0
                    while left < right - 1:
                        i = (left + right) / 2
                        next_address, _ = self._data_leaders[i]
                        if address < next_address:
                            right = i
                        elif address >= next_address:
                            left = i

                    # Locate data reference's target section.
                    for section in self._data_sections:
                        if section.start_address <= address < section.end_address:
                            break

                    # Since there are no other data references made in the range
                    # from `address' to `next_address', this indirect branch may
                    # point to a series of pointers to executable memory (e.g. a
                    # virtual function table).
                    fmt = _FMT_MAP[size]
                    while address < min(next_address, section.end_address):

                        # Extract possible target address.
                        data = self.read_memory(address, size)
                        target_address = long(struct.unpack(fmt, data)[0])

                        if self.is_memory_executable(target_address):

                            # Add in basic block leaders.
                            self._leaders.add(target_address)

                            # If this is an indirect `call', add target address
                            # in functions set.
                            if category == pyxed.XED_CATEGORY_CALL:
                                self.functions.add(target_address)

                            # Else if not tail call optimized jump, add CFG link.
                            elif target_address not in self.functions:
                                self.cfg.add_edge((insn.runtime_address, \
                                    target_address))

                        address += size

            # Empty cross references map, we don't need it any more.
            del self._xrefs[insn]


    def _get_basic_blocks_and_cfg(self):
        '''Build basic block set and final version of the CFG.'''

        # Convert basic block leaders set to list and sort by address in
        # descending order.
        self._leaders = sorted(self._leaders, reverse=True)

        # Sort instructions by address in descending order.
        self._instructions = sorted(self._instructions, \
            key=lambda insn: insn.runtime_address, reverse=True)

        # Build basic block set.
        start_address = self._leaders.pop()
        while len(self._leaders):
            end_address = self._leaders.pop()

            # Populate basic block's instruction list.
            instructions = []
            while len(self._instructions):
                insn = self._instructions[-1]
                if start_address <= insn.runtime_address < end_address:
                    instructions.append(self._instructions.pop())
                else:
                    break

            if len(instructions):
                # Construct basic block object.
                block = basic_block.BasicBlock(start_address, end_address,
                    instructions)

                # Map basic block start address to basic block object.
                self.basic_blocks[start_address] = block

            start_address = end_address


        # Now construct the final version of the CFG.
        cfg = simple_graph.SimpleGraph()

        # Populate CFG with basic block links.
        for block in self.basic_blocks.values():

            # Get basic block's last instruction (this might be a branch).
            insn = block.instructions[-1]

            address = insn.runtime_address
            category = insn.get_category()

            # Create a shallow copy of the outgoing links set; `self.cfg' is
            # modified in the following loop.
            target_addresses = self.cfg.outgoing[address].copy()

            # If there are outgoing links from basic block's last instruction to
            # other instructions, create the corresponding CFG links.
            if len(target_addresses):
                for target_address in target_addresses:
                    # Do not add edges for tail call optimized jumps.
                    if target_address not in self.functions:
                        cfg.add_edge((block, self.basic_blocks[target_address]))
                    self.cfg.del_edge((address, target_address))

            # No outgoing links from basic block's last instruction. Execution
            # continues to the basic block physically bordering the current one
            # unless the latter ends with a `ret'.
            elif category != pyxed.XED_CATEGORY_RET:
                target_address = block.end_address

                # Do not add edges for tail call optimized jumps.
                if target_address not in self.functions and \
                        target_address in self.basic_blocks:
                    cfg.add_edge((block, self.basic_blocks[target_address]))
                self.cfg.del_edge((address, target_address))

        # Replace instance's CFG.
        self.cfg = cfg


    def analyze(self):
        '''Start code analysis.'''

        # Build leaders set from executable sections.
        for section in self._executable_sections:
            self._get_leaders_and_functions(section)
        self._get_indirect_leaders_and_functions()

        # Build basic block set.
        self._get_basic_blocks_and_cfg()


    def get_function_basic_blocks(self, address):
        '''Return a list of basic blocks for function at address `address'.'''

        basic_blocks = []

        if address in self.functions:

            # Map of basic blocks to boolean values.
            visited = {}

            # DFS stack of basic blocks.
            stack = [self.basic_blocks[address]]

            while len(stack):
                block = stack.pop()

                # Mark basic block as visited.
                if block not in visited:
                    basic_blocks.append(block)
                    visited[block] = True

                # Push basic blocks that have not been visited yet.
                stack += [b for b in self.cfg.outgoing[block] \
                    if b not in visited]

        return basic_blocks

