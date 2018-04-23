#!/usr/bin/env python
'''
:mod:`disassembler` - Main class for disassembling S.EX. projects
=================================================================

.. module: disassembler
   :platform: Unix, Windows
   :synopsis: Main class for disassembling S.EX. projects
.. moduleauthor:: huku <huku@grhack.net>


About
-----
This is the class responsible for disassembling x86 and x86_64 code. It was
designed to be as abstract and as hack-less as possible. Hopefully, people
interested in designing disassemblers will benefit from studying this code.

The constructor of :class:`Disassembler`, analyzed below, takes the directory
where the S.EX. [1] project to be analyzed is located. Several external memory
data structures will be stored at this location:

* **shadow** -- An :class:`em_shadow_memory.EMShadowMemory` instance mapping
  program addresses to properties (integers).

* **code_xrefs** -- An :class:`em_graph.EMGraph` instance mapping instruction
  addresses to sets of other instruction addresses referenced from them.

* **data_xrefs** -- An :class:`em_graph.EMGraph` instance mapping instruction
  addresses to sets of data locations referenced from them.

* **basic_blocks** -- A ``pyrsistence.EMDict`` [2] instance mapping basic block
  addresses to the corresponding :class:`basic_block.BasicBlock` instances.

* **cfg** -- An :class:`em_graph.EMGraph` instance holding the program's CFG.

[1] https://github.com/huku-/sex

[2] https://github.com/huku-/pyrsistence


Classes
-------
'''

__author__ = 'huku <huku@grhack.net>'


import sys
import struct
import time


try:
    import sex
except ImportError:
    sys.exit('S.EX. not installed?')

try:
    import pyxed
except ImportError:
    sys.exit('Pyxed not installed?')

try:
    import pyrsistence
except ImportError:
    sys.exit('Pyrsistence not installed?')


import cpu
import instruction
import basic_block
import em_shadow_memory
import em_graph
import classifiers


DEBUG = True


def _msg(message):
    '''
    Display a formatted message if :data:`DEBUG` is true.

    :param message: The message to display.
    '''

    if DEBUG:
        print '(%s) [*] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), message)


class Disassembler(object):
    '''
    Main class that performs disassembly of x86 and x86_64 code.

    .. automethod:: __init__
    .. automethod:: _analyze_normal_instruction_memory_operands
    .. automethod:: _disassemble_normal_instruction
    .. automethod:: _get_jump_table_element
    .. automethod:: _analyze_flow_control_instruction_memory_operand
    .. automethod:: _analyze_flow_control_instruction_memory_operands
    .. automethod:: _disassemble_unconditional_jump_instruction
    .. automethod:: _disassemble_conditional_jump_instruction
    .. automethod:: _disassemble_call_instruction
    .. automethod:: _disassemble_flow_control_instruction
    .. automethod:: _disassemble_instruction
    .. automethod:: _do_recursive_disassembly
    .. automethod:: _do_linear_sweep_disassembly
    .. automethod:: _is_code
    .. automethod:: _disassemble_entry_points
    .. automethod:: _disassemble_functions
    .. automethod:: _disassemble_relocated
    .. automethod:: _disassemble_deferred
    .. automethod:: _disassemble_orphan
    .. automethod:: _build_basic_block_set_for_range
    .. automethod:: _build_basic_block_set
    .. automethod:: _build_cfg
    .. automethod:: _analyze_relocation
    .. automethod:: _analyze_relocations
    '''

    def __init__(self, dirname):
        '''
        :param dirname: Path to directory that holds the S.EX. project to be
            analyzed. Several external memory data structures will be stored in
            this directory.
        '''

        _msg('Initializing disassembler for S.EX. project "%s"' % dirname)

        # Load project created by "sex.sh".
        self.loader = sex.sex_loader.SexLoader(dirname)

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

        # Initialize external memory list holding program's shadow memory.
        # Remember that the section array is sorted by address.
        self.shadow = em_shadow_memory.EMShadowMemory('%s/shadow' % dirname,
           [(s.start_address, s.end_address) for s in self.loader.sections])

        # Initialize graph of code cross references. Maps instruction addresses
        # to sets of referenced instruction addresses.
        self.code_xrefs = em_graph.EMGraph('%s/code_xrefs' % dirname)

        # Initialize graph of data cross references. Maps instruction addresses
        # to sets of referenced data addresses.
        self.data_xrefs = em_graph.EMGraph('%s/data_xrefs' % dirname)

        # Initialize dictionary of basic blocks. Maps basic block start addresses
        # to corresponding `BasicBlock' instances.
        self.basic_blocks = pyrsistence.EMDict('%s/basic_blocks' % dirname)

        # Initialize intra-procedural CFG. Maps basic block addresses to sets of
        # children basic block addresses.
        self.cfg = em_graph.EMGraph('%s/cfg' % dirname)


    def __del__(self):
        '''Wrapper around :func:`close()`.'''
        self.close()


    def __str__(self):
        return '<Disassembler %s %s>' % (str(self.cpu), str(self.loader))



    def _analyze_normal_instruction_memory_operands(self, insn):
        '''
        Analyze normal (i.e. not flow control) instruction memory operands and
        update the sets of code and data cross references accordingly.

        :param insn: Instruction object to be analyzed.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Get instruction's runtime address.
        runtime_address = insn.runtime_address

        # Traverse the list of memory operands of this instruction.
        for i in range(insn.get_number_of_memory_operands()):

            # Compute operand's asbolute memory displacement.
            displacement = insn.get_memory_displacement(i)
            if displacement and self.is_memory_mapped(displacement):

                # Add data cross reference for this memory displacement.
                self.data_xrefs.add_edge((runtime_address, displacement))

                # If memory operand's length is not one of the lengths used in
                # indirect branching instructions, mark it as data. Otherwise,
                # we can't be sure if the memory operand's address points to a
                # code or a data region. In this case, be conservative and do
                # nothing.
                length = insn.get_memory_operand_length(i)
                if length not in [4, 6, 8, 10]:
                    self.shadow.mark_as_analyzed(displacement, length)
                    self.shadow.mark_as_data(displacement, length)


    def _disassemble_normal_instruction(self, insn):
        '''
        Disassemble a normal (i.e. not flow control) instruction.

        :param insn: Instruction object to be analyzed.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Get instruction's runtime address.
        runtime_address = insn.runtime_address

        # Get the native address width given the current CPU mode.
        width_map = {
            cpu.X86_MODE_REAL: 16,
            cpu.X86_MODE_PROTECTED_32BIT: 32,
            cpu.X86_MODE_PROTECTED_64BIT: 64
        }
        width = width_map[self.cpu.mode]

        # If the instruction has an unsigned immediate, read it and check if it
        # looks like an address.
        if insn.get_immediate_width_bits() == width:

            # Get instruction's immediate value.
            immediate = insn.get_unsigned_immediate()

            # Immediate value looks like an executable memory address.
            if self.is_memory_executable(immediate):

                # True if the binary is relocatable.
                is_relocatable = len(self.loader.relocations) > 0

                # If the binary is relocatable and the immediate represents an
                # executable memory address, there should be a leaf relocation
                # entry for the address in question.
                if self.shadow.is_marked_as_relocated_leaf(immediate) or \
                        not is_relocatable:

                    # Last but not least, the immediate should represent an
                    # address of, what it looks like, executable code. If this
                    # is the case, update the data cross references set.
                    if self._is_code(immediate):
                        self.data_xrefs.add_edge((runtime_address, immediate))

        # Analyze any memory operands referenced by the instruction.
        self._analyze_normal_instruction_memory_operands(insn)

        # Execution flow continues to the next instruction, so, add it in the
        # set of code cross references.
        next_address = insn.get_next_instruction_address()
        self.code_xrefs.add_edge((runtime_address, next_address))


    def _get_jump_table_element(self, address, length):
        '''
        Unpack an element of *length* bytes from address *address* and attempt
        to determine if it's a jump table element or not.

        :param address: Address to unpack a jump table element from.
        :param length: Length of jump table element to unpack.
        :returns: The jump table element or ``None``
        :rtype: ``long``

        .. warning:: This is a private function, don't use it directly.
        '''

        r = None

        # Maps memory operand sizes of indirect flow control instructions to
        # format strings corresponding to the native address width.
        fmt_map = {
            4: 'I',     # 32-bit EIP
            6: '=HI',   # 48-bit pointer (CS+EIP for far branching)
            8: 'Q',     # 64-bit RIP
            10: '=HQ'   # 80-bit pointer (CS+RIP for far branching)
        }

        # Get memory operand's format (shouldn't throw an exception).
        fmt = fmt_map[length]

        # True if the binary is relocatable.
        is_relocatable = len(self.loader.relocations) > 0

        # If the binary is relocatable, the memory displacement should have been
        # marked as relocated.
        if self.shadow.is_marked_as_relocated(address) or not is_relocatable:

            # Unpack one element from memory.
            data = self.read_memory(address, length)
            element = long(struct.unpack(fmt, data)[-1])

            # If the binary is relocatable, the unpacked jump table element should
            # have been marked as relocatable leaf.
            if self.shadow.is_marked_as_relocated_leaf(element) or \
                    not is_relocatable:

                # Last but not least, the jump table element should point to an
                # executable memory address.
                if self.is_memory_executable(element):
                    r = element
        return r


    def _analyze_flow_control_instruction_memory_operand(self, insn, i):
        '''
        Analyze the *i*-th memory operand of a flow control instruction. The
        sets of code and data cross references are updated accordingly.

        :param insn: Instruction object whose memory operand will be analyzed.
        :param i: Index of memory operand of *insn* to be analyzed.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Get instruction's runtime address.
        runtime_address = insn.runtime_address

        # Get memory operand's attributes.
        index_reg = insn.get_index_reg(i)
        scale = insn.get_scale(i)
        displacement = insn.get_memory_displacement(i)
        length = insn.get_memory_operand_length(i)

        # Start unpacking elements from the given memory displacement to discover
        # possible jump table elements.
        while self.is_memory_mapped(displacement):

            # This is not a pointer to an imported symbol. Analyze possible jump
            # table element.
            if displacement not in self.loader.exit_points:

                # Attempt to read a jump table element.
                element = self._get_jump_table_element(displacement, length)

                # If no jump table element was recovered, break.
                if not element:
                    break

                # Add jump table element in code cross references and mark it as
                # a basic block leader.
                self.code_xrefs.add_edge((runtime_address, element))
                self.shadow.mark_as_basic_block_leader(element)

            # Looks like a pointer to an imported symbol, just add it in the set
            # of code cross references.
            else:
                self.code_xrefs.add_edge((runtime_address, displacement))

            # If we don't have an index register, there's only one element in
            # the jump table.
            if index_reg == pyxed.XED_REG_INVALID:
                break

            # Memory displacement should be increased by scale.
            displacement += scale


    def _analyze_flow_control_instruction_memory_operands(self, insn):
        '''
        Analyze the memory operands of a flow control instruction. The sets of
        code and data cross references are updated accordingly.

        :param insn: Instruction object whose memory operands will be analyzed.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Get instruction's runtime address.
        runtime_address = insn.runtime_address

        # Traverse the list of memory operands of this flow control instruction.
        for i in range(insn.get_number_of_memory_operands()):

            # Compute operand's absolute memory displacement.
            displacement = insn.get_memory_displacement(i)
            if displacement and self.is_memory_mapped(displacement):

                # Add data cross reference for this memory displacement.
                self.data_xrefs.add_edge((runtime_address, displacement))

                # Analyze memory operand in search of jump table elements.
                self._analyze_flow_control_instruction_memory_operand(insn, i)


    def _disassemble_unconditional_jump_instruction(self, insn):
        '''
        Disassemble unconditional jump instruction.

        :param insn: Instruction object to be analyzed.
        :raises RuntimeError: Raised when an unknown form of an unconditional
            jump instruction is encountered.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Get instruction's runtime address and form.
        runtime_address = insn.runtime_address
        iform = insn.get_iform()

        # Handle direct jumps with relative branch displacement.
        if iform in [pyxed.XED_IFORM_JMP_RELBRb, pyxed.XED_IFORM_JMP_RELBRd,
                pyxed.XED_IFORM_JMP_RELBRz]:

            # Mark jump target as basic block leader.
            displacement = insn.get_branch_displacement()
            if self.is_memory_executable(displacement):
                self.code_xrefs.add_edge((runtime_address, displacement))
                self.shadow.mark_as_basic_block_leader(displacement)

        # Handle indirect near and far jumps with memory operands.
        elif iform in [pyxed.XED_IFORM_JMP_MEMv, pyxed.XED_IFORM_JMP_FAR_MEMp2]:
            self._analyze_flow_control_instruction_memory_operands(insn)

        # We can't do anything for indirect jumps with register operand.
        elif iform == pyxed.XED_IFORM_JMP_GPRv:
            pass

        # Handle direct far jumps with 48-bit pointer operand.
        elif iform == pyxed.XED_IFORM_JMP_FAR_PTRp_IMMw:

            # Ignore possible change in segment.
            displacement = insn.get_branch_displacement()
            if self.is_memory_executable(displacement):
                self.code_xrefs.add_edge((runtime_address, displacement))
                self.shadow.mark_as_basic_block_leader(displacement)

        elif iform == pyxed.XED_IFORM_XABORT_IMMb:
            pass

        else:
            raise RuntimeError('Unknown unconditional jump form "%s"' % \
                insn.dump_intel_format())


    def _disassemble_conditional_jump_instruction(self, insn):
        '''
        Disassemble conditional jump instruction.

        :param insn: Instruction object to be analyzed.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Get instruction's runtime address and form.
        runtime_address = insn.runtime_address
        iform = insn.get_iform()

        # Conditional jump instructions, other than XEND, have a single operand
        # which is a relative branch displacement.
        if iform != pyxed.XED_IFORM_XEND:
            displacement = insn.get_branch_displacement()
            if self.is_memory_executable(displacement):
                edge = (runtime_address, displacement)
                self.code_xrefs.add_edge(edge)
                self.code_xrefs.add_edge_attribute(edge, 'predicate', True)
                self.shadow.mark_as_basic_block_leader(displacement)

        # Next instruction is also a basic block leader.
        next_address = insn.get_next_instruction_address()
        edge = (runtime_address, next_address)
        self.code_xrefs.add_edge(edge)
        self.code_xrefs.add_edge_attribute(edge, 'predicate', False)
        self.shadow.mark_as_basic_block_leader(next_address)


    def _disassemble_call_instruction(self, insn):
        '''
        Analyze a CALL instruction and update the sets of code and data cross
        references accordingly.

        :param insn: Instruction object to be analyzed.
        :raises RuntimeError: Raised when an unknown CALL instruction form is
            encountered.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Get instruction's runtime address and form.
        runtime_address = insn.runtime_address
        iform = insn.get_iform()

        # Handle direct near calls with relative branch displacement.
        if iform in [pyxed.XED_IFORM_CALL_NEAR_RELBRz,
                pyxed.XED_IFORM_CALL_NEAR_RELBRd]:

            # Calls to the immediately following instruction are used by several
            # compilers (e.g. LLVM) in PIC code for reading the value of the
            # program counter. In this case, the target address doesn't mark the
            # beginning of a function and it's not a basic block leader either.
            displacement = insn.get_branch_displacement()
            if displacement != insn.get_next_instruction_address() and \
                    self.is_memory_executable(displacement):

                # Otherwise, mark it as function.
                self.code_xrefs.add_edge((runtime_address, displacement))
                self.shadow.mark_as_function(displacement)

        # Handle indirect near and far calls with memory operands.
        elif iform in [pyxed.XED_IFORM_CALL_NEAR_MEMv,
                pyxed.XED_IFORM_CALL_FAR_MEMp2]:

            self._analyze_flow_control_instruction_memory_operands(insn)

            # Mark all callees as functions.
            for address in self.code_xrefs.get_successors(runtime_address):
                self.shadow.mark_as_function(address)

        # We can't do anything for indirect calls with register operand.
        elif iform == pyxed.XED_IFORM_CALL_NEAR_GPRv:
            pass

        # Handle direct far calls with 48-bit pointer operand.
        elif iform == pyxed.XED_IFORM_CALL_FAR_PTRp_IMMw:

            # Ignore possible change in segment.
            displacement = insn.get_branch_displacement()
            if self.is_memory_executable(displacement):
                self.shadow.mark_as_function(displacement)

        else:
            raise RuntimeError('Unknown call instruction form "%s"' % \
                insn.dump_intel_format())

        # Execution flow continues to the next instruction, so, add it in the
        # set of code cross references.
        next_address = insn.get_next_instruction_address()
        self.code_xrefs.add_edge((runtime_address, next_address))


    def _disassemble_flow_control_instruction(self, insn):
        '''
        Disassemble flow control instruction.

        :param insn: Instruction object to be analyzed.
        :raises RuntimeError: Raised when an unknown flow control instruction is
            encountered.

        .. warning:: This is a private function, don't use it directly.
        '''

        category = insn.get_category()

        if category == pyxed.XED_CATEGORY_CALL:
            self._disassemble_call_instruction(insn)

        elif category == pyxed.XED_CATEGORY_UNCOND_BR:
            self._disassemble_unconditional_jump_instruction(insn)

        elif category == pyxed.XED_CATEGORY_COND_BR:
            self._disassemble_conditional_jump_instruction(insn)

        elif category == pyxed.XED_CATEGORY_RET:
            pass

        elif category == pyxed.XED_CATEGORY_INTERRUPT:
            pass

        elif category == pyxed.XED_CATEGORY_SYSCALL:
            pass

        elif category == pyxed.XED_CATEGORY_SYSRET:
            pass

        else:
            raise RuntimeError('Unknown flow control instruction "%s"' % \
                insn.dump_intel_format())


    def _disassemble_instruction(self):
        '''
        Disassemble next instruction.

        :returns: Disassembled instruction object or ``None``.
        :rtype: :class:`instruction.Instruction`

        .. warning:: This is a private function, don't use it directly.
        '''

        insn = self.decoder.decode()
        if insn is not None:
            # print insn.dump_intel_format()

            # Wrap `pyxed.Instruction' into an `instruction.Instruction'.
            insn = instruction.Instruction(insn, self.cpu)

            # Distinguish between instructions that modify the program counter
            # and those that don't (referred to as "normal" here).
            written_registers = insn.get_written_registers()
            if self.cpu.get_program_counter_name() in written_registers:
                self._disassemble_flow_control_instruction(insn)
            else:
                self._disassemble_normal_instruction(insn)

            # Mark instruction address range as analyzed code.
            length = insn.get_length()
            runtime_address = insn.runtime_address
            self.shadow.mark_as_analyzed(runtime_address, length)
            self.shadow.mark_as_code(runtime_address, length)

        # Return the instruction object or `None'.
        return insn


    def _do_recursive_disassembly(self, address):
        '''
        Start recursive disassembly from instruction at address *address*. This
        function should be used only when *address* has been verified to be a
        valid code region. Each disassembled instruction is further analyzed and
        the sets of code and data cross references are updated accordingly.

        :param address: Address to start recursive disassembly from.

        .. warning:: This is a private function, don't use it directly.
        '''

        stack = [address]
        while len(stack):

            # Pop next address to disassemble from the stack.
            start_address = address = stack.pop()

            # Don't analyze regions already analyzed and skip code that transfers
            # control outside the executable.
            if self.shadow.is_marked_as_analyzed(address) or \
                    address in self.loader.exit_points:
                continue

            # Setup decoder's input.
            section = self.loader.get_section_for_address_range(address)
            self.decoder.itext = section.data
            self.decoder.itext_offset = address - section.start_address
            self.decoder.runtime_address = section.start_address

            # The following loop performs a linear sweep disassembly until an
            # instruction that unconditionally modifies the program counter is
            # hit, or an already analyzed region (data or code) is reached.
            error = False
            while True:
                try:
                    # Disassemble next instruction in stream and break when we
                    # reach the end of the section.
                    insn = self._disassemble_instruction()
                    if insn is None:
                        break

                    # Add unanalyzed code cross references from this instruction
                    # in stack for later analysis.
                    for address in self.code_xrefs.get_successors(insn.runtime_address):
                        if not self.shadow.is_marked_as_analyzed(address):
                            stack.append(address)

                    # If it unconditionally modifies the program counter, break.
                    if insn.get_category() in [pyxed.XED_CATEGORY_RET,
                            pyxed.XED_CATEGORY_UNCOND_BR]:
                        break

                    # If next instruction has already been analyzed, break.
                    address = insn.get_next_instruction_address()
                    if self.shadow.is_marked_as_analyzed(address):
                        break

                # If we hit an invalid instruction, chances are we attempted to
                # disassemble a data region within an executable section.
                except pyxed.InvalidInstructionError:
                    _msg('Invalid instruction at @%#x' % start_address)
                    error = True

                except pyxed.InvalidOffsetError:
                    error = True

            # If we have successfully disassembled linearly from `start_address'
            # without raising an exception, mark it as a basic block leader.
            if not error:
                self.shadow.mark_as_basic_block_leader(start_address)



    def _do_linear_sweep_disassembly(self, address):
        '''
        Starts a linear sweep disassembly from instruction at address *address*.
        This function is mainly used to verify that *address* marks, in fact,
        the beginning of a valid code region. Unlike its recursive counterpart,
        :func:`_do_recursive_disassembly()`, it doesn't perform any kind of
        further analysis and doesn't update the cross references sets. It only
        performs various sanity checks on the disassembled instruction stream.

        :param address: Address to start linear sweep disassembly from.
        :returns: ``True`` if *address* marks a valid code region, ``False``
            otherwise.
        :rtype: ``bool``

        .. warning:: This is a private function, don't use it directly.
        '''

        # Get section object for address `address'.
        section = self.loader.get_section_for_address_range(address)

        # Keep a reference to the decoder object.
        decoder = self.decoder

        # Save decoder's state.
        state = decoder.itext, decoder.itext_offset, decoder.runtime_address

        # Modify decoder's state.
        decoder.itext = section.data
        decoder.itext_offset = address - section.start_address
        decoder.runtime_address = section.start_address

        # List of disassembled instructions.
        insns = []

        error = False
        while True:

            # Disassemble next instruction in stream.
            try:
                insn = decoder.decode()
            except (pyxed.InvalidInstructionError, pyxed.InvalidOffsetError):
                error = True
                break

            # Reached end of instruction stream without errors.
            if insn is None:
                break

            # Make sure we have a valid instruction.
            category = insn.get_category()
            if category == pyxed.XED_CATEGORY_INVALID:
                error = True
                break

            # Add instruction in list of disassembled instructions.
            insn = instruction.Instruction(insn, self.cpu)
            insns.append(insn)
            # print insn.dump_intel_format()

            # Instruction bytes should not overlap with a data region, otherwise
            # this is an error.
            runtime_address = insn.runtime_address
            length = insn.get_length()
            if self.shadow.is_marked_as_data(runtime_address, length):
                error = True
                break

            # Branch displacement, if any, should point to executable memory or
            # we have an error.
            displacement = insn.get_branch_displacement()
            if displacement and not self.is_memory_executable(displacement):
                error = True
                break

            # Instruction modifies the program counter unconditionally, we don't
            # know what lies beyond. Stop linear sweep and break.
            if category in [pyxed.XED_CATEGORY_UNCOND_BR, pyxed.XED_CATEGORY_RET]:
                break

        # Restore decoder's state.
        decoder.itext, decoder.itext_offset, decoder.runtime_address = state

        # Use classification only if not error.
        if not error:
            # Instantiate classifier and set the error flag if not code.
            error = classifiers.classifier.Classifier().is_data(insns)

        # Return sucess if the error flag is not set.
        return not error


    def _is_code(self, address):
        '''
        Attempts to guess if address *address* holds executable code or data.
        This is the holy grail of all disassemblers, this is where heuristics
        for answering this question should be implemented. For now we just
        start a linear sweep disassembly from the address in question. If the
        disassembled stream ends with a RET or an unconditional branch, we
        assume the region holds executable code. A code/data classifier is also
        used to verify this claim before returning the verdict.

        I'm currently experimenting with more advanced methods involving Markov
        models and some trivial machine learning techniques.

        :param address: Address to check.
        :returns: ``True`` if address holds executable code, ``False`` otherwise.
        :rtype: ``bool``

        .. warning:: This is a private function, don't use it directly.
        '''

        # If the address has not been marked as data and if it falls within an
        # executable segment, just start a linear sweep disassembly.
        r = False
        if not self.shadow.is_marked_as_data(address) and \
                self.is_memory_executable(address):
            r = self._do_linear_sweep_disassembly(address)
        return r


    def _disassemble_entry_points(self):
        '''
        Start recursive disassembly from each entry point.

        .. warning:: This is a private function, don't use it directly.
        '''

        _msg('Disassembling entry points')
        for entry_point in self.loader.entry_points:
            self.shadow.mark_as_function(entry_point)
            self._do_recursive_disassembly(entry_point)


    def _disassemble_functions(self):
        '''
        Start recursive disassembly from each address reported as function entry
        point by the executable's metadata.

        .. warning:: This is a private function, don't use it directly.
        '''

        _msg('Disassembling functions')
        for address in self.loader.functions:
            # Looks like function tables in PE executables, sometimes, mark jump
            # tables, as well as other data regions in executable segments, as
            # function entry points.
            if self._is_code(address):
                self.shadow.mark_as_function(address)
                self._do_recursive_disassembly(address)

        # Also mark exit points as function entry points.
        for address in self.loader.exit_points:
            self.shadow.mark_as_analyzed(address)
            self.shadow.mark_as_function(address)


    def _disassemble_relocated(self):
        '''
        Disassemble code regions discovered during relocation analysis.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Get list of executable sections.
        sections = [s for s in self.loader.sections if 'x' in s.flags]

        _msg('Disassembling relocated code regions')

        # Iterate through all addresses marked as containers of relocated elements.
        for section in sections:
            for address in xrange(section.start_address, section.end_address):
                if self.shadow.is_marked_as_relocated_leaf(address):

                    # Current address holds a relocated element, which points to
                    # either code or data. If it looks like code, mark it as a
                    # basic block leader and start recursive disassembly.
                    if self._is_code(address):
                        self.shadow.mark_as_basic_block_leader(address)
                        self._do_recursive_disassembly(address)


    def _disassemble_deferred(self):
        '''
        Disassemble executable regions whose analysis was previously deferred.

        .. warning:: This is a private function, don't use it directly.
        '''

        _msg('Starting deferred disassembly of executable regions')

        # Get list of executable sections.
        sections = [s for s in self.loader.sections if 'x' in s.flags]

        # Standard fixed point loop. We disassemble all unanalyzed regions until
        # no more unanalyzed regions exist.
        done = False
        while not done:

            done = True
            for section in sections:
                for address in xrange(section.start_address, section.end_address):
                    if not self.shadow.is_marked_as_analyzed(address) and \
                            self.shadow.is_marked_as_basic_block_leader(address):

                        # Start recursive disassembly from each address that
                        # hasn't been analyzed yet. Analysis may generate new
                        # code regions that should be analyzed and so on.
                        _msg('Disassembling from @%#x' % address)
                        self._do_recursive_disassembly(address)
                        done = False

            if not done:
                _msg('Fixed-point not reached, restarting')


    def _disassemble_orphan(self):
        '''
        Look for unreferenced basic block leaders and mark them as functions.

        .. warning:: This is a private function, don't use it directly.
        '''

        _msg('Searching for orphan basic block leaders')

        # Get list of executable sections.
        sections = [s for s in self.loader.sections if 'x' in s.flags]

        # If there's any relocated address which has been marked as a basic block
        # leader with no incoming edges, mark it as function entry point.
        for section in sections:
            for address in xrange(section.start_address, section.end_address):
                if self.shadow.is_marked_as_relocated_leaf(address) and \
                        self.shadow.is_marked_as_basic_block_leader(address) and \
                        len(self.code_xrefs.get_predecessors(address)) == 0:
                    self.shadow.mark_as_function(address)



    def _build_basic_block_set_for_range(self, start_address, end_address):
        '''
        Parse shadow memory marks and build basic block set for the given memory
        range.

        .. warning:: This is a private function, don't use it directly.
        '''

        address = start_address
        while address <= end_address:

            # Get the address of the next available basic block leader.
            while address <= end_address and \
                    not self.shadow.is_marked_as_basic_block_leader(address):
                address += 1

            # If no more basic block leaders, break.
            if address > end_address:
                break

            # This is the basic block's start address.
            bb_start_address = address
            address += 1

            # This basic block extends up to the next basic block leader or to
            # the end of the current code region (a data region may lie between
            # two basic block leaders).
            instructions = [bb_start_address]
            while address <= end_address and \
                    self.shadow.is_marked_as_code(address) and \
                    not self.shadow.is_marked_as_basic_block_leader(address):

                # Each address marked as code and head is the first byte of an
                # instruction.
                if self.shadow.is_marked_as_head(address):
                    instructions.append(address)

                address += 1

            # This is the basic block's end address (i.e. the address of the
            # next instruction - this is how IDA Pro does it).
            bb_end_address = address

            # Create a `BasicBlock' object and add it in basic blocks map.
            self.basic_blocks[bb_start_address] = \
                basic_block.BasicBlock(bb_start_address, bb_end_address, instructions)


    def _build_basic_block_set(self):
        '''
        Parse shadow memory marks and build basic block set.

        .. warning:: This is a private function, don't use it directly.
        '''

        _msg('Building basic block set')

        for start_address, end_address in self.shadow.memory_ranges:
            self._build_basic_block_set_for_range(start_address, end_address)


    def _build_cfg(self):
        '''
        Build a first approximation of the program's CFG.

        :raises RuntimeError: Raised when an instruction decoding error occurs.
            This is an internal error that usually indicates a problem in the
            disassembly logic.

        .. warning:: This is a private function, don't use it directly.
        '''

        _msg('Building CFG')

        program_counter_name = self.cpu.get_program_counter_name()

        for block in self.basic_blocks.values():

            # If basic block is an exit point (e.g. a symbol imported from an
            # external library), skip it.
            if block.start_address in self.loader.exit_points:
                continue

            # Get basic block's last instruction.
            address = block.instructions[-1]
            insn = self.get_instruction(address)

            # Should not happen, but if it does, then something is really wrong
            # with the disassembly logic.
            if insn is None:
                raise RuntimeError('Instruction at %#x not found' % address)

            # Get set of target addresses of this instruction.
            successors = self.code_xrefs.get_successors(address)

            # If last instruction in this basic block modifies the program
            # counter, add CFG links for all possible target addresses. If it's
            # a RET instruction, the target addresses set should be empty.
            if program_counter_name in insn.get_written_registers():
                for successor in successors:

                    # Create CFG links only for target addresses which are basic
                    # block leaders but not function entry points. This results
                    # in a forest of intra-procedural CFGs.
                    if self.shadow.is_marked_as_basic_block_leader(successor) and \
                            not self.shadow.is_marked_as_function(successor):
                        self.cfg.add_edge((block.start_address, successor))

            # If last instruction in this basic block doesn't modify the program
            # counter, execution flow continues to the basic block physically
            # bordering the current one.
            else:
                self.cfg.add_edge((block.start_address, block.end_address))



    def _analyze_relocation(self, address, fmt, size):
        '''
        Recursively analyze relocation at address *address*.

        :param address: Address holding a relocated element.
        :param fmt: CPU mode-specific Format string used for unpacking pointers
            passed to ``struct.unpack()``.
        :param size: Number of bytes corresponding to *fmt*.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Make sure the relocation entry is valid.
        if self.is_memory_mapped(address, size):

            # Mark `address' as analyzed.
            self.shadow.mark_as_analyzed(address)
            self.shadow.mark_as_relocated(address)

            # Extract the relocated element.
            data = self.read_memory(address, size)
            element = struct.unpack(fmt, data)[0]

            # Sometimes the relocated elements are not mapped addresses (don't
            # know why, have seen that in Adobe Flash and haven't investigated
            # it further).
            if self.is_memory_mapped(element):

                # The current address may hold a relocated element, which, in
                # turn, may point to another relocated element. If this is the
                # case, recursively analyze the relocated element.
                if element in self.loader.relocations:
                    self._analyze_relocation(element, fmt, size)

                # Otherwise, this is the leaf entry in the current chain of
                # relocations. Mark it accordingly and continue. We will later
                # attempt to determine if this element points to code or data.
                else:
                    self.shadow.mark_as_relocated_leaf(element)

        # Otherwise let the user know something is wrong.
        else:
            _msg('Invalid relocation entry @%#x' % address)


    def _analyze_relocations(self):
        '''
        Normally, relocations form a series of chains. We refer to chains' last
        elements as *relocated leaves*. This function is responsible for parsing
        the relocation entries of a binary and setting the appropriate marks in
        the program's shadow memory.

        .. warning:: This is a private function, don't use it directly.
        '''

        # Map CPU modes to native address width format strings.
        fmt_map = {
            cpu.X86_MODE_REAL: '=H',
            cpu.X86_MODE_PROTECTED_32BIT: '=I',
            cpu.X86_MODE_PROTECTED_64BIT: '=Q'
        }

        # Get format and corresponding size for the current CPU mode.
        fmt = fmt_map[self.cpu.mode]
        size = struct.calcsize(fmt)

        # Now, recursively parse all relocation entries.
        _msg('Analyzing relocations')
        for address in self.loader.relocations:
            self._analyze_relocation(address, fmt, size)

        # Discover data regions by examining contiguous relocated addresses.
        _msg('Analyzing relocated data regions')
        for section in self.loader.sections:
            address = section.start_address
            while address < section.end_address:

                # Three or more contiguous addresses marked as relocated, usually
                # indicate a data region.
                if self.shadow.is_marked_as_relocated(address) and \
                        self.shadow.is_marked_as_relocated(address + size) and \
                        self.shadow.is_marked_as_relocated(address + size + size):

                    # Start marking as data until a non-relocated address is hit.
                    while self.shadow.is_marked_as_relocated(address) and \
                            address < section.end_address:

                        # Already marked as analyzed.
                        self.shadow.mark_as_data(address)
                        address += size

                else:
                    address += 1


    # Public API definitions begin here.

    def disassemble(self):
        '''Start disassembly of S.EX. project.'''

        _msg('Beginning early analysis')
        self._analyze_relocations()

        _msg('Beginning disassembly')
        self._disassemble_entry_points()
        self._disassemble_functions()
        self._disassemble_relocated()
        self._disassemble_deferred()
        self._disassemble_orphan()

        _msg('Building program structure')
        self._build_basic_block_set()
        self._build_cfg()

        _msg('Disassembly completed')


    # Public API for examining memory contents and memory protection.

    def is_memory_readable(self, address, length=1):
        '''
        Check if specified address range is readable.

        :param address: Address to start checking from.
        :param length: Number of bytes to check.
        :returns: ``True`` if memory region is readable, ``False`` otherwise.
        :rtype: ``bool``
        '''
        section = self.loader.get_section_for_address_range(address, length)
        return section is not None and 'r' in section.flags


    def is_memory_writable(self, address, length=1):
        '''
        Check if specified address range is writable.

        :param address: Address to start checking from.
        :param length: Number of bytes to check.
        :returns: ``True`` if memory region is writable, ``False`` otherwise.
        :rtype: ``bool``
        '''
        section = self.loader.get_section_for_address_range(address, length)
        return section is not None and 'w' in section.flags


    def is_memory_executable(self, address, length=1):
        '''
        Check if specified address range is executable.

        :param address: Address to start checking from.
        :param length: Number of bytes to check.
        :returns: ``True`` if memory region is executable, ``False`` otherwise.
        :rtype: ``bool``
        '''
        section = self.loader.get_section_for_address_range(address, length)
        return section is not None and 'x' in section.flags


    def is_memory_mapped(self, address, length=1):
        '''
        Check if specified address range is mapped (i.e. falls within one of the
        binary's load segments).

        :param address: Address to start checking from.
        :param length: Number of bytes to check.
        :returns: ``True`` if memory region is mapped, ``False`` otherwise.
        :rtype: ``bool``
        '''
        section = self.loader.get_section_for_address_range(address, length)
        return section is not None and 'l' in section.flags


    def read_memory(self, address, length):
        '''
        Read *length* bytes from memory address *address*.

        :param address: Address to read data from.
        :param length: Number of bytes to read.
        :returns: A string of *length* bytes.
        :rtype: ``str``
        '''
        return self.loader.read(address, length)


    # Public API for examining program structure and so on.

    def get_instruction(self, address):
        '''
        Return an :class:`instruction.Instruction` instance for the instruction
        at address *address*.

        :param address: Address of instruction whose object to return.
        :returns: Instruction object for instruction at *address* or ``None``.
        :rtype: :class:`instruction.Instruction`
        '''

        r = None

        # Make sure `address' points to the first byte of a valid instruction.
        if self.shadow.is_marked_as_code(address) and \
                self.shadow.is_marked_as_head(address):

            # Get the section containing this instruction and prepare decoder's
            # input.
            section = self.loader.get_section_for_address_range(address)
            self.decoder.itext = section.data
            self.decoder.itext_offset = address - section.start_address
            self.decoder.runtime_address = section.start_address

            try:
                insn = self.decoder.decode()
            except (pyxed.InvalidInstructionError, pyxed.InvalidOffsetError):
                insn = None

            if insn is not None:
                r = instruction.Instruction(insn, self.cpu)

        return r


    def get_basic_block(self, address):
        '''
        Return the :class:`basic_block.BasicBlock` instance of the basic block
        that contains address *address*.

        :param address: Address whose basic block object to look up and return.
        :returns: The basic block instance that contains *address* or ``None``.
        :rtype: :class:`basic_block.BasicBlock`
        '''

        r = None

        if self.shadow.start_address <= address <= self.shadow.end_address:
            while not self.shadow.is_marked_as_basic_block_leader(address):
                address -= 1
            r = self.basic_blocks[address]

        return r


    def get_function(self, address):
        '''
        Return a list of :class:`basic_block.BasicBlock` instances corresponding
        to the basic blocks of function at address *address*.

        :param address: Address of function whose basic block list to return.
        :return: List of basic blocks of function or ``None``.
        :rtype: ``list``
        '''

        r = None

        # Make sure `address' is a function entry point.
        if self.shadow.is_marked_as_function(address):

            # List of basic block addresses belonging to function.
            addresses = []

            # Set of seen basic blocks.
            seen = set()

            # DFS stack of basic blocks.
            stack = [address]

            while len(stack):
                address = stack.pop()

                # Add in basic blocks set.
                if address not in seen:
                    seen.add(address)
                    addresses.append(address)

                # Push basic block addresses that have not been visited yet but
                # skip calls to other functions.
                stack += [a for a in self.cfg.get_successors(address) \
                    if a not in seen and not self.shadow.is_marked_as_function(a)]

            # Return corresponding basic block objects.
            r = [self.basic_blocks[a] for a in addresses]

        return r


    def close(self):
        '''Release all resources and finalize the disassembler.'''
        self.shadow.close()
        self.basic_blocks.close()
        self.code_xrefs.close()
        self.data_xrefs.close()
        self.cfg.close()

