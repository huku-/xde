#!/usr/bin/env python
'''dump_function.py - Dump first function's basic blocks.'''

__author__ = 'huku <huku@grhack.net>'


import sys

from xde import disassembler


def main(argv):

    if len(argv) != 2:
        print 'Usage: %s <sex_project_dir>' % argv[0]
        return 1

    print 'Disassembling S.EX. project from %s' % argv[1]

    disasm = disassembler.Disassembler(argv[1])
    disasm.analyze()

    print 'Analysis finished'
    print '    %d basic blocks' % len(disasm.basic_blocks)
    print '    %d functions' % len(disasm.functions)

    address = list(disasm.functions)[0]
    print 'Basic blocks for sub_%x()' % address
    for basic_block in disasm.get_function_basic_blocks(address):
        print '    %s' % str(basic_block)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))

