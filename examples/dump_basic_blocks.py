#!/usr/bin/env python
'''dump_basic_blocks.py - Dumps basic blocks and their links.'''

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

    for address, block in disasm.basic_blocks.items():
        print '0x%x => %s' % (address, str(block))
        print '    Incoming: %s' % map(str, disasm.cfg.incoming[block])
        print '    Outgoing: %s' % map(str, disasm.cfg.outgoing[block])

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))

