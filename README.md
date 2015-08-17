# XDE - XED2 based Disassembly Engine

huku &lt;[huku@grhack.net](mailto:huku@grhack.net)&gt;


## About

**xde** is a WIP disassembly engine based on [pyxed](https://github.com/huku-/pyxed).


## How to use

First, download and compile [pyxed](https://github.com/huku/pyxed) as **xde**
depends on it. You can find the relevant instructions in **pyxed**'s
**README.md** file.

Then, grab [section extractor](https://github.com/huku-/sex) and run it against
the binary you would like to disassemble.

```sh
$ ./sex.sh /bin/ls
```

A directory named **ls/** will be created. Pass the path to this directory to
the constructor of class **Disassembler** as shown below.

```python
import disassembler

disasm = disassembler.Disassembler("ls/")
disasm.analyze()
```

Member **functions** holds the list of discovered functions:

```python
print map(hex, disasm.functions)
```

Member **cfg** holds the program's control flow graph. It's a **SimpleGraph**
instance (see **simple_graph.py**) where each node is of type **BasicBlock**
(see **basic_block.py**). A map of basic block addresses to **BasicBlock**
instances can be accessed via member **basic_blocks**.

By combining this knowledge, to print all basic blocks along with their incoming
and outgoing links, you can do the following:

```python
for address, block in disasm.basic_blocks.items():
    print '0x%x => %s' % (address, str(block))
    print '    Incoming: %s' % map(str, disasm.cfg.incoming[block])
    print '    Outgoing: %s' % map(str, disasm.cfg.outgoing[block])
```

A complete example can be found in **main.py**.

For bugs, comments, whatever feel free to contact me.

