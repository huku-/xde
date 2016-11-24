# XDE - XED based Disassembly Engine

huku &lt;[huku@grhack.net](mailto:huku@grhack.net)&gt;


## About

XDE is a WIP disassembly engine based on [pyxed](https://github.com/huku-/pyxed)
and [pyrsistence](https://github.com/huku-/pyrsistence).

XDE is constantly updated and will soon become a full featured, reliable, modular,
yet minimal and clean, x86 and x86\_64 disassembly engine. At its current version,
XDE can handle large CFGs, using the API offered by **pyrsistence**, without
wasting too much main memory. This feature alone makes XDE ideal for implementing
binary analyses schemes.


## Installing XDE

First, download and compile [pyxed](https://github.com/huku-/pyxed) and
[pyrsistence](https://github.com/huku-/pyrsistence) as XDE depends on both.
You can find the relevant instructions in each project's **README.md** file.

Then, grab [section extractor](https://github.com/huku-/sex) and install it as
well.

Last but not least, run the following command to install XDE:

```sh
python setup.py install
```

The setup script will install the **xde** Python module under **site-packages**
and a small utility, named **xdec**, under **/usr/local/bin**.


## Using XDE

First run the section extractor script against the binary you would like to
disassemble.

```sh
$ sex /bin/ls
```

A directory named **ls.sex/** will be created. Pass the path to this directory
to the constructor of class **Disassembler** as shown below.

```python
import xde

disasm = xde.disassembler.Disassembler('ls.sex/')
disasm.disassemble()
```

Once **disassemble()** returns, you can access various members of class
**Disassembler** to explore the program's instructions and structure. For more
information and examples have a look at XDE's [wiki](https://github.com/huku-/xde/wiki).

For bugs, comments, whatever feel free to contact me.

