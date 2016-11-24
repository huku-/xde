# Classifier backends

## About

Classifier backends. See comment **classifier.py** for more information.

Each classifier should implement a function named **is_code()** taking a single
argument, the list of instructions that were linearly disassembled from the
address whose contents we are interested in classifying as either code or data.
The function should return **True** if the instructions represent a valid code
region and **False** otherwise.


## Implemented classifiers

  * **naive.py** - Classifies as code anything that looks like a valid function
    prologue.


## Literature

  * [Differentiating Code from Data in x86 Binaries](http://www.utd.edu/~hamlen/wartell-pkdd11.pdf)
  * [Machine Learning-Assisted Binary Code Analysis](http://pages.cs.wisc.edu/~jerryzhu/pub/nips07-abs.pdf)
  * [Static Analysis of Binary Executables Using Structural SVMs](http://lowrank.net/nikos/pubs/segment.pdf)

