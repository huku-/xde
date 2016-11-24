#!/usr/bin/env python
'''
:mod:`classifier` - Classifies a series of instructions as either code or data
==============================================================================

.. module: classifier
   :platform: Unix, Windows
   :synopsis: Classifies a series of instructions as either code or data
.. moduleauthor:: huku <huku@grhack.net>


About
-----
It is widely known that complete disassembly is an undecidable problem. As [1]
points out, the aforementioned undecidability is inherent in various aspects
of the disassembly process, the separation between code and data being one of
them. This has also been the subject of various academic publications, some of
which are listed in :file:`README.md`.

This file exports :class:`Classifier`, a class implementing the proxy design
pattern, which uses classification backends in order to decide whether a given
memory address holds code or data. Notice that, in practice, this question
cannot be answered with a simple yes/no since a data region may hold bytes
corresponding to perfectly valid machine code (and this may be for various
reasons ranging from random coincidences to anti-reversing and anti-debugging
tricks).

For now, only a simple *naive* approach has been implemented, which works much
better than I initially thought. I'm currently experimenting with other ideas,
involving Markov models and simple machine learning techniques.

Using this module is straightforward (assuming it's under :file:`classifiers/`):

.. code-block:: python

   from xde.classifiers import classifier

   c = classifier.Classifier(classifier.CLASSIFIER_NAIVE)
   print c.is_code(insns)


[1] https://indefinitestudies.org/2010/12/19/the-halting-problem-for-reverse-engineers/


Classes
-------
'''

__author__ = 'huku <huku@grhack.net>'


from xde.classifiers import naive


CLASSIFIER_NAIVE = 0


class Classifier(object):
    '''
    Main classification class.

    .. automethod:: __init__
    '''

    def __init__(self, classifier_id=CLASSIFIER_NAIVE):
        '''
        :param classifier_id: Id of classifier to instantiate and use as backend.
        '''
        self.classifier_id = classifier_id

    def is_code(self, insns):
        '''
        Determine if *insns* look like valid code or data.

        :param insns: A ``list`` of decoded instructions to examine.
        :returns: ``True`` if *insns* look like code, ``False`` otherwise.
        :rtype: ``bool``
        '''
        r = False
        if self.classifier_id == CLASSIFIER_NAIVE:
            r = naive.is_code(insns)
        return r

    def is_data(self, insns):
        '''
        This is the exact opposite of :func:`is_code()` defined above.

        :param insns: A ``list`` of decoded instructions to examine.
        :returns: ``True`` if *insns* look like data, ``False`` otherwise.
        :rtype: ``bool``
        '''
        return not(self.is_code(insns))

