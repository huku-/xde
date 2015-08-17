#!/usr/bin/env python
'''simplegraph.py - Simple, but memory hungry, graph implementation.'''

__author__ = 'huku <huku@grhack.net>'


import collections


class SimpleGraph(object):
    '''
    Simple, but memory hungry, graph implementation. Designed with Python sets
    so that no checks for duplicates are performed when nodes or edges are added
    or deleted. This simple class provides maps of node names to their immediate
    ancestors and descendants, hence the increased memory consumption.

    The implementation is unaware of the of types of the objects that compose
    the graph nodes. It's up to the end programmer to implement appropriate
    `__hash__()' methods.
    '''

    def __init__(self):
        self.nodes = set()
        self.edges = set()
        self.outgoing = collections.defaultdict(set)
        self.incoming = collections.defaultdict(set)

    def __str__(self):
        return '<SimpleGraph %d nodes, %d edges>' % \
            (len(self.nodes), len(self.edges))

    def add_node(self, name):
        '''Add a node in the graph.'''
        self.nodes.add(name)

    def del_node(self, name):
        '''
        Delete a node from the graph. Incoming and outgoing edges are also
        removed.
        '''
        for edge in self.outgoing[name]:
            self.edges.discard(edge)
        del self.outgoing[name]
        for edge in self.incoming[name]:
            self.edges.discard(edge)
        del self.incoming[name]
        self.nodes.discard(name)

    def add_edge(self, edge):
        '''Add an edge in the graph. New nodes are automatically added.'''
        src, dst = edge
        self.nodes.add(src)
        self.nodes.add(dst)
        self.edges.add(edge)
        self.outgoing[src].add(dst)
        self.incoming[dst].add(src)

    def del_edge(self, edge):
        '''
        Delete an edge from the graph. Nodes with no links are automatically
        removed.
        '''
        src, dst = edge

        # Remove this edge from the graph.
        self.outgoing[src].discard(dst)
        self.incoming[dst].discard(src)
        self.edges.discard(edge)

        # If the removal of the edge results in orphan nodes, remove those from
        # the graph as well.
        if len(self.outgoing[src]) == 0 and len(self.incoming[src]) == 0:
            self.nodes.discard(src)
        if len(self.outgoing[dst]) == 0 and len(self.incoming[dst]) == 0:
            self.nodes.discard(dst)

