'''
:mod:`em_graph` -- External memory graph implementation
=======================================================

.. module: em_graph
   :platform: Unix, Windows
   :synopsis: External memory graph implementation
.. moduleauthor:: huku <huku@grhack.net>


About
-----
A simple external memory graph implementation built on top of external memory
dictionaries.

An :class:`EMGraph` is composed of four private ``EMDict`` instances:

* The first holds the graph's adjacency structure. That is, each vertex is a
  key that maps to a normal Python set holding the vertex' successors. Notice
  that we assume that each vertex' adjacency list can fit in main memory (and,
  in fact, this is an assumption made by all external memory algorithms).

* The second holds the graph's transpose, the inverse adjacency lists.

* The third maps each vertex to a normal Python dictionary, which, in turn,
  maps attribute names to their values. You can use the relevant :class:`EMGraph`
  API to set vertex attributes as shown below:

  .. code-block:: python

     graph.add_vertex_attribute(vertex, 'visited', True)
     graph.add_vertex_attribute(vertex, 'visited', False)
     graph.remove_vertex_attribute(vertex, 'visited')

* The fourth does a similar job, but maps graph edges to their attributes
  instead. The relevant :class:`EMGraph` API allows you to set a weight value,
  for example, to each edge as shown below:

  .. code-block:: python

     edge = (tail_vertex, head_vertex)
     graph.add_edge_attribute(edge, 'weight', 0.4)

A vertex can be any object as long as it's ``cPickle`` friendly. To avoid strange
behavior make sure your objects implement ``__eq__()`` and ``__hash__()``. People
already familiar with Python object serialization are aware of these complications.
Knowing this in advance, will save you many hours of debugging.

An example vertex object is shown in the following example:

.. code-block:: python

   class VertexObject(object):

       def __init__(self, vertex_id):
           self.vertex_id = vertex_id

       def __eq__(self, other):
           return self.vertex_id == other.vertex_id

       def __hash__(self):
           return self.vertex_id

An edge is just a 2-tuple of vertex objects.


Classes
-------
'''

__author__ = 'huku <huku@grhack.net>'


import sys
import os


try:
    import pyrsistence
except ImportError:
    sys.exit('Pyrsistence not installed?')



class EMGraph(object):
    '''
    This class represents an external memory graph.

    .. automethod:: __init__
    .. automethod:: _add_attribute
    .. automethod:: _remove_attribute
    .. automethod:: _get_attribute
    '''

    def __init__(self, dirname):
        '''
        :param dirname: Directory where memory mapped files will be stored. The
            directory is created if it does not exist.
        '''

        # Create container directory if not there.
        if os.access(dirname, os.F_OK) == False:
            os.makedirs(dirname, 0750)

        # Create new, or open existing external memory dictionaries. See the
        # module's documentation for more information on each dictionary.
        self._graph = pyrsistence.EMDict('%s/graph' % dirname)
        self._transpose_graph = pyrsistence.EMDict('%s/transpose_graph' % dirname)
        self._vertex_attributes = pyrsistence.EMDict('%s/vertex_attributes' % dirname)
        self._edge_attributes = pyrsistence.EMDict('%s/edge_attributes' % dirname)


    def __del__(self):
        self.close()


    def _add_attribute(self, attributes, subject, name, value):
        '''
        Template function used for implementing :func:`add_vertex_attribute()`
        and :func:`add_edge_attribute()`, both defined below. Adds or updates
        subject attribute *name* with value *value*. Previous value if any is
        returned.

        :param attributes: An external memory dictionary that maps subjects to
            normal Python dictionaries, which, in turn, map attribute names to
            their values.
        :param subject: The subject whose attributes will be updated.
        :param name: Name of attribute to add or update.
        :param value: Value assigned to attribute *name*.
        :returns: Previous attribute value, if any.
        :rtype: ``object``

        .. warning:: This is a private function, don't use it directly.
        '''
        prev_value = None

        # Check if the subject has any attributes set.
        if subject in attributes:

            # Read dictionary of subject attributes and the current attribute
            # value if one is set.
            subject_attributes = attributes[subject]
            prev_value = subject_attributes.get(name, None)

            # Add or replace attribute value.
            subject_attributes[name] = value

            # Update subject's attributes in attributes container.
            attributes[subject] = subject_attributes

        return prev_value


    def _remove_attribute(self, attributes, subject, name):
        '''
        Template function used for implementing :func:`remove_vertex_attribute()`
        and :func:`remove_edge_attribute()`, both defined below. Removes subject
        attribute *name*. Previous value, if any, is returned.

        :param attributes: An external memory dictionary that maps subjects to
            normal Python dictionaries, which, in turn, map attribute names to
            their values.
        :param subject: The subject whose attributes will be updated.
        :param name: Name of attribute to remove.
        :returns: Previous attribute value, if any.
        :rtype: ``object``

        .. warning:: This is a private function, don't use it directly.
        '''
        value = None

        # Check if the subject has any attributes set.
        if subject in attributes:

            # Read dictionary of subject attributes and the current attribute
            # value if one is set.
            subject_attributes = attributes[subject]
            value = subject_attributes.get(name, None)

            # Delete given attribute.
            del subject_attributes[name]

            # Update subject's attributes in attribute container.
            attributes[subject] = subject_attributes

        return value


    def _get_attribute(self, attributes, subject, name):
        '''
        A template function used for implementing :func:`get_vertex_attribute()`
        and :func:`get_edge_attribute()`, both defined below. Returns the value
        of subject attribute *name*.

        :param attributes: An external memory dictionary that maps subjects to
            normal Python dictionaries, which, in turn, map attribute names to
            their values.
        :param subject: The subject whose attributes will be looked up.
        :param name: Name of attribute whose value to return.
        :returns: Attribute value or ``None``.
        :rtype: ``object``

        .. warning:: This is a private function, don't use it directly.
        '''
        value = None

        # Check if the subject has any attributes set.
        if subject in attributes:

            # Read dictionary of subject attributes and return current attribute
            # value or `None'.
            subject_attributes = attributes[subject]
            value = subject_attributes.get(name, None)

        return value



    def add_vertex(self, vertex):
        '''
        Add a vertex in the graph.

        :param vertex: The vertex to add in the graph.
        '''

        # Make sure we don't overwrite existing vertex.
        if vertex not in self._graph:
            self._graph[vertex] = set()
            self._transpose_graph[vertex] = set()
            self._vertex_attributes[vertex] = dict()


    def remove_vertex(self, vertex):
        '''
        Remove a vertex as well as its incoming and outgoing edges from the
        graph. If removal of the vertex generates orphan vertices, these can
        later be removed by calling :func:`remove_orphan_vertices()` defined
        below.

        :param vertex: The vertex to remove from the graph.
        '''

        # Make sure vertex is in the graph.
        if vertex in self._graph:

            # Remove outgoing edges.
            for successor in self._graph[vertex]:

                # Remove vertex from successor's predecessors.
                predecessors = self._transpose_graph[successor]
                predecessors.discard(vertex)
                self._transpose_graph[successor] = predecessors

                # We are done with this variable, release some memory.
                del predecessors

                # Remove edge attributes.
                del self._edge_attributes[(vertex, successor)]


            # Remove incoming edges.
            for predecessor in self._transpose_graph[vertex]:

                # Remove vertex from predecessor's successors.
                successors = self._graph[predecessor]
                successors.discard(vertex)
                self._graph[predecessor] = successors

                # We are done with this variable, release some memory.
                del successors

                # Remove edge attributes.
                del self._edge_attributes[(predecessor, vertex)]


            # Now remove the vertex.
            del self._graph[vertex]
            del self._transpose_graph[vertex]
            del self._vertex_attributes[vertex]


    def remove_orphan_vertices(self):
        '''
        Remove orphan nodes from the graph (nodes that have neither incoming nor
        outgoing edges).
        '''
        for vertex in self._graph.keys():
            if len(self._graph[vertex]) == 0 and \
                    len(self._transpose_graph[vertex]) == 0:
                del self._graph[vertex]
                del self._transpose_graph[vertex]
                del self._vertex_attributes[vertex]


    def get_vertices(self):
        '''
        Return graph vertices.

        :returns: Generator for all vertices in graph.
        :rtype: ``generator``
        '''
        for vertex in self._graph.keys():
            yield vertex


    def add_vertex_attribute(self, vertex, name, value):
        '''
        Add vertex attribute. Previous value, if any, is returned.

        :param vertex: The graph vertex whose attributes to update.
        :param name: Attribute name to add or update.
        :param value: Value to set the attribute to.
        :returns: Previous attribute value, if any, or ``None``.
        :rtype: ``object``
        '''
        return self._add_attribute(self._vertex_attributes, vertex, name, value)


    def remove_vertex_attribute(self, vertex, name):
        '''
        Remove vertex attribute. Previous value, if any, is returned.

        :param vertex: The graph vertex whose attribute to remove.
        :param name: Attribute name to remove.
        :returns: Previous attribute value, if any, or ``None``.
        :rtype: ``object``
        '''
        return self._remove_attribute(self._vertex_attributes, vertex, name)


    def get_vertex_attribute(self, vertex, name):
        '''
        Get value of vertex attribute.

        :param vertex: The graph vertex whose attribute to retrieve.
        :param name: Attribute name whose value to retrieve.
        :returns: Attribute value or ``None``.
        :rtype: ``object``
        '''
        return self._get_attribute(self._vertex_attributes, vertex, name)


    def get_successors(self, vertex):
        '''
        Get set of immediate successors of vertex. We assume successor set can
        fit in main memory.

        :param vertex: The vertex whose successors to return.
        :returns: Set of vertex successors.
        :rtype: ``set``
        '''
        if vertex in self._graph:
            vertices = self._graph[vertex]
        else:
            vertices = set()
        return vertices


    def get_predecessors(self, vertex):
        '''
        Get set of immediate predecessors of vertex. We assume predecessor set
        can fit in main memory.

        :param vertex: The vertex whose predecessors to return.
        :returns: Set of vertex predecessors.
        :rtype: ``set``
        '''
        if vertex in self._transpose_graph:
            vertices = self._transpose_graph[vertex]
        else:
            vertices = set()
        return vertices


    def add_edge(self, edge):
        '''
        Add an edge in the graph.

        :param edge: The graph edge to add.
        '''

        tail, head = edge

        # Make sure vertices are there.
        self.add_vertex(tail)
        self.add_vertex(head)

        # Read tail's successors.
        successors = self._graph[tail]

        # Update sets only if needed.
        if head not in successors:

            # Add head in tail's successors.
            successors.add(head)
            self._graph[tail] = successors

            # We are done with this variable, release some memory.
            del successors

            # Add tail in head's predecessors.
            predecessors = self._transpose_graph[head]
            predecessors.add(tail)
            self._transpose_graph[head] = predecessors

            # We are done with this variable, release some memory.
            del predecessors

            # Initialize edge attributes to an empty dictionary.
            self._edge_attributes[edge] = dict()


    def remove_edge(self, edge):
        '''
        Remove an edge from the graph. If removal of the edge generates orphan
        vertices, these can be removed by calling :func:`remove_orphan_vertices()`
        defined above.

        :param edge: The graph edge to remove.
        '''

        tail, head = edge

        # Make sure vertices are there.
        if tail in self._graph and head in self._graph:

            # Read tail's successors.
            successors = self._graph[tail]

            # Make sure such an edge does exist.
            if head in successors:

                # Remove head from tail's successors.
                successors.discard(head)
                self._graph[tail] = successors

                # We are done with this variable, release some memory.
                del successors

                # Remove tail from head's predecessors.
                predecessors = self._transpose_graph[head]
                predecessors.discard(tail)
                self._transpose_graph[head] = predecessors

                # We are done with this variable, release some memory.
                del predecessors

                # Delete edge attributes.
                del self._edge_attributes[edge]


    def get_edges(self):
        '''
        Return graph edges.

        :returns: Generator for all edges in graph.
        :rtype: ``generator``
        '''
        for vertex in self._graph.keys():
            for successor in self._graph[vertex]:
                yield (vertex, successor)


    def add_edge_attribute(self, edge, name, value):
        '''
        Add edge attribute. Previous value, if any, is returned.

        :param edge: The graph edge whose attributes to update.
        :param name: Attribute name to add or update.
        :param value: Value to set the attribute to.
        :returns: Previous attribute value, if any, or ``None``.
        :rtype: ``object``
        '''
        return self._add_attribute(self._edge_attributes, edge, name, value)


    def remove_edge_attribute(self, edge, name):
        '''
        Remove edge attribute. Previous value, if any, is returned.

        :param edge: The graph edge whose attribute to remove.
        :param name: Attribute name to remove.
        :returns: Previous attribute value, if any, or ``None``.
        :rtype: ``object``
        '''
        return self._remove_attribute(self._edge_attributes, edge, name)


    def get_edge_attribute(self, edge, name):
        '''
        Get value of edge attribute.

        :param edge: The graph edge whose attribute to retrieve.
        :param name: Attribute name whose value to retrieve.
        :returns: Attribute value or ``None``.
        :rtype: ``object``
        '''
        return self._get_attribute(self._edge_attributes, edge, name)


    def close(self):
        '''Finalize this :class:`EMGraph` instance.'''
        self._graph.close()
        self._transpose_graph.close()
        self._vertex_attributes.close()
        self._edge_attributes.close()

