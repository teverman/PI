"""
Base classes for GRPC based PI test cases

Tests will usually inherit from one of these classes to have the controller
and/or dataplane automatically set up.
"""

import importlib

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils

################################################################
#
# protobuf base tests
#
################################################################
import grpc
import pi_pb2
import sys

class GrpcInterface(BaseTest):
    def __init__(self, p4_name):
        BaseTest.__init__(self)
        self.p4_name = p4_name

    def setUp(self):
        BaseTest.setUp(self)
        self.channel = grpc.insecure_channel('localhost:50051')
	self.stub = pi_pb2.StubChannel(self.channel)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        BaseTest.tearDown(self)

class GrpcInterfaceDataPlane(GrpcInterface):
    """
    Root class that sets up the GRPC interface and dataplane
    """
    def __init__(self, p4_name):
        GrpcInterface.__init__(self, p4_name)

    def setUp(self):
        GrpcInterface.setUp(self)
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        GrpcInterface.tearDown(self)

