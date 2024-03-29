# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: scion_grpc/hopfields.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1ascion_grpc/hopfields.proto\x12\x16proto.control_plane.v1\"\xb5\x01\n\x1cHopFieldsRegistrationRequest\x12\x11\n\ttimestamp\x18\x01 \x01(\x03\x12\x12\n\nsegment_id\x18\x02 \x01(\r\x12\x33\n\thop_field\x18\x03 \x01(\x0b\x32 .proto.control_plane.v1.HopField\x12\x39\n\x0fpeer_hop_fields\x18\x04 \x03(\x0b\x32 .proto.control_plane.v1.HopField\"J\n\x08HopField\x12\x0f\n\x07ingress\x18\x01 \x01(\x04\x12\x0e\n\x06\x65gress\x18\x02 \x01(\x04\x12\x10\n\x08\x65xp_time\x18\x03 \x01(\r\x12\x0b\n\x03mac\x18\x04 \x01(\x0c\"\x1f\n\x1dHopFieldsRegistrationResponse\"\x1f\n\x1dRemoveExpiredHopFieldsRequest\" \n\x1eRemoveExpiredHopFieldsResponse2\xb3\x02\n\x1cHopFieldsRegistrationService\x12\x86\x01\n\x15HopFieldsRegistration\x12\x34.proto.control_plane.v1.HopFieldsRegistrationRequest\x1a\x35.proto.control_plane.v1.HopFieldsRegistrationResponse\"\x00\x12\x89\x01\n\x16RemoveExpiredHopFields\x12\x35.proto.control_plane.v1.RemoveExpiredHopFieldsRequest\x1a\x36.proto.control_plane.v1.RemoveExpiredHopFieldsResponse\"\x00\x62\x06proto3')



_HOPFIELDSREGISTRATIONREQUEST = DESCRIPTOR.message_types_by_name['HopFieldsRegistrationRequest']
_HOPFIELD = DESCRIPTOR.message_types_by_name['HopField']
_HOPFIELDSREGISTRATIONRESPONSE = DESCRIPTOR.message_types_by_name['HopFieldsRegistrationResponse']
_REMOVEEXPIREDHOPFIELDSREQUEST = DESCRIPTOR.message_types_by_name['RemoveExpiredHopFieldsRequest']
_REMOVEEXPIREDHOPFIELDSRESPONSE = DESCRIPTOR.message_types_by_name['RemoveExpiredHopFieldsResponse']
HopFieldsRegistrationRequest = _reflection.GeneratedProtocolMessageType('HopFieldsRegistrationRequest', (_message.Message,), {
  'DESCRIPTOR' : _HOPFIELDSREGISTRATIONREQUEST,
  '__module__' : 'scion_grpc.hopfields_pb2'
  # @@protoc_insertion_point(class_scope:proto.control_plane.v1.HopFieldsRegistrationRequest)
  })
_sym_db.RegisterMessage(HopFieldsRegistrationRequest)

HopField = _reflection.GeneratedProtocolMessageType('HopField', (_message.Message,), {
  'DESCRIPTOR' : _HOPFIELD,
  '__module__' : 'scion_grpc.hopfields_pb2'
  # @@protoc_insertion_point(class_scope:proto.control_plane.v1.HopField)
  })
_sym_db.RegisterMessage(HopField)

HopFieldsRegistrationResponse = _reflection.GeneratedProtocolMessageType('HopFieldsRegistrationResponse', (_message.Message,), {
  'DESCRIPTOR' : _HOPFIELDSREGISTRATIONRESPONSE,
  '__module__' : 'scion_grpc.hopfields_pb2'
  # @@protoc_insertion_point(class_scope:proto.control_plane.v1.HopFieldsRegistrationResponse)
  })
_sym_db.RegisterMessage(HopFieldsRegistrationResponse)

RemoveExpiredHopFieldsRequest = _reflection.GeneratedProtocolMessageType('RemoveExpiredHopFieldsRequest', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEEXPIREDHOPFIELDSREQUEST,
  '__module__' : 'scion_grpc.hopfields_pb2'
  # @@protoc_insertion_point(class_scope:proto.control_plane.v1.RemoveExpiredHopFieldsRequest)
  })
_sym_db.RegisterMessage(RemoveExpiredHopFieldsRequest)

RemoveExpiredHopFieldsResponse = _reflection.GeneratedProtocolMessageType('RemoveExpiredHopFieldsResponse', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEEXPIREDHOPFIELDSRESPONSE,
  '__module__' : 'scion_grpc.hopfields_pb2'
  # @@protoc_insertion_point(class_scope:proto.control_plane.v1.RemoveExpiredHopFieldsResponse)
  })
_sym_db.RegisterMessage(RemoveExpiredHopFieldsResponse)

_HOPFIELDSREGISTRATIONSERVICE = DESCRIPTOR.services_by_name['HopFieldsRegistrationService']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _HOPFIELDSREGISTRATIONREQUEST._serialized_start=55
  _HOPFIELDSREGISTRATIONREQUEST._serialized_end=236
  _HOPFIELD._serialized_start=238
  _HOPFIELD._serialized_end=312
  _HOPFIELDSREGISTRATIONRESPONSE._serialized_start=314
  _HOPFIELDSREGISTRATIONRESPONSE._serialized_end=345
  _REMOVEEXPIREDHOPFIELDSREQUEST._serialized_start=347
  _REMOVEEXPIREDHOPFIELDSREQUEST._serialized_end=378
  _REMOVEEXPIREDHOPFIELDSRESPONSE._serialized_start=380
  _REMOVEEXPIREDHOPFIELDSRESPONSE._serialized_end=412
  _HOPFIELDSREGISTRATIONSERVICE._serialized_start=415
  _HOPFIELDSREGISTRATIONSERVICE._serialized_end=722
# @@protoc_insertion_point(module_scope)
