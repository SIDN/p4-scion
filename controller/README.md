# SCION in P4 control plane

Applications to configure the control plane of the P4 implementation of SCION. 

## Installation

```
apt install libprotobuf-dev
pip3 install -r requirements.txt
```

### bfrt_grpc

Copy `bfruntime.proto` from P4 studio to `proto/bfrt_grpc/`. Make sure to use up to date proto files, i.e. from the current P4 studio and using the last SCION definition of HopField.
```
python3 -m grpc_tools.protoc -I=./proto -I=$SDE/p4studio_build/third_party/grpc_protobuf/grpc/third_party/googleapis/ --python_out=. --grpc_python_out=. proto/scion_grpc/hopfields.proto proto/bfrt_grpc/bfruntime.proto
```

Copy `client.py` and `info_parse.py` from P4 studio to the `bfrt_grpc` directory.

### scion_grpc

If `scion_grpc/hopfields_pb2_grpc.py` or `scion_grpc/hopfields_pb2.py` needs to be generated (e.g. because hopfields.proto was updated), use the following command:
```
python3 -m grpc_tools.protoc -I=./proto --python_out=. --grpc_python_out=. proto/scion_grpc/hopfields.proto
```

## Applications

- `generate_config.py`: Generate stub configuration for the SCION P4 implementation based on the topology.json
- `load_config.py`: Load configuration on the Tofino switch for the SCION implementation
- `hopfields_registration_server.py`: Service to register hop fields and add them to the MAC verification tables at the Tofino switch
- `onehop_processor.py`: Service to process one-hop paths: compute and register missing hop field
- `remove_expired_hop_fields.py`: Application to trigger the process to remove expired hop fields
