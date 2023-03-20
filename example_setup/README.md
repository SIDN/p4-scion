# Setup to test P4 implementation with VMs

This setup consists of two VMs: one on which the Tofino model runs to emulate the switch and one on which the modified version of SCION runs. On the SCION VM we run a modified version of SCION in which hop fields are registered at the switch when they are generated.

## Topology

```
+-----------------------------------------------+                     
| AS 110                                        |                     
|                                               |                     
|                         +----------------+    |                     
|                         | Tofino VM      |    |                     
| +---------------+       | +------------+ |    |                     
| | Internal host |---------|   Switch   | |    |     +--------------+
| | (CS)          |---------|            |------------|    AS 112    |
| +---------------+       | +------------+ |    |     |              |
|                         +--------|-------+    |     +--------------+
+----------------------------------|------------+                     
                                   |                                  
                                   |                                  
                           +--------------+                           
                           |    AS 111    |                           
                           |              |                           
                           +--------------+
```

There are 4 connections between the Barefoot VM and the SCION VM (3 for the dataplane and 1 for the control plane). The control plane connection is used to register hop fields at the switch.

### SCION VM interfaces

**Control plane**
- Interface: enp0s16
- Address: 10.0.50.10/24

**AS 110 (internal)**
- Interface: enp0s10
- Address: 10.0.30.10/24
- MAC: 08:00:27:8b:38:63

**AS 111**
- Interface: enp0s8
- Address: 10.0.10.10/24
- MAC: 08:00:27:22:82:4a

**AS 112**
- Interface: enp0s9
- Address: 10.0.20.10/24
- MAC: 08:00:27:3e:ac:95

### Barefoot VM interfaces

**Control plane**

This interface is used by `hopfields_registration_server.py` to allow the control service to register hop fields.

- Interface: enp0s16
- Address: 10.0.50.5/24

**AS 110 (internal)**

This interface is used to connect to the internal network of AS 110.

- Interface: enp0s10
- PortId: 3
- Address: 10.0.30.5
- MAC: 08:00:27:2c:f8:c4

**AS 111**
- Interface: enp0s8
- PortId: 1
- Address: 10.0.10.5
- MAC: 08:00:27:b4:c9:7a

**AS 112**
- Interface: enp0s9
- PortId: 2
- Address: 10.0.20.5
- MAC: 08:00:27:1d:8e:1a

## Run

Tofino VM:
```
cd $P4_SCION
sudo sh $SCRIPTS/setup_networking.sh

cd $SDE
sudo ./install/bin/veth_setup.sh
./run_tofino_model.sh -p scion -f $CONFIG/ports.json [-q]
./run_switchd.sh -p scion

cd $P4_SCION
python3 controller/load_config.py $CONFIG/switch_config.json
python3 controller/hopfields_registration_server.py
python3 controller/remove_expired_hop_fields.py
sudo python3 controller/onehop_processor.py -k $SCION/gen/ASff00_0_110/keys/master0.key -m $CONFIG/interface_mapping.json -b $CONFIG/bfd_config.json
```

For the SCION VM we have two different configurations: one where AS 110 is the core AS and AS 111 and AS 112 are children and one where AS 112 is the core AS, AS 110 is a child of AS 112 and AS 111 is a child of AS 110. The configurations for SCION can be found in `config/scion-parent` and `config/scion-child` respectively.

SCION VM:
```
sudo sh $SCRIPTS/set_arp.sh
cd scion
./scion.sh run nobuild
```

## Test connections

Use `$SCRIPTS/test_connections.sh` to perform an SCMP between all ASes.
