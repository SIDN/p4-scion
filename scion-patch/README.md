This patch add functionality to SCION to register hop fields when they are generated at the hop fields registration service.

Start by cloning the SCION source code from https://github.com/scionproto/scion

This patch was generated against commit `2ade82199e4bfceea98b2b4594171df58633b4c0`.

Apply the patch using git in the SCION source directory:
`git apply scion.patch`

After this, follow the regular procedure to build SCION. You can then add an additional setting to the configuration file of the control service in the general section to indicate at which server the hop fields should be registered. For example:
```
[general]
hop_fields_registration_server = "10.0.50.5:10000"
```
