*v1.3*

The Find Hub Network (FHN) accessory specification defines an end-to-end
encrypted approach for tracking beaconing Bluetooth Low Energy (BLE) devices.
This page describes FHN as an extension to the Fast Pair specification.
Providers should enable this extension if they have devices that are compatible
with FHN and are willing to enable location tracking for those devices.

> [!NOTE]
> **Note:** If you are interested in integrating your location tag or non hearable device with *Find Hub Network Accessory* , complete a [Find Hub device proposal form](https://docs.google.com/forms/d/e/1FAIpQLSekmYsXwVhPofdonOBtUU4O3Lbr_gQ-o2sCm6LHocehXKiM1A/viewform). If you are interested in adding Find Hub support to over-the-ear or TWS headphones, complete the Fast Pair [device proposal form](https://docs.google.com/forms/d/e/1FAIpQLSdAzrYyd-gFk90ghLsZdYkXTH4HkL1VNdgBEUqtaA9UST8lLg/viewform) instead.

## GATT Specification

An additional generic attributes (GATT) characteristic should be added to the
Fast Pair Service with the following semantics:

| Fast Pair Service characteristic | Encrypted | Permissions | UUID |
|---|---|---|---|
| Beacon actions | No | Read, write and notify | `FE2C1238-8366-4814-8EB0-01DE32100BEA` |

***Table 1:** Fast Pair Service characteristics for FHN.*

### Authentication

The operations required by this extension are performed as a write operation,
secured by a challenge-response mechanism. Prior to performing any operation,
the Seeker is expected to perform a read operation from the characteristic in
table 1, which results in a buffer in the following format:

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Protocol major version number | 0x01 |
| 1 - 8 | byte array | One-time random nonce | *varies* |

Each read operation should result in a different nonce, and a single nonce
should be valid only for a single operation. The nonce must be invalidated even
if the operation failed.

The Seeker then calculates a one-time authentication key to be used in a
subsequent write request. The authentication key is calculated as described in
tables 2 through 5. Depending on the operation being requested, the Seeker
proves knowledge of one or more of the following keys:

- **Account key**: The 16-byte Fast Pair account key, as defined in the Fast
  Pair specification.

- **Owner account key** : The Provider chooses one of the existing account keys
  as the owner account key the first time a Seeker accesses the Beacon Actions
  characteristic. The chosen owner account key can't be changed until the Provider
  is factory reset. The Provider *must not* remove the owner account key when it
  runs out of free account key slots.

  - Providers that already support FHN when paired for the first time (or
    support it when paired after factory reset) choose the first account key,
    because this is the only existing account key when the Seeker reads the
    provisioning state during pairing.

  - Providers that gain FHN support after they're already paired (for example,
    through a firmware update) can choose any existing account key. It's reasonable
    to choose the first account key that is used to read the provisioning state from
    the beacon actions characteristic after the firmware update, assuming the user
    who performed the update is the Provider's current owner.

- **Ephemeral identity key (EIK)**: A 32-byte key chosen at random by the Seeker
  when performing the FHN provisioning process. This key is used to derive
  cryptographic keys that are used for end-to-end encrypting location reports. The
  Seeker never reveals it to the backend.

- **Recovery key** : Defined as `SHA256(ephemeral identity key || 0x01)`,
  truncated to the first 8 bytes. The key is stored on the backend and the Seeker
  can use it to [recover the EIK](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#read-eik), provided the user expresses consent
  by pressing a button on the device.

- **Ring key** : Defined as `SHA256(ephemeral identity key || 0x02)`, truncated
  to the first 8 bytes. The key is stored on the backend and the Seeker can use it
  only to [ring](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#ring) the device.

- **Unwanted tracking protection key** : Defined as
  `SHA256(ephemeral identity key || 0x03)`, truncated to the first 8 bytes. The
  key is stored on the backend and the Seeker can use it only to activate
  [unwanted tracking protection mode](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#unwanted-tracking).

### Operations

The format of the data written to the characteristic is given in tables 2
through 5. Each of the operations is discussed in more details later in this
section.

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | - 0x00: Read beacon parameters - 0x01: Read provisioning state - 0x02: Set ephemeral identity key - 0x03: Clear ephemeral identity key |
| 1 | uint8 | Data length | *varies* |
| 2 - 9 | byte array | One-time authentication key | The first 8 bytes of `HMAC-SHA256(account key, protocol major version number || the last nonce read from the characteristic || data ID || data length || additional data)` |
| 10 - var | byte array | Additional data | - 0x00: n/a - 0x01: n/a - 0x02: 32 bytes that are the ephemeral identity key, AES-ECB-128 encrypted with the account key. If the Provider already has an ephemeral identity key set, also send the first 8 bytes of `SHA256(current ephemeral identity key || the last nonce read from the characteristic)` - 0x03: The first 8 bytes of `SHA256(ephemeral identity key || the last nonce read from the characteristic)` |

***Table 2:** Beacon provisioning request.*

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | 0x04: Read ephemeral identity key with user consent |
| 1 | uint8 | Data length | 0x08 |
| 2 - 9 | byte array | One-time authentication key | The first 8 bytes of `HMAC-SHA256(recovery key, protocol major version number || the last nonce read from the characteristic || data ID || data length)` |

***Table 3:** Beacon provisioning key recovery request.*

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | - 0x05: Ring - 0x06: Read ringing state |
| 1 | uint8 | Data length | *varies* |
| 2 - 9 | byte array | One-time authentication key | The first 8 bytes of `HMAC-SHA256(ring key, protocol major version number || the last nonce read from the characteristic || data ID || data length || additional data)` |
| 10 - var | byte array | Additional data | - 0x05: 4 bytes indicating the ringing state, ringing duration and ringing volume. - 0x06: n/a |

***Table 4:** Ringing request.*

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | - 0x07: Activate unwanted tracking protection mode - 0x08: Deactivate unwanted tracking protection mode |
| 1 | uint8 | Data length | *varies* |
| 2 - 9 | byte array | One-time authentication key | The first 8 bytes of `HMAC-SHA256(unwanted tracking protection key, protocol major version number || the last nonce read from the characteristic || data ID || data length || additional data)` |
| 10 - var | byte array | Additional data | - 0x07: 1 byte of control flags (optional) - 0x08: The first 8 bytes of `SHA256(ephemeral identity key || the last nonce read from the characteristic)` |

***Table 5:** Unwanted tracking protection request.*

Successful writes trigger notifications as listed in table 6.

Notifications with data ID other than *0x05: Ring state change* should be sent
before the write transaction that triggers the notification is completed, that
is, before a response PDU for the write request is sent.

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | - 0x00: Read beacon parameters - 0x01: Read provisioning state - 0x02: Set ephemeral identity key - 0x03: Clear ephemeral identity key - 0x04: Read ephemeral identity key with user consent - 0x05: Ring state change - 0x06: Read ringing state - 0x07: Activate unwanted tracking protection mode - 0x08: Deactivate unwanted tracking protection mode |
| 1 | uint8 | Data length | *varies* |
| 2 - 9 | byte array | Authentication | [Detailed per operation](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#read-beacon-param) |
| 10 - var | byte array | Additional data | - 0x00: 8 bytes indicating the transmission power, clock value, encryption method and ringing capabilities, AES-ECB-128 encrypted with the account key (zero padded) - 0x01: 1 byte indicating the provisioning state, followed by the current ephemeral ID (20 or 32 bytes) if applicable - 0x04: 32 bytes that are the ephemeral identity key, AES-ECB-128 encrypted with the account key - 0x05: 4 bytes indicating the new state and trigger for the change - 0x06: 3 bytes indicating the components actively ringing and the number of deciseconds remaining for ringing - Other data IDs use empty additional data |

***Table 6:** Beacon service response.*

Table 7 lists the possible GATT error codes returned by the operations.

| Code | Description | Notes |
|---|---|---|
| 0x80 | Unauthenticated | Returned in response to a write request when authentication fails (including the case where an old nonce was used). |
| 0x81 | Invalid value | Returned when any invalid value is provided or the data received has an unexpected number of bytes. |
| 0x82 | No user consent | Returned in response to a write request with data ID *0x04: Read ephemeral identity key with user consent* when the device isn't in pairing mode. |

***Table 7:** GATT error codes.*

#### Read the beacon's parameter

The Seeker can query the Provider for the beacon's parameters by performing a
write operation to the characteristic consisting of a request from table 2 with
data ID 0x00. The Provider verifies that the provided one-time authentication
key matches any of the account keys stored on the device.

If verification fails the Provider returns an unauthenticated error.

On success, the Provider notifies with a response from table 6 with data ID
0x00. The Provider constructs the data segment as follows:

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Calibrated power | The calibrated power as received at 0m (a value in the range \[-100, 20\]). Represented as a signed integer, with 1 dBm resolution. |
| 1 - 4 | uint32 | Clock value | The current clock value in seconds (big endian). |
| 5 | uint8 | Curve selection | The elliptic curve being used for encryption: - 0x00 (default): SECP160R1 - 0x01: SECP256R1 (requires extended advertising) |
| 6 | uint8 | Components | The number of components capable of ringing: - 0x00: Indicates that the device is incapable of ringing. - 0x01: Indicates that only a single component is capable of ringing. - 0x02: Indicates that two components, left and right buds, are capable of ringing independently. - 0x03: Indicates that three components, left and right buds and the case, are capable of ringing independently. |
| 7 | uint8 | Ringing capabilities | The supported options are: - 0x00: Ringing volume selection not available. - 0x01: Ringing volume selection available. If set, the Provider must accept and handle 3 volume levels as indicated in [Ring operation](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#ring). |
| 8-15 | byte array | Padding | Zero padding for AES encryption. |

The data should be AES-ECB-128 encrypted with the account key used for
authenticating the request.

The authentication segment is defined as the first 8 bytes of
`HMAC-SHA256(account key, protocol major version number || the last nonce read
from the characteristic || data ID || data length || additional data after
encryption || 0x01)`.

#### Read the beacon's provisioning state

The Seeker can query the Provider for the beacon's provisioning state by
performing a write operation to the characteristic consisting of a request from
table 2 with data ID 0x01.
The Provider verifies that the provided one-time authentication key matches any
of the account keys stored on the device.

If verification fails, the Provider returns an unauthenticated error.

On success, the Provider notifies with a response from table 6 with data ID
0x01. The Provider constructs the data segment as follows:

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Provisioning state | A bitmask having the following values: - Bit 1 (0x01): Set if an ephemeral identity key is set for the device. - Bit 2 (0x02): Set if the provided one-time authentication key matches the owner account key. |
| 1 - 20 or 32 | byte array | Current ephemeral identifier | 20 or 32 bytes (depending on the encryption method being used) indicating the current ephemeral ID advertised by the beacon, if one is set for the device. |

The authentication segment is defined as the first 8 bytes of
`HMAC-SHA256(account key, protocol major version number || the last nonce read
from the characteristic || data ID || data length || additional data || 0x01)`.

#### Set an ephemeral identity key

To provision an unprovisioned Provider as an FHN beacon, or change the
ephemeral identity key of already provisioned Provider, the Seeker performs a
write operation to the characteristic consisting of a request from table 2 with
data ID 0x02. The Provider verifies that:

- The provided one-time authentication key matches the owner account key.
- If a hash of an ephemeral identity key was provided, the hashed ephemeral identity key matches the current ephemeral identity key.
- If a hash of an ephemeral identity key wasn't provided, verify that the Provider wasn't already provisioned as an FHN beacon.

If verification fails, the Provider returns an unauthenticated error.

On success, the ephemeral identity key is recovered by AES-ECB-128 decrypting it
using the matched account key. The key should be persisted on the device, and
from that point on the Provider should start advertising FHN frames. The new
ephemeral identity key takes effect immediately after the BLE connection is
terminated.
The Provider notifies with a response from table 6 with data ID 0x02.

The authentication segment is defined as the first 8 bytes of
`HMAC-SHA256(account key, protocol major version number || the last nonce read
from the characteristic || data ID || data length || 0x01)`.

#### Clear the ephemeral identity key

To unprovision the beacon portion of the Provider, the Seeker performs a write
operation to the characteristic, consisting of a request from table 2 with data
ID 0x03. The Provider verifies that:

- The provided one-time authentication key matches the owner account key.
- The hashed ephemeral identity key matches the current ephemeral identity key.

If the Provider isn't provisioned as an FHN beacon or verification fails, it
returns an unauthenticated error.

On success, the Provider forgets the key and stops advertising FHN frames.
The Provider notifies with a response from table 6 with data ID 0x03.
The authentication segment is defined as the first 8 bytes of
`HMAC-SHA256(account key, protocol major version number || the last nonce read
from the characteristic || data ID || data length || 0x01)`.

#### Read the ephemeral identity key with user consent

This option is only available to recover a lost key, as the key is only stored
locally by the Seeker. As such, this capability is available only when the
device is in pairing mode or for some limited time after a physical button was
pressed on the device (which constitutes user consent).

The Seeker must store the recovery key on the backend to be able to recover the
cleartext key, but it doesn't store the EIK itself.

To read the EIK, the Seeker performs a write operation to the characteristic,
consisting of a request from table 3 with data ID 0x04. The Provider verifies
that:

- The hashed recovery key matches the expected recovery key.
- The device is in EIK recovery mode.

If verification fails, the Provider returns an unauthenticated error.

If the device isn't in pairing mode, the Provider returns a No User Consent
error.

On success, the Provider notifies with a response from table 6 with data ID
0x04.

The authentication segment is defined as the first 8 bytes of
`HMAC-SHA256(recovery key, protocol major version number || the last nonce read
from the characteristic || data ID || data length || additional data || 0x01)`.

#### Ring operation

The Seeker can ask the Provider to play a sound by performing a write operation
to the characteristic, consisting of a request from table 4 with data ID 0x05.
The Provider constructs the data segment as follows:

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Ring operation | A bitmask having the following values: - Bit 1 (0x01): Ring right - Bit 2 (0x02): Ring left - Bit 3 (0x04): Ring case - 0xFF: Ring all components - 0x00: Stop ringing |
| 1 - 2 | uint16 | Timeout | The timeout in deciseconds. Must not be zero and must not be greater than the equivalent of 10 minutes. The Provider uses this value to determine how long it should ring before silencing itself. The timeout overrides the one already in effect if any component of the device is already ringing. If *ring operation* is set to 0x00, the timeout is ignored. |
| 3 | uint8 | Volume | - 0x00: Default - 0x01: Low - 0x02: Medium - 0x03: High The exact meaning of these values is implementation dependent. |

Upon receiving the request, the Provider verifies that:

- The provided one-time authentication key matches the ring key.
- The requested state matches the components that can ring.

If the Provider isn't provisioned as an FHN beacon or verification fails, it
returns an unauthenticated error. However, if the Provider has unwanted tracking
protection active, and the triggering unwanted tracking protection request had
the skip ringing authentication flag turned on, the Provider should skip that
check. The authentication data is still expected to be provided by the Seeker,
but it could be set to an arbitrary value.

When ringing starts or terminates a notification is sent as indicated in table 6
with data ID 0x05. The contents of the notification are defined as follows:

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Ringing state | - 0x00: Started - 0x01: Failed to start or stop (all requested components are out of range) - 0x02: Stopped (timeout) - 0x03: Stopped (button press) - 0x04: Stopped (GATT request) |
| 1 | uint8 | Ringing components | A bitmask of the components actively ringing, as defined in the request. |
| 2 - 3 | uint16 | Timeout | The remaining time for ringing in deciseconds. If the device has stopped ringing, 0x0000 should be returned. |

The authentication segment is defined as the first 8 bytes of
`HMAC-SHA256(ring key, protocol major version number || the nonce used to
initiate the ringing command || data ID || data length || additional data ||
0x01)`.

If the device is already in the requested ring state when a request to ring or
stop ringing is received, the Provider should send a notification with a ringing
state or either 0x00: Started or 0x04: Stopped (GATT request), respectively.
This request overrides the existing state's parameters, so that the ringing
duration can be extended.

If the Provider has a physical button (or touch sense is enabled), that button
should stop the ringing function if pressed while the ringing is active.

> [!NOTE]
> **Note:** For Providers that include on-head detection, consider checking that the device isn't on head before ringing at maximum volume. If on-head detection isn't supported or isn't reliable, increase the volume gradually (so that the user has time to stop ringing or remove their ear buds).

> [!NOTE]
> **Note:** The Provider should continue ringing regardless of the connection status of the Seeker that requested ringing. This prevents a situation where the device stops ringing because the connection is lost due to the client moving too far away from the device. Then the device can't be found because it stopped ringing and is too far from the client for it to request ringing again.

#### Get the beacon's ringing state

To get the ringing state of the beacon, the Seeker performs a write operation to
the characteristic, consisting of a request from table 4 with data ID 0x06. The
Provider verifies that the provided one-time authentication key matches the ring
key.

If the Provider isn't provisioned as an FHN beacon or if verification fails,
the Provider returns an unauthenticated error.

On success, the Provider notifies with a response from table 6 with data ID
0x06. The Provider constructs the data segment as follows:

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Ringing components | The components actively ringing, as defined in the ringing request. |
| 1 - 2 | uint16 | Timeout | The remaining time for ringing in deciseconds. Note that if the device isn't ringing, 0x0000 should be returned. |

The authentication segment is defined as the first 8 bytes of
`HMAC-SHA256 (ring key, protocol major version number || the last nonce read
from the characteristic || data ID || data length || additional data || 0x01)`.

#### Unwanted tracking protection mode

Unwanted tracking protection mode is intended to let any client identify abusive
devices with no server communication. By default, the Provider should rotate all
identifiers as described in [ID rotation](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#id-rotation). The Find Hub service
can relay an unwanted tracking protection mode activation request through the
Find Hub network. By doing so, the service causes the Provider to temporarily
use a fixed MAC address, allowing clients to detect the device and warn the user
of possible unwanted tracking.

To activate or deactivate the unwanted tracking protection mode of the beacon,
the Seeker performs a write operation to the characteristic, consisting of a
request from table 5 with data ID 0x07 or 0x08 respectively.

**When enabling unwanted tracking protection mode**

The Provider constructs the data segment as follows:

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Control Flags | - 0x01: Skip ringing authentication. When set, ringing requests aren't authenticated while in unwanted tracking protection mode. If no flag is being set (the byte is all zeros), it's valid to omit the data section altogether and send an empty data section. The flags are in effect only until the unwanted tracking protection mode is deactivated. |

The Provider verifies that the provided one-time authentication key matches the
unwanted tracking protection key. If the Provider isn't provisioned as an FHN
beacon or verification fails, it returns an unauthenticated error.

When unwanted tracking protection mode is activated, the beacon should reduce
MAC private address rotation frequency to once per 24 hours. The advertised
ephemeral identifier should keep rotating as usual. The frame type should be set
to 0x41. The state is also reflected in the [hashed flags](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#hashed-flags)
section.

**When disabling unwanted tracking protection mode**

The Provider verifies that:

- The provided one-time authentication key matches the unwanted tracking protection key.
- The hashed ephemeral identity key matches the current ephemeral identity key.

If the Provider isn't provisioned as an FHN beacon or verification fails, the
Provider returns an unauthenticated error.

When unwanted tracking protection mode is deactivated, the beacon should start
rotating the MAC address at a normal rate again, synchronized with ephemeral
identifier rotation. The frame type should be set back to 0x40. The state is
also reflected in the [hashed flags](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#hashed-flags) section.

On success, the Provider notifies with a response from table 6 with data ID 0x07
or 0x08.

The authentication segment is defined as the first 8 bytes of
`HMAC-SHA256(unwanted tracking protection key, protocol major version number ||
the last nonce read from the characteristic || data ID || data length ||
0x01)`.

### Precision Finding

This section details flow and additional operations needed for precision
finding. The same rules for GATT characteristic and Authentication apply here as
defined in the GATT specification section. Precision Finding is optional.

The type of precision finding depends on the type of the ranging technologies
supported on devices engaged in precision finding. Supported ranging
technologies can be found in the [Ranging: Out-of-band message sequence and
payload](https://source.android.com/docs/core/connect/ranging-oob-spec)
specification. Later sections explore what kind of precision finding experience
can be expected based on the used ranging technology.

#### Precision Finding flow

This section explores the FHNA message flow for Precision Finding. Figure 1
shows the flow of the messages, and the paragraphs explain each message in more
detail.

![Precision Finding message flow](https://developers.google.com/static/nearby/fast-pair/images/precision_finding_spec_flow_diagram.png)

*Fig. 1 Typical Precision Finding message flow*

The Initiator device is the device that has the Find Hub app, and where
the Precision Finding feature was engaged from. The initiator is the device that
is trying to find the other device.

The Responder device is the device that is trying to be found by the Initiator
device.

The Initiator device sends a Ranging Capability Request message to the Responder
device, where it will list the ranging technologies that it's interested in
learning about from the Responder device. The responder device will reply back
with the Ranging Capability Response notification, containing information about
which ranging technologies are supported and what are their capabilities. The
responder will include information only requested by the initiator. The list of
capabilities will be sorted based on the priority of the ranging technology the
Responder device favors, with first in the list having the highest priority.

The Initiator device will then follow up with a Ranging Configuration message,
where it will define the configuration for each ranging technology it wants to
range with. Upon receiving this message, the Responder device must start ranging
for applicable technologies using the provided configurations. The responder
device will send back a Ranging Configuration response notification, which
contains the results of whether each individual ranging technology started
successfully. Some ranging technologies have to be started on both the Initiator
and the Responder device in order to have a successful ranging session, while
for others it is only necessary that it is started on the Initiator device,
still, the Responder device must reply back with a success result for such
technologies. More about specific ranging technology behavior can be found in
later sections.

Once the Initiator device is ready to stop the Precision Finding session, it
will send a Stop Ranging message to the responder, indicating which ranging
technologies must stop ranging. The Responder device will respond with a Stop
Ranging Response notification, indicating that it successfully stopped ranging
with the requested ranging technologies.

In the case of FHNA BLE GATT communication channel disconnecting mid Precision
Finding session, but while some of the ranging technologies are still ranging,
the responder device will implement a timeout mechanism to ensure that it
doesn't range indefinitely. Details will depend on each use case.

Note, the responder device mustn't assume the order of the operations will
always be the same. E.g. the responder device must be able to handle multiple
Ranging Capability requests operations in a row, or even a direct Ranging
Configuration operation without the preceding capability request.

#### Precision Finding Operations

Table 8 shows FHNA operations defined by this document that are required for
Precision Finding. Each subsection defines the FHNA message for each of the
operations, while the **Additional Data** field contents refer to [Ranging:
Out-of-band message sequence and
payload](https://source.android.com/docs/core/connect/ranging-oob-spec)
specification.

| Operation | Data Id | Description |
|---|---|---|
| Ranging Capability Request | 0x0A | The capability request operation that will be sent by the Initiator device to the Responder device. Data contents of this operation will list all ranging technologies the Initiator wants to know about from the Responder device. |
| Ranging Capability Response | 0x0A | This is the notification response to the Ranging Capability Request operation. It contains information about capabilities for each supported ranging technology that were requested by the initiator. |
| Ranging Configuration | 0x0B | Ranging Configuration operation contains the configurations for ranging technologies the Initiator device wants to start ranging with the Responder device. |
| Ranging Configuration Response | 0x0B | This is the notification response to the Ranging Configuration operation. It contains data about whether the Responder device successfully started ranging with the requested ranging technologies based on the provided configuration. |
| RFU | 0x0C | The operation with this Data Id is not used and it's reserved for future use. |
| Stop Ranging | 0x0D | The Stop Ranging operation sent by the Initiator device contains information about which ranging technologies the Responder device must stop ranging with. |
| Stop Ranging Response | 0x0D | This is the notification response to the Stop Ranging operation. It contains data whether the stop operation for specific ranging technology was successful or not. |

***Table 8:** Precision Finding Operations.*

##### Ranging Capability Request operation

Table 9 defines the Ranging Capability Request message.

| Octet | Data type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | **0x0A** - Ranging Capability Request operation |
| 1 | uint8 | Data length | varies |
| 2 | byte array | One-time authentication key | The first 8 bytes of HMAC-SHA256(Account Key, Protocol major version number \|\| the last nonce read from the characteristic \|\| Data ID \|\| Data length \|\| Additional Data). |
| 10 | byte array | Additional Data | **Ranging Capability Request** message as defined in the [Ranging: Out-of-band message sequence and payload](https://source.android.com/docs/core/connect/ranging-oob-spec) specification (both header and payload) |

***Table 9:** Ranging Capability Request.*

##### Ranging Capability Response operation

Table 10 defines the Ranging Capability Response message.

| Octet | Data type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | 0x0A: Ranging Capability Response |
| 1 | uint8 | Data length | varies |
| 2 | byte array | One-time authentication key | The first 8 bytes of HMAC-SHA256(Account Key, Protocol major version number \|\| the last nonce read from the characteristic \|\| Data ID \|\| Data length \|\| Additional Data \|\| 0x01). |
| 10 | byte array | Additional Data | **Ranging Capability Response** message as defined in the [Ranging: Out-of-band message sequence and payload](https://source.android.com/docs/core/connect/ranging-oob-spec) specification (both header and payload) |

***Table 10:** Ranging Capability Response.*

##### Ranging Configuration operation

Table 11 defines the Ranging Configuration message.

| Octet | Data type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | **0x0B** - Set Ranging Configuration |
| 1 | uint8 | Data length | varies |
| 2 | byte array | One-time authentication key | The first 8 bytes of HMAC-SHA256(Account Key, Protocol major version number \|\| the last nonce read from the characteristic \|\| Data ID \|\| Data length \|\| Additional Data). |
| 10 | byte array | Additional Data | **Ranging Configuration** message as defined in the [Ranging: Out-of-band message sequence and payload](https://source.android.com/docs/core/connect/ranging-oob-spec) specification (both header and payload) |

***Table 11:** Ranging Configuration.*

##### Ranging Configuration Response operation

Table 12 defines the Ranging Configuration Response message.

| Octet | Data type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | **0x0B** - Set Ranging Configuration Response |
| 1 | uint8 | Data length | varies |
| 2 | byte array | One-time authentication key | The first 8 bytes of HMAC-SHA256(Account Key, Protocol major version number \|\| the last nonce read from the characteristic \|\| Data ID \|\| Data length \|\| Additional Data \|\| 0x01). |
| 10 | byte array | Additional Data | **Ranging Configuration Response** message as defined in the [Ranging: Out-of-band message sequence and payload](https://source.android.com/docs/core/connect/ranging-oob-spec) specification (both header and payload) |

***Table 12:** Ranging Configuration Response.*

##### Stop Ranging operation

Table 13 defines the Stop Ranging message.

| Octet | Data type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | **0x0D** - Ranging Stop |
| 1 | uint8 | Data length | varies |
| 2 | byte array | One-time authentication key | The first 8 bytes of HMAC-SHA256(Account Key, Protocol major version number \|\| the last nonce read from the characteristic \|\| Data ID \|\| Data length). |
| 10 | byte array | Additional Data | **Stop Ranging** message as defined in the [Ranging: Out-of-band message sequence and payload](https://source.android.com/docs/core/connect/ranging-oob-spec) specification (both header and payload) |

***Table 13:** Stop Ranging.*

##### Stop Ranging Response operation

Table 14 defines the Stop Ranging Response message.

| Octet | Data type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Data ID | **0x0D** - Ranging Stop Response |
| 1 | uint8 | Data length | varies |
| 2 | byte array | One-time authentication key | The first 8 bytes of HMAC-SHA256(Account Key, Protocol major version number \|\| the last nonce read from the characteristic \|\| Data ID \|\| Data length \|\| Additional Data \|\| 0x01). |
| 10 | byte array | Additional Data | **Stop Ranging Response** message as defined in the [Ranging: Out-of-band message sequence and payload](https://source.android.com/docs/core/connect/ranging-oob-spec) specification (both header and payload) |

***Table 14:** Stop Ranging Response.*

#### Unwanted tracking protection with Precision Finding

When unwanted tracking protection mode is activated, as described in the
unwanted tracking protection section, the same flow that applies to skipping
authentication checks for ringing messages also applies for all Precision
Finding messages defined in this document for devices that want to support
this feature.

#### Ranging Technology specifics for Precision Finding

This section contains details that are ranging technology specific.

##### Ultra-wideband (UWB) specifics

UWB specific details.

###### Precision Finding level

Precision Finding sessions using UWB as the ranging technology can expect to see
both distance and direction information. The ranging interval needs to be at
least 240ms, with 96ms preferred for optimal guidance.

###### Config Ids

Out-of-band configuration data exchanged for UWB doesn't contain a full set of
available configurable parameters that UWB requires to start an UWB ranging
session. Some parameters are implicitly selected by the chosen config Id.

Each config Id is a set of predefined UWB configuration parameters that is
[publicly
documented](https://developer.android.com/reference/android/ranging/uwb/UwbRangingParams).
For the Precision Finding use case, the responder device must support [config Id
6](https://developer.android.com/reference/android/ranging/uwb/UwbRangingParams#CONFIG_PROVISIONED_UNICAST_DS_TWR_VERY_FAST),
and optionally [config Id
3](https://developer.android.com/reference/android/ranging/uwb/UwbRangingParams#CONFIG_PROVISIONED_UNICAST_DS_TWR_VERY_FAST).

###### UWB Initiator and Responder

For the Precision Finding use case, the device noted as the Initiator device in
this document will be the UWB responder, and the device noted as the Responder
device in this document will be the UWB initiator. This is because the UWB
initiator device consumes less power than UWB responder does, and in most cases
the Responder device will be a peripheral with limited battery.

This means that the Responder device needs to indicate that it supports being a
UWB initiator role in the Ranging Capability Response message.

###### Other UWB related parameters

- Channel 9 must be supported
- For optimal guidance, a 96ms ranging interval is recommended, otherwise 240ms must be supported.
- Slot duration of 1ms is recommended for battery savings, but 2ms is also supported.
- The UWB chip must be at least FIRA v1.2 + P-STS compliant.
- BPRF is mandatory, HPRF is recommended but optional. The supported or selected mode is determined by the supported or selected preamble index.
- Session security type: P-STS

##### BLE Channel Sounding (CS) specifics

BLE CS specific details.

###### Precision Finding level

Precision Finding sessions using CS as the ranging technology will cause
distance only measurements, directionality is not provided at this moment.

###### Required bond between devices

Precision Finding sessions using Channel Sounding won't work if devices are
not bonded. An existing bond between the initiator and the responder device is
required. This specification does not provide a way for creating a bond between
the devices. Instead, it is up to the developer of the use case to establish
this bond between the devices.

###### Action required by the responder side for CS

Unlike UWB, where both devices are required to call the UWB start ranging and
stop ranging API explicitly, for CS, only the initiator device is required to
start CS ranging by calling the Bluetooth stack, the rest of the initialization
on the responder side happens in-band using Bluetooth (BT). This means that upon
receiving the Ranging Configuration message or the Stop Ranging message for CS,
the responder side doesn't have to do anything if BT is enabled, other than
reply with the Ranging Configuration Response message notification. The
responder device could potentially use those messages as a trigger to update the
UI where a screen is present, or regardless of having a screen it could be used
for visual feedback on the devices state, for example blink the device LEDs.

##### Wi-Fi NAN RTT

Wi-Fi NAN RTT specific details.

###### Precision Finding level

Precision Finding sessions using Wi-Fi NAN RTT as the ranging technology will
cause distance only measurements, directionality is not provided at this moment.

##### BLE RSSI

BLE RSSI specific details.

###### Precision Finding level

Precision Finding sessions using only BLE RSSI as the ranging technology won't
be able to get either the distance or the direction information, due to BLE RSSI
not being an accurate ranging technology. Instead, the user will see guidance
indicating that device is close or device is far.

## Advertised frames

After provisioning, the Provider is expected to advertise FHN frames at least
once every 2 seconds. If Fast Pair frames are advertised, the Provider should
interleave the FHN frames within the regular Fast Pair advertisements. For
example, every two seconds, the Provider should advertise seven Fast Pair
advertisements and one FHN advertisement.

The conducted Bluetooth transmit power for FHN advertisements should be set to
at least 0 dBm.

> [!NOTE]
> **Note:** It is recommended to advertise the FHN frames even when the device is in low power mode, as this allows finding the device if lost. For some devices, it might not be possible to advertise when the device is turned off due to the battery life implications. In such cases, it is strongly recommended to periodically wake up the device and advertise for a short period of time (e.g. wake up every 10 minutes and advertise for 10 seconds).

The FHN frame carries a public key used to encrypt location reports by any
supporting client that contributes to the crowdsourcing network. Two types of
elliptic curve keys are available: a 160-bit key that fits legacy BLE 4 frames,
or 256-bit key that requires BLE 5 with extended advertising capabilities. The
Provider's implementation determines which curve is used.

> [!NOTE]
> **Note:** Using 256-bit keys means that older phones that don't support BLE 5 can't scan and report for advertising devices, thus reducing the size of the network.

An FHN frame is structured as follows.

| Octet | Value | Description |
|---|---|---|
| 0 | 0x02 | Length |
| 1 | 0x01 | Flags data type value |
| 2 | 0x06 | Flags data |
| 3 | 0x18 or 0x19 | Length |
| 4 | 0x16 | Service data data type value |
| 5 | 0xAA | 16-bit service UUID |
| 6 | 0xFE | ... |
| 7 | 0x40 or 0x41 | FHN frame type with unwanted tracking protection mode indication |
| 8..27 |   | 20-byte ephemeral identifier |
| 28 |   | [Hashed flags](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#hashed-flags) |

***Table 15:** FHN frame supporting a 160-bit curve.*

Table 16 shows the byte offsets and values for a 256-bit curve.

| Octet | Value | Description |
|---|---|---|
| 0 | 0x02 | Length |
| 1 | 0x01 | Flags data type value |
| 2 | 0x06 | Flags data |
| 3 | 0x24 or 0x25 | Length |
| 4 | 0x16 | Service data data type value |
| 5 | 0xAA | 16-bit service UUID |
| 6 | 0xFE | ... |
| 7 | 0x40 or 0x41 | FHN frame type with unwanted tracking protection mode indication |
| 8..39 |   | 32-byte ephemeral identifier |
| 40 |   | [Hashed flags](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#hashed-flags) |

***Table 16:** FHN frame supporting a 256-bit curve.*

### Ephemeral identifier (EID) computation

A random is generated by AES-ECB-256 encrypting the following data structure
with the ephemeral identity key:

| Octet | Field | Description |
|---|---|---|
| 0 - 10 | Padding | Value = 0xFF |
| 11 | K | Rotation period exponent |
| 12 - 15 | TS\[0\]...TS\[3\] | Beacon time counter, in 32-bit big-endian format. The K lowest bits are cleared. |
| 16 - 26 | Padding | Value = 0x00 |
| 27 | K | Rotation period exponent |
| 28 - 31 | TS\[0\]...TS\[3\] | Beacon time counter, in 32-bit big-endian format. The K lowest bits are cleared. |

***Table 17:** Construction of a pseudorandom number.*

> [!NOTE]
> **Note:** The device is assumed to have a 32-bit time counter in seconds.

> [!NOTE]
> **Note:** Rotation period exponent is fixed and set to 10, corresponding to 1024 seconds.

The result of this computation is a 256-bit number, denoted `r'`.

For the rest of the calculation, `SECP160R1` or `SECP256R1` are used for
elliptic curve cryptographic operations. See curve definitions in
[SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/SEC2-Ver-1.0.pdf), which defines `Fp`, `n` and `G`
referenced next.

`r'` is now projected to the finite field `Fp` by calculating `r = r' mod n`.
Finally, compute `R = r * G`, which is a point on the curve representing the
public key being used. The beacon advertises `Rx`, which is the `x` coordinate
of `R`, as its ephemeral identifier.

### Hashed flags

The hashed flags field is calculated as follows (bits are referenced from most
significant to least significant):

- Bits 0-4: Reserved (set to zeros).
- Bits 5-6 indicates the battery level for the device as follows:
  - 00: Battery level indication unsupported
  - 01: Normal battery level
  - 10: Low battery level
  - 11: Critically low battery level (battery replacement needed soon)
- Bit 7 is set to 1 if the beacon is in unwanted tracking protection mode, and 0 otherwise.

To produce the final value of this byte, it is xor-ed with the least significant
byte of `SHA256(r)`.

Note that r should be aligned to the curve's size. Add zeros as most significant
bits if its representation is shorter than 160 or 256 bits, or the most
significant bits should be truncated if its representation is larger than 160 or
256 bits.

If the beacon doesn't support battery level indication, and isn't in unwanted
tracking protection mode, it's allowed to omit this byte entirely from the
advertisement.

### Encryption with EID

> [!NOTE]
> **Note:** The following details for encryption and decryption with EIDs are only included for completeness of the specification. Only the Seeker implements these, not the Provider.

To encrypt a message `m`, a sighter (having read `Rx` from the beacon) would do
the following:

1. Choose a random number `s` in `Fp`, as defined in the [EID computation](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#eid-computation) section.
2. Compute `S = s * G`.
3. Compute `R = (Rx, Ry)` by substitution in the curve equation and picking an arbitrary `Ry` value out of the possible results.
4. Compute the 256-bit AES key `k = HKDF-SHA256((s * R)x)` where `(s * R)x` is the `x` coordinate of the curve multiplication result. Salt isn't specified.
5. Let `URx` and `LRx` be the upper and lower 80-bits of `Rx`, respectively, in big-endian format. In a similar way, define `USx` and `LSx` for `S`.
6. Compute `nonce = LRx || LSx`.
7. Compute `(m', tag) = AES-EAX-256-ENC(k, nonce, m)`.
8. Send `(URx, Sx, m', tag)` to the owner, possibly through an untrusted remote service.

### Decryption of values encrypted with EID

The owner's client, which is in possession of the EIK and the rotation period
exponent, decrypts the message as follows:

1. Given `URx`, obtain the beacon time counter value on which `URx` is based. This can be done by the owner's client computing `Rx` values for beacon time counter values for the recent past and near future.
2. Given the beacon time counter value on which `URx` is based, compute the anticipated value of `r` as defined in the [EID computation](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#eid-computation) section.
3. Compute `R = r * G`, and verify a match to the value of `URx` provided by the sighter.
4. Compute `S = (Sx, Sy)` by substitution in the curve equation and picking an arbitrary `Sy` value out of the possible results.
5. Compute `k = HKDF-SHA256((r * S)x)` where `(r * S)x` is the `x` coordinate of the curve multiplication result.
6. Compute `nonce = LRx || LSx`.
7. Compute `m = AES-EAX-256-DEC(k, nonce, m', tag)`.

## ID rotation

A resolvable (RPA) or non-resolvable (NRPA) BLE address must be used for
advertising FHN frames. RPA is required for LE Audio (LEA) devices and is
recommended for other devices, with the exception of locator tags that don't
use bonding.

Fast Pair advertisement, FHN advertisement and the corresponding BLE address(es)
should rotate at the same time. Rotation should happen every 1024 seconds on
average. The precise point at which the beacon starts advertising the new
identifier must be randomized within the window.

The recommended approach to randomize the rotation time is to set it to the next
anticipated rotation time (if no randomization was applied) plus a positive
randomized time factor in the range of 1 to 204 seconds.

When the device is in unwanted tracking protection mode, the BLE address of the
FHN advertisement should be fixed, but the RPA for FP non-discoverable
advertisement (such as Fast Pair) must keep rotating. It's acceptable to use
different addresses for the different protocols.

## Recovery from power loss

Resolving the ephemeral identifier is strongly tied to its clock value at the
time of the advertisement, so it's important that the Provider can recover its
clock value if there's a power loss. It is recommend that the Provider writes
its current clock value to nonvolatile memory at least once per day, and that at
boot time the Provider checks the NVM to see if there's a value present from
which to initialize. Resolvers of the ephemeral identifier would implement
resolution over a time window sufficient to allow for both reasonable clock
drift and this type of power loss recovery.

Providers should still make all efforts to minimize clock drifts, as the
resolution time window is limited. At least one additional clock synchronization
method should be implemented (advertising [non-discoverable Fast Pair frames](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#locator-tag) or implementing the [message stream](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#message-stream)).

## Fast Pair implementation guidelines

This section describes special aspects of the Fast Pair implementation on
Providers that support FHN.

### Locator tag specific guidelines

- If the Provider was paired, but FHN wasn't provisioned within 5 minutes (or if an OTA update was applied while the device is paired but not FHN-provisioned), the Provider should revert to its factory configuration and clear the stored account keys.
- After the Provider is paired, it shouldn't change its MAC address until FHN is provisioned or until 5 minutes pass.
- If the ephemeral identity key is cleared from the device, the device should perform a factory reset and clear the stored account keys as well.
- The Provider should reject normal Bluetooth pairing attempts and accept only Fast Pair pairing.
- The Provider must include a mechanism that lets users temporarily stop advertising without factory resetting the device (for example, pressing a combination of buttons).
- After a power loss, the device should advertise non-discoverable Fast Pair frames until the next invocation of [read beacon parameters](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn#read-beacon-param). This lets the Seeker detect the device and synchronize the clock even if a significant clock drift occurred.
- When advertising non-discoverable Fast Pair frames, UI indications shouldn't be enabled.
- Discoverable Fast Pair frames shouldn't be advertised while the Provider is provisioned for FHN.
- The Provider shouldn't expose any identifying information information in an unauthenticated manner (e.g. names or identifiers).

### Classic Bluetooth device-specific guidelines

This section describes special aspects of classic Bluetooth devices that support
FHN.

#### FHN provisioning of already paired devices

The Provider isn't always provisioned for FHN when pairing with the Seeker, but
a while after that. In that case, the Provider might not have an up-to-date BLE
MAC address that's required to establish a GATT connection. The Provider must
support at least one of the following ways for the Seeker to get its BLE address
while it's already paired:

- The Provider can periodically advertise the [Fast Pair account data](https://developers.google.com/nearby/fast-pair/specifications/service/provider#%0AAdvertisingWhenNotDiscoverable) that lets the Seeker find its BLE address through a BLE scan.  
  This approach suits Providers that don't implement the message stream.
- The Provider can provide this data through the [Fast Pair message stream](https://developers.google.com/nearby/fast-pair/specifications/extensions/messagestream "Fast Pair message stream") over classic Bluetooth.  
  This approach suits Providers that don't advertise Fast Pair frames while connected to the Seeker over Bluetooth.

Supporting both approaches increases the chances that the user can provision the
device for FHN.

#### Fast Pair message stream

The Provider can implement [Fast Pair message stream](https://developers.google.com/nearby/fast-pair/specifications/extensions/messagestream "Fast Pair message stream") and use it to notify the
Seeker about [Device information](https://developers.google.com/nearby/fast-pair/specifications/extensions/deviceinformation "Device information"). Implementing the message stream enables
certain features as described in this section.

The Provider should send device information messages once every time the
Message Stream is established.

**Firmware version (device information code 0x09) and the tracking capability**

When a firmware update adds FHN support to the Provider, a connected Seeker can
notify the user about that and offer to provision it. Otherwise, the user has to
navigate to the Bluetooth device list manually to initiate FHN provisioning.

To allow that, the Provider should use the Firmware version property (code 0x09)
to report a string value that represents the firmware version. In addition, the
Provider should support the protocol that lets the Seeker know about [Capability
changes](https://developers.google.com/nearby/fast-pair/specifications/extensions/changecapability "Capability changes") due to firmware updates.

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Device information event | 0x03 |
| 1 | uint8 | Firmware version | 0x09 |
| 2 - 3 | uint16 | Additional data length | *varies* |
| var | byte array | Version string | *varies* |

***Table 18:** Device information event: updated firmware version.*

Upon receiving a capability update request (0x0601), if the Provider has enabled
support for FHN tracking, it should respond as shown in table 12.

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Device capability sync event | 0x06 |
| 1 | uint8 | FHN tracking | 0x03 |
| 2 - 3 | uint16 | Additional data length | 0x0007 |
| 4 | uint8 | FHN provisioning state | 0x00 if unprovisioned; 0x01 if provisioned by any account |
| 5 - 10 | byte array | The current BLE MAC address of the device | *varies* |

***Table 19:** Device capability sync event: added tracking capability.*

**Current ephemeral identifier (device information code 0x0B)**

The Provider can use the *current ephemeral identifier (code 0x0B)* to report
the current EID and clock value when the Provider is provisioned for FHN, to
sync the Seeker in case of a clock drift (for example, due to drained battery).
Otherwise, the Seeker initiates a more expensive and less reliable connection
for this purpose.

| Octet | Data Type | Description | Value |
|---|---|---|---|
| 0 | uint8 | Device information event | 0x03 |
| 1 | uint8 | Current ephemeral identifier | 0x0B |
| 2 - 3 | uint16 | Additional data length | 0x0018 or 0x0024 |
| 4 - 7 | byte array | Clock value | Example: 0x13F9EA80 |
| 8 - 19 or 31 | byte array | Current EID | Example: 0x1122334455667788990011223344556677889900 |

***Table 20:** Device information event: clock sync.*

## Factory reset

For devices that support factory reset: if a factory reset is performed, the
Provider must stop beaconing and wipe out the ephemeral identity key and all
stored account keys, including the owner's account key.

After a factory reset (either manual or programmatic), the Provider shouldn't
start advertising Fast Pair right away, to prevent the pairing flow to start
immediately after the user deletes the device.

## Unwanted tracking prevention

Certified FHN devices must also meet the requirements in the implementation
version of the cross-platform specification for
[Detecting Unwanted Location Trackers](https://datatracker.ietf.org/doc/draft-ietf-dult-accessory-protocol/) (DULT).

Relevant guidelines specific to FHN to be compliant with DULT spec:

- Any FHN compatible device must be registered in the Nearby Device Console, and have the "Find Hub" capability activated.
- The device must implement the Accessory Non-Owner service and characteristic defined in the implementation version of the DULT spec, including the *Accessory Information* operations and *Non-owner controls*.
- During the backward compatibility period, as defined in the DULT spec, there are no changes to the advertised frame as defined in this document.
- "Unwanted tracking protection mode" defined in this document maps to the "separated state" defined by the DULT spec.
- Guidelines for implementing the *Accessory Information* opcodes:
  - Get_Product_Data should return the model ID provided by the console, zero padded to fit the 8-byte requirement. For example, model ID 0xFFFFFF is returned as 0x0000000000FFFFFF.
  - Get_Manufacturer_Name and Get_Model_Name should match the values provided in the console.
  - Get_Accessory_Category can return the generic "Location Tracker" value if no other category better fits the type of the device.
  - Get_Accessory_Capabilities must indicate the support for ringing as well as BLE identifier lookup.
  - Get_Network_ID should return Google's identifier (0x02).
- Guidelines for implementing the *Get_Identifier* opcode:
  - The operation should only return a valid response for 5 minutes after the user activated the 'identification' mode, which requires a combination of button presses. A visual or audio signal should indicate to the user that the provider entered that mode. The model-specific instructions for activating that mode must be provided to Google as a requirement for certification and at least 10 days prior to any update or modification to the instructions.
  - The response is constructed as: the first 10 bytes of current ephemeral identifier, followed by the first 8 bytes of `HMAC-SHA256(recovery key, the
    truncated current ephemeral identifier)`.
- Guidelines for implementing Identifier over NFC:
  - As a URL, use `find-my.googleapis.com/lookup`.
  - As the `e` parameter, use the same response as constructed for *Get_Identifier*, hex encoded.
  - As the `pid` parameter, use the same response as constructed for *Get_Product_Data*, hex encoded.
- It is mandatory for the device to include a sound maker and support the ringing function. Per the DULT spec, the sound maker must emit a sound with minimum 60 Phon peak loudness as defined by ISO 532-1:2017.
- Guidelines for implementing the *Sound_Start* opcode:
  - The command should trigger ringing in all available components.
  - The maximal supported volume should be used.
  - The recommended duration for ringing is 12 seconds.
- Locator tags must include a mechanism that lets users temporarily stop advertising without factory resetting the device (for example, pressing a combination of buttons).
  - The disablement instructions must be documented in a publicly available URL and provided to Google as a requirement for certification and at least 10 days prior to any update or modification to the instructions.
  - The URL should support localization. Depending on the client, the language will be provided either as a query param ("hl=en") or using the "accept-language" HTTP header.

## Switchable protocol guidelines

- Only one protocol should be used at a time. Ensure that no more than one network can operate on the device simultaneously. This requirement is needed to ensure that there is no commingling of sensitive user data between varying protocols.
- It is suggested to incorporate a hard reset workflow into the device that allows a user to re-setup a device with a different network.
- The process of updating a device to a network should be user friendly and equitable between networks. A user must be able to choose which network they want to use without giving preference to one of the networks. This flow needs to be approved by the Google team.

## Firmware updates

The process and distribution of OTA updates should be managed by the partner
using their own Mobile or Web app workflow.

Fast Pair supports delivering notifications to the user, informing of available
OTA updates. In order to use this mechanism:

- The latest firmware version should be updated in the Nearby Device Console.
- A companion App should be set in the Nearby Device Console. It should support the [firmware update intent](https://developers.google.com/nearby/fast-pair/companion-apps#firmware_update_intent "firmware update intent").
- Provider should implement the [Firmware revision](https://developers.google.com/nearby/fast-pair/specifications/characteristics#FirmwareRevision "Firmware revision") GATT characteristic.

To prevent tracking, access to the *Firmware revision* characteristic should be
restricted. Seeker will first read the provisioning state and provide an
authentication key, as defined in this specification, and only then read the
firmware revision. This will be done over the same connection. If an attempt is
made to read the firmware revision, and the Provider isn't bonded nor an
authenticated operation was successfully completed over that same connection,
the Provider should return an unauthenticated error.

## Compatibility

Find Hub network requires location services and Bluetooth to be turned on.
Requires cell service or internet connection. Works on Android 9+ and in certain
countries for age-eligible users.

## Changelog

| FHN Version | Date | Comment |
|---|---|---|
| v1 |   | Initial release of the FHN spec for early access. |
| v1.1 | Feb 2023 | - Added a cleartext indication of unwanted tracking protection mode. - Added an option to skip authentication of ringing requests while in unwanted tracking protection mode. |
| v1.2 | Apr 2023 | - Updated the definition of an owner's AK. - Added a recommendation for recovering from power loss in locator tags. - Added a clarification for MAC address randomization. - Added a clarification on MAC address rotation while in unwanted tracking protection mode. - Added a guideline on having a way to deactivate a locator tag. |
| v1.3 | Dec 2023 | - Added a clarification on identifying information exposed by locator tags. - Added a requirement to implement the unwanted tracking prevention specification. - Added guidelines for switchable protocol devices. |