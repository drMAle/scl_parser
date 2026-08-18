# MMS / IEC 61850 discovery decoder

The PCAP pipeline now supports the following discovery stages:

1. TPKT/COTP extraction from TCP/102 streams.
2. ASN.1 BER parsing.
3. MMS `GetNameList` request/response decoding and correlation.
4. MMS `GetVariableAccessAttributes` request/response decoding and correlation.
5. MMS `TypeSpecification` structural decoding.
6. Reconstruction of named MMS structure components into flattened IEC 61850-style DO/DA/SDI paths.

For a `GetVariableAccessAttributes` response, the decoder exposes:

- `mmsDeletable`;
- `typeSpecification` (structural BER/MMS type tree);
- `components` (flattened component paths and MMS types).

Example:

```text
GetVariableAccessAttributes: LD_Plant/MMXU1.TotW
  f       -> floating-point
  q       -> structure
  q.i     -> integer
```

The decoder deliberately does not infer CDC semantics solely from MMS type tags. Mapping a runtime type tree to IEC 61850 DO/DA/CDC semantics is a separate validation stage and should use the SCL/type-template information where available.

## DO / DA reconstruction

`GetVariableAccessAttributes` responses are now expanded into named component paths. The requested IEC 61850 object is retained as the runtime Data Object, while the components returned by the MMS `TypeSpecification` are exposed as Data Attribute / Structured Data Attribute evidence.

The decoder does not claim a CDC solely from a primitive MMS type. SCL/type-template correlation is required for authoritative IEC 61850 semantic typing.
