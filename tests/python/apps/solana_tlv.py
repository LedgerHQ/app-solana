from typing import Union
from enum import IntEnum

def der_encode(value: int) -> bytes:
    # max() to have minimum length of 1
    value_bytes = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    if value >= 0x80:
        value_bytes = (0x80 | len(value_bytes)).to_bytes(1, 'big') + value_bytes
    return value_bytes

# https://ledgerhq.atlassian.net/wiki/spaces/TrustServices/pages/3736863735/LNS+Arch+Nano+Trusted+Names+Descriptor+Format+APIs#TLV-description
class FieldTag(IntEnum):
    TAG_STRUCTURE_TYPE = 0x01
    TAG_VERSION = 0x02
    TAG_TRUSTED_NAME_TYPE = 0x70
    TAG_TRUSTED_NAME_SOURCE = 0x71
    TAG_TRUSTED_NAME = 0x20
    TAG_CHAIN_ID = 0x23
    TAG_ADDRESS = 0x22
    TAG_TRUSTED_NAME_NFT_ID = 0x72
    TAG_TRUSTED_NAME_SOURCE_CONTRACT = 0x73
    TAG_CHALLENGE = 0x12
    TAG_NOT_VALID_AFTER = 0x10
    TAG_SIGNER_KEY_ID = 0x13
    TAG_SIGNER_ALGO = 0x14
    TAG_DER_SIGNATURE = 0x15

def format_tlv(tag: int, value: Union[int, str, bytes]) -> bytes:
    if isinstance(value, int):
        # max() to have minimum length of 1
        value = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    elif isinstance(value, str):
        value = value.encode()

    assert isinstance(value, bytes), f"Unhandled TLV formatting for type : {type(value)}"

    tlv = bytearray()
    tlv += der_encode(tag)
    tlv += der_encode(len(value))
    tlv += value
    return tlv

