from typing import List, Generator, Optional
from enum import IntEnum
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU

from .solana_tlv import FieldTag, format_tlv
from .solana_keychain import Key, sign_data

class INS(IntEnum):
    # DEPRECATED - Use non "16" suffixed variants below
    INS_GET_APP_CONFIGURATION16 = 0x01
    INS_GET_PUBKEY16 = 0x02
    INS_SIGN_MESSAGE16 = 0x03
    # END DEPRECATED
    INS_GET_APP_CONFIGURATION = 0x04
    INS_GET_PUBKEY = 0x05
    INS_SIGN_MESSAGE = 0x06
    INS_SIGN_OFFCHAIN_MESSAGE = 0x07
    INS_GET_CHALLENGE = 0x20
    INS_TRUSTED_INFO = 0x21


CLA = 0xE0

P1_NON_CONFIRM = 0x00
P1_CONFIRM = 0x01

P2_NONE = 0x00
P2_EXTEND = 0x01
P2_MORE = 0x02

PUBLIC_KEY_LENGTH = 32

MAX_CHUNK_SIZE = 255

STATUS_OK = 0x9000


class ErrorType:
    NO_APP_RESPONSE = 0x6700
    SDK_EXCEPTION = 0x6801
    SDK_INVALID_PARAMETER = 0x6802
    SDK_EXCEPTION_OVERFLOW = 0x6803
    SDK_EXCEPTION_SECURITY = 0x6804
    SDK_INVALID_CRC = 0x6805
    SDK_INVALID_CHECKSUM = 0x6806
    SDK_INVALID_COUNTER = 0x6807
    SDK_NOT_SUPPORTED = 0x6808
    SDK_INVALID_STATE = 0x6809
    SDK_TIMEOUT = 0x6810
    SDK_EXCEPTION_PIC = 0x6811
    SDK_EXCEPTION_APP_EXIT = 0x6812
    SDK_EXCEPTION_IO_OVERFLOW = 0x6813
    SDK_EXCEPTION_IO_HEADER = 0x6814
    SDK_EXCEPTION_IO_STATE = 0x6815
    SDK_EXCEPTION_IO_RESET = 0x6816
    SDK_EXCEPTION_CX_PORT = 0x6817
    SDK_EXCEPTION_SYSTEM = 0x6818
    SDK_NOT_ENOUGH_SPACE = 0x6819
    NO_APDU_RECEIVED = 0x6982
    USER_CANCEL = 0x6985
    SOLANA_INVALID_MESSAGE = 0x6a80
    SOLANA_SUMMARY_FINALIZE_FAILED = 0x6f00
    SOLANA_SUMMARY_UPDATE_FAILED = 0x6f01
    UNIMPLEMENTED_INSTRUCTION = 0x6d00
    INVALID_CLA = 0x6e00


def _extend_and_serialize_multiple_derivations_paths(derivations_paths: List[bytes]):
    serialized: bytes = len(derivations_paths).to_bytes(1, byteorder='little')
    for derivations_path in derivations_paths:
        serialized += derivations_path
    return serialized

class StatusWord(IntEnum):
    OK = 0x9000
    ERROR_NO_INFO = 0x6a00
    INVALID_DATA = 0x6a80
    INSUFFICIENT_MEMORY = 0x6a84
    INVALID_INS = 0x6d00
    INVALID_P1_P2 = 0x6b00
    CONDITION_NOT_SATISFIED = 0x6985
    REF_DATA_NOT_FOUND = 0x6a88
    EXCEPTION_OVERFLOW = 0x6807
    NOT_IMPLEMENTED = 0x911c

class PKIClient:
    _CLA: int = 0xB0
    _INS: int = 0x06

    def __init__(self, client: BackendInterface) -> None:
        self._client = client

    def  send_certificate(self, payload: bytes) -> RAPDU:
        response = self.send_raw(payload)

    def send_raw(self, payload: bytes) -> RAPDU:
        header = bytearray()
        header.append(self._CLA)
        header.append(self._INS)
        header.append(0x04) # PubKeyUsage = 0x04
        header.append(0x00)
        header.append(len(payload))
        return self._client.exchange_raw(header + payload)

class SolanaClient:
    client: BackendInterface

    def __init__(self, client: BackendInterface):
        self._client = client
        self._pki_client: Optional[PKIClient] = None
        if self._client.firmware != Firmware.NANOS:
            # LedgerPKI not supported on Nanos
            self._pki_client = PKIClient(self._client)

    def _exchange_split(self, cla: int, ins: int, p1: int, payload: bytes) -> RAPDU:
        payload_split = [payload[x:x + MAX_CHUNK_SIZE] for x in range(0, len(payload), MAX_CHUNK_SIZE)]
        for i, p in enumerate(payload_split):
            p2 = P2_NONE
            # Send all chunks with P2_MORE except for the last chunk
            if i != len(payload_split) - 1:
                p2 |= P2_MORE
            # Send all chunks with P2_EXTEND except for the first chunk
            if i != 0:
                p2 |= P2_EXTEND
            rapdu = self._client.exchange(CLA, ins=ins, p1=p1, p2=p2, data=p)

        return rapdu

    def provide_trusted_name(self,
                             source_contract: bytes,
                             trusted_name: bytes,
                             address: bytes,
                             chain_id: int,
                             challenge: Optional[int] = None):

        payload = format_tlv(FieldTag.TAG_STRUCTURE_TYPE, 3)
        payload += format_tlv(FieldTag.TAG_VERSION, 2)
        payload += format_tlv(FieldTag.TAG_TRUSTED_NAME_TYPE, 0x06)
        payload += format_tlv(FieldTag.TAG_TRUSTED_NAME_SOURCE, 0x06)
        payload += format_tlv(FieldTag.TAG_TRUSTED_NAME, trusted_name)
        payload += format_tlv(FieldTag.TAG_CHAIN_ID, chain_id)
        payload += format_tlv(FieldTag.TAG_ADDRESS, address)
        payload += format_tlv(FieldTag.TAG_TRUSTED_NAME_SOURCE_CONTRACT, source_contract)
        if challenge is not None:
            payload += format_tlv(FieldTag.TAG_CHALLENGE, challenge)
        payload += format_tlv(FieldTag.TAG_SIGNER_KEY_ID, 0)  # test key
        payload += format_tlv(FieldTag.TAG_SIGNER_ALGO, 1)  # secp256k1
        payload += format_tlv(FieldTag.TAG_DER_SIGNATURE,
                              sign_data(Key.TRUSTED_NAME, payload))

        # send PKI certificate
        if self._pki_client is None:
            print(f"Ledger-PKI Not supported on '{self._client.firmware.name}'")
        else:
            # pylint: disable=line-too-long
            if self._client.firmware == Firmware.NANOSP:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020004310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010315473045022100D494B106E217B46BB90BF20A4E9285529C4C8382D9B80FF462F74942579785F802202D68D0F85CD7CA36BDF351FD41332F310E93163BD175F6A92446C14A3329CC8B"  # noqa: E501
            elif self._client.firmware == Firmware.NANOX:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020004310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F653401013501021546304402207FCD665B94B43A6E838E8CD68BE52403D38A7E6A98E2CE291AB1C5D24A41101D02207AB1863E5CB127D9E8A680AC63FF2F2CBEA79CE76652A72832EF154BF1AD6477"  # noqa: E501
            elif self._client.firmware == Firmware.STAX:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020004310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F65340101350104154730450221008F8FB0117C8D51F0D13A77680C18CA98B4B317C3D6C67F23BF9198410BEDF1A1022023B1052CA43E86E2411831990C64B1E027D85E142AD39F480948E3EF9517E55E"  # noqa: E501
            elif self._client.firmware == Firmware.FLEX:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020004310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010515473045022100CEF28780DCAFA3A485D83406D519F9AC12FD9B9C3AA7AE798896013F07DD178D022020F01B1AB1D2AAEDA70357F615EAC55E17FE94EC36DF9DE850CEFACBC98D16C8"  # noqa: E501
            # pylint: enable=line-too-long

            self._pki_client.send_certificate(bytes.fromhex(cert_apdu))

        # send TLV trusted info
        # res: RAPDU = self._client.exchange(CLA, INS.INS_TRUSTED_INFO, P1_NON_CONFIRM, P2_NONE, payload)
        self._exchange_split(CLA, INS.INS_TRUSTED_INFO, P1_NON_CONFIRM, payload)


    def get_challenge(self) -> bytes:
        challenge: RAPDU = self._client.exchange(CLA, INS.INS_GET_CHALLENGE,P1_NON_CONFIRM, P2_NONE)
        return challenge.data


    def get_public_key(self, derivation_path: bytes) -> bytes:
        public_key: RAPDU = self._client.exchange(CLA, INS.INS_GET_PUBKEY,
                                                  P1_NON_CONFIRM, P2_NONE,
                                                  derivation_path)
        assert len(public_key.data) == PUBLIC_KEY_LENGTH, "'from' public key size incorrect"
        return public_key.data


    @contextmanager
    def send_public_key_with_confirm(self, derivation_path: bytes) -> bytes:
        with self._client.exchange_async(CLA, INS.INS_GET_PUBKEY,
                                         P1_CONFIRM, P2_NONE,
                                         derivation_path):
            yield


    def split_and_prefix_message(self, derivation_path: bytes, message: bytes) -> List[bytes]:
        assert len(message) <= 65535, "Message to send is too long"
        header: bytes = _extend_and_serialize_multiple_derivations_paths([derivation_path])
        max_size = MAX_CHUNK_SIZE
        message_splited = [message[x:x + max_size] for x in range(0, len(message), max_size)]
        # The first chunk is the header, then all chunks with max size
        return [header] + message_splited


    def send_first_message_batch(self, ins: INS, messages: List[bytes], p1: int) -> RAPDU:
        self._client.exchange(CLA, ins, p1, P2_MORE, messages[0])
        for m in messages[1:]:
            self._client.exchange(CLA, ins, p1, P2_MORE | P2_EXTEND, m)


    @contextmanager
    def send_async_sign_request(self,
                                ins: INS,
                                derivation_path : bytes,
                                message: bytes) -> Generator[None, None, None]:
        message_splited_prefixed = self.split_and_prefix_message(derivation_path, message)

        # Send all chunks with P2_MORE except for the last chunk
        # Send all chunks with P2_EXTEND except for the first chunk
        if len(message_splited_prefixed) > 1:
            final_p2 = P2_EXTEND
            self.send_first_message_batch(ins, message_splited_prefixed[:-1], P1_CONFIRM)
        else:
            final_p2 = 0

        with self._client.exchange_async(CLA,
                                         ins,
                                         P1_CONFIRM,
                                         final_p2,
                                         message_splited_prefixed[-1]):
            yield


    @contextmanager
    def send_async_sign_message(self,
                                derivation_path : bytes,
                                message: bytes) -> Generator[None, None, None]:
        with self.send_async_sign_request(INS.INS_SIGN_MESSAGE, derivation_path, message):
            yield


    @contextmanager
    def send_async_sign_offchain_message(self,
                                         derivation_path : bytes,
                                         message: bytes) -> Generator[None, None, None]:
        with self.send_async_sign_request(INS.INS_SIGN_OFFCHAIN_MESSAGE, derivation_path, message):
            yield


    def get_async_response(self) -> RAPDU:
        return self._client.last_async_response
