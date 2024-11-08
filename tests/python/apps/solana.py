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

    def send_certificate(self, payload: bytes) -> RAPDU:
        try:
            response = self.send_raw(payload)
            assert response.status == StatusWord.OK
        except ExceptionRAPDU as err:
            if err.status == StatusWord.NOT_IMPLEMENTED:
                print("Ledger-PKI APDU not yet implemented. Legacy path will be used")

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
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020004310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F65340101350103154630440220328886305590C895D119105849A87835BF531B26E646B815E0E8A5528DF480950220155747BAF14A26870B09622330F24DD120EB1AE1662C4A734E73C20395892F48"  # noqa: E501
            elif self._client.firmware == Firmware.NANOX:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020004310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010215463044022034B002268EA97826A44E2704514CB0F8B70353DE4D465F50116A5CB3131E3C1E02202387F059A6F701361A960DB61D5749F25EE390C505A09DD4CBD868A1C4042A1C"  # noqa: E501
            elif self._client.firmware == Firmware.STAX:
                cert_apdu = "01010102010111040000000212010013020002140101160400000000200C547275737465645F4E616D6530020004310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F65340101350104154730450221009DCD14004A1C6F8A6A56F91FD253865F255E83FD316CB3E6B9AF585B12FBD78A02206DFA969336E82C93C1F2EF863CFAC19F88ECE1F38C900791FFFD46B9C9E02279"  # noqa: E501
            elif self._client.firmware == Firmware.FLEX:
                cert_apdu = "01010102010111040000000212010013020002140101160400000000200C547275737465645F4E616D6530020004310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010515473045022100A35942AD66FEBD1899C52BB3EE3A5CB3802C4C2BE6C6521EB590D32ADC152E380220210F7BAB9A62501134D513CFD127A72BA1EB0D9F956E3EC7E553BF460F505810"  # noqa: E501
            # pylint: enable=line-too-long

            self._pki_client.send_certificate(bytes.fromhex(cert_apdu))   
        
        # send TLV trusted info
        res: RAPDU = self._client.exchange(CLA, INS.INS_TRUSTED_INFO, P1_NON_CONFIRM, P2_NONE, payload)
        assert res.status == StatusWord.OK

    def get_challenge(self) -> bytes:
        challenge: RAPDU = self._client.exchange(CLA, INS.INS_GET_CHALLENGE,P1_NON_CONFIRM, P2_NONE)
        
        assert challenge.status == StatusWord.OK                                         
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


    def split_and_prefix_message(self, derivation_path : bytes, message: bytes) -> List[bytes]:
        assert len(message) <= 65535, "Message to send is too long"
        header: bytes = _extend_and_serialize_multiple_derivations_paths([derivation_path])
        # Check to see if this data needs to be split up and sent in chunks.
        max_size = MAX_CHUNK_SIZE - len(header)
        message_splited = [message[x:x + max_size] for x in range(0, len(message), max_size)]
        # Add the header to every chunk
        return [header + s for s in message_splited]


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
