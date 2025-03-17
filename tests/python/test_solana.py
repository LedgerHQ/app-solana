from ragger.backend import RaisePolicy
from ragger.utils import RAPDU

from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, OffchainMessage
from .apps.solana_utils import FOREIGN_PUBLIC_KEY, FOREIGN_PUBLIC_KEY_2, AMOUNT, AMOUNT_2, SOL_PACKED_DERIVATION_PATH, SOL_PACKED_DERIVATION_PATH_2, ROOT_SCREENSHOT_PATH
from .apps.solana_utils import enable_blind_signing, enable_expert_mode


class TestGetPublicKey:

    def test_solana_get_public_key_ok(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            scenario_navigator.address_review_approve(path=ROOT_SCREENSHOT_PATH)

        assert sol.get_async_response().data == from_public_key


    def test_solana_get_public_key_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            scenario_navigator.address_review_reject(path=ROOT_SCREENSHOT_PATH)

        assert sol.get_async_response().status == ErrorType.USER_CANCEL


class TestMessageSigning:

    def test_solana_simple_transfer_ok_1(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_ok_2(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH_2)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY_2, AMOUNT_2)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH_2, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


class TestOffchainMessageSigning:

    def test_ledger_sign_offchain_message_ascii_ok(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_ascii_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_ascii_expert_ok(self, backend, scenario_navigator, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_ascii_expert_refused(self, backend, scenario_navigator, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_utf8_ok(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_utf8_refused(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_utf8_expert_ok(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")
        enable_expert_mode(navigator, backend.firmware, test_name + "_2")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_3")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_utf8_expert_refused(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")
        enable_expert_mode(navigator, backend.firmware, test_name + "_2")

        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_3")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

# Values used across Trusted Name test
CHAIN_ID = 101
# Token account address owner
ADDRESS = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE"
# Token account address
TRUSTED_NAME = "EQ96zptNAWwM23m5v2ByChCMTFu6zUmJgRtUrQV1uYNM"
# SPL token address (JUP Token)
SOURCE_CONTRACT = "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN"

from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.hash import Hash
from solders.message import Message as MessageSolders
from spl.token.constants import TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID
from spl.token.instructions import TransferCheckedParams, transfer_checked, get_associated_token_address, create_associated_token_account
from .apps import solana_utils as SOL
from solders.keypair import Keypair
from solders.pubkey import Pubkey
# A bit hacky but way less hassle than actually writing an actual address decoder
SOLANA_ADDRESS_DECODER = {
    SOL.FOREIGN_ADDRESS: SOL.FOREIGN_PUBLIC_KEY,
    SOL.FOREIGN_ADDRESS_2: SOL.FOREIGN_PUBLIC_KEY_2,
}

import base58
class TestTrustedName:

    def test_solana_trusted_name(self, backend, scenario_navigator):

        # Generate a keypair
        keypair = Keypair()

        # Extract the public key in both bytes and Base58 format
        public_key_bytes = bytes(keypair.pubkey())
        public_key_base58 = str(keypair.pubkey())
        assert Pubkey.is_on_curve(keypair.pubkey())
        print(public_key_bytes.hex())
        print(public_key_base58)
        # sol = SolanaClient(backend)

        # from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # # Create message (SPL Token transfer)
        # message: bytes = bytes.fromhex("0100030621a36fe74e1234c35e62bfd700fd247b92c4d4e0e538401ac51f5c4ae97657a7276497ba0bb8659172b72edd8c66e18f561764d9c86a610a3a7e0f79c0baf9dbc71573813ea96479a79e579af14646413602b9b3dcbdc51cbf8e064b5685ed120479d9c7cc1035de7211f99eb48c09d70b2bdf5bdf9e2e56b8a1fbb5a2ea332706ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a938b19525b109c0e2517df8786389e33365afe2dc6bfabeb65458fd24a1ab5b13000000000000000000000000000000000000000000000000000000000000000001040501030205000a0c020000000000000006")

        # with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
        #     scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        # signature: bytes = sol.get_async_response().data
        # verify_signature(from_public_key, message, signature)



        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
# TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
        destination = str(get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
        ))

        # Create the transaction
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination),
                owner=sender_public_key,
                amount=1,
                decimals=6  # Number of decimals for JUP token
            )
        )

        blockhash = Hash.default()
        message = MessageSolders.new_with_blockhash([transfer_instruction], sender_public_key, blockhash)
        tx = Transaction.new_unsigned(message)

        # Dump the message embedded in the transaction
        message = tx.message_data()

        sol = SolanaClient(backend)
        challenge = sol.get_challenge()

        print(f"destination = {base58.b58decode(destination.encode('utf-8')).hex()}")
        print(f"SOL.FOREIGN_PUBLIC_KEY = {SOL.FOREIGN_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_PUBLIC_KEY = {SOL.JUP_MINT_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_ADDRESS_STR = {SOL.JUP_MINT_ADDRESS_STR}")
        print(f"SOL.JUP_MINT_ADDRESS = {SOL.JUP_MINT_ADDRESS.hex()}")

        sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
                                 # "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN".encode('utf-8'),
                                 destination.encode('utf-8'),
                                 SOL.FOREIGN_ADDRESS_STR.encode('utf-8'),
                                 CHAIN_ID,
                                 challenge=challenge)

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message, signature)


    def test_solana_trusted_name_create(self, backend, scenario_navigator):

        # Generate a keypair
        keypair = Keypair()

        # Extract the public key in both bytes and Base58 format
        public_key_bytes = bytes(keypair.pubkey())
        public_key_base58 = str(keypair.pubkey())
        assert Pubkey.is_on_curve(keypair.pubkey())
        print(public_key_bytes.hex())
        print(public_key_base58)
        # sol = SolanaClient(backend)

        # from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # # Create message (SPL Token transfer)
        # message: bytes = bytes.fromhex("0100030621a36fe74e1234c35e62bfd700fd247b92c4d4e0e538401ac51f5c4ae97657a7276497ba0bb8659172b72edd8c66e18f561764d9c86a610a3a7e0f79c0baf9dbc71573813ea96479a79e579af14646413602b9b3dcbdc51cbf8e064b5685ed120479d9c7cc1035de7211f99eb48c09d70b2bdf5bdf9e2e56b8a1fbb5a2ea332706ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a938b19525b109c0e2517df8786389e33365afe2dc6bfabeb65458fd24a1ab5b13000000000000000000000000000000000000000000000000000000000000000001040501030205000a0c020000000000000006")

        # with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
        #     scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        # signature: bytes = sol.get_async_response().data
        # verify_signature(from_public_key, message, signature)



        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
# TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
        destination = str(get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
        ))

        # Create the transaction
        create_instruction = create_associated_token_account(
            payer=sender_ata,
            owner=Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
        )
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination),
                owner=sender_public_key,
                amount=1,
                decimals=6  # Number of decimals for JUP token
            )
        )

        blockhash = Hash.default()
        message = MessageSolders.new_with_blockhash([create_instruction, transfer_instruction], sender_public_key, blockhash)
        tx = Transaction.new_unsigned(message)

        # Dump the message embedded in the transaction
        message = tx.message_data()

        sol = SolanaClient(backend)
        challenge = sol.get_challenge()

        print(f"destination = {base58.b58decode(destination.encode('utf-8')).hex()}")
        print(f"SOL.FOREIGN_PUBLIC_KEY = {SOL.FOREIGN_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_PUBLIC_KEY = {SOL.JUP_MINT_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_ADDRESS_STR = {SOL.JUP_MINT_ADDRESS_STR}")
        print(f"SOL.JUP_MINT_ADDRESS = {SOL.JUP_MINT_ADDRESS.hex()}")

        sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
                                 # "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN".encode('utf-8'),
                                 destination.encode('utf-8'),
                                 SOL.FOREIGN_ADDRESS_STR.encode('utf-8'),
                                 CHAIN_ID,
                                 challenge=challenge)

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message, signature)

    def test_solana_trusted_name_token_2022(self, backend, scenario_navigator):

        # Generate a keypair
        keypair = Keypair()

        # Extract the public key in both bytes and Base58 format
        public_key_bytes = bytes(keypair.pubkey())
        public_key_base58 = str(keypair.pubkey())
        assert Pubkey.is_on_curve(keypair.pubkey())
        print(public_key_bytes.hex())
        print(public_key_base58)
        # sol = SolanaClient(backend)

        # from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # # Create message (SPL Token transfer)
        # message: bytes = bytes.fromhex("0100030621a36fe74e1234c35e62bfd700fd247b92c4d4e0e538401ac51f5c4ae97657a7276497ba0bb8659172b72edd8c66e18f561764d9c86a610a3a7e0f79c0baf9dbc71573813ea96479a79e579af14646413602b9b3dcbdc51cbf8e064b5685ed120479d9c7cc1035de7211f99eb48c09d70b2bdf5bdf9e2e56b8a1fbb5a2ea332706ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a938b19525b109c0e2517df8786389e33365afe2dc6bfabeb65458fd24a1ab5b13000000000000000000000000000000000000000000000000000000000000000001040501030205000a0c020000000000000006")

        # with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
        #     scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        # signature: bytes = sol.get_async_response().data
        # verify_signature(from_public_key, message, signature)



        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
# TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
        destination = str(get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
        ))

        # Create the transaction
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_2022_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination),
                owner=sender_public_key,
                amount=1,
                decimals=6  # Number of decimals for JUP token
            )
        )

        blockhash = Hash.default()
        message = MessageSolders.new_with_blockhash([transfer_instruction], sender_public_key, blockhash)
        tx = Transaction.new_unsigned(message)

        # Dump the message embedded in the transaction
        message = tx.message_data()

        sol = SolanaClient(backend)
        challenge = sol.get_challenge()

        print(f"destination = {base58.b58decode(destination.encode('utf-8')).hex()}")
        print(f"SOL.FOREIGN_PUBLIC_KEY = {SOL.FOREIGN_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_PUBLIC_KEY = {SOL.JUP_MINT_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_ADDRESS_STR = {SOL.JUP_MINT_ADDRESS_STR}")
        print(f"SOL.JUP_MINT_ADDRESS = {SOL.JUP_MINT_ADDRESS.hex()}")

        sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
                                 # "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN".encode('utf-8'),
                                 destination.encode('utf-8'),
                                 SOL.FOREIGN_ADDRESS_STR.encode('utf-8'),
                                 CHAIN_ID,
                                 challenge=challenge)

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message, signature)

    def test_raw(self, backend):
        backend.exchange_raw(bytes.fromhex("b001000000"))
        backend.exchange_raw(bytes.fromhex("e00500000d038000002c800001f580000000"))
        # backend.exchange_raw(bytes.fromhex("b00604009f01010102010235010336010110040106000013020002140101200c747275737465645f6e616d65300200073101043201213401013321036a94e7a42cd0c33fdf440c8e2ab2542cefbe5db7aa0b93a9fc814b9acfa75eb415463044022057eaa964e691e8d1999048b41398e7c4d3242d048b5d6b39c2f622cf5cb6717102204c1707ae12dab8e616d75420c934bd9c7f89847262f7d24f1863e553e927c5cc"))
        backend.exchange_raw(bytes.fromhex("e004000000"))
        backend.exchange_raw(bytes.fromhex("e020000000"))
        backend.exchange_raw(bytes.fromhex("e0210000eb010103020102700106710106202b77707a544e50594674474d507169766439756978424c7958586d464a323679593234586d6a625443457759230165222b51327933656d39665a455738595850746d3139786a7456314d345a58445765695a6b33536736775167457a732c464c5558426d506854334664314544564664673436595245714842654e79706e31683445626e547a5745525812047035ab1913010714010115463044022044a0e545fcf2549adb99434fc34a1c2701032d041f5106c111204c8cde1798b6022079b8bc7e2d0e86f6e0d6e1842e0f84e9ca0c6a2da10e414cb0545aca917543ae"))
        backend.exchange_raw(bytes.fromhex("e0060102ff01038000002c800001f580000000010004079148d5d8007a60b16c3cb913a266c5f6b6564d602e55a17c050fb8a182db47f5e991451058c2d13e7fcbffae0e54b3e6f199c7008609cee798b7e6e307eba8b70e0ba07802ebc012f44ac9d69ed5ba392967ac898a51cfebfec51fe310a7e6470306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a4000000006ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfcd500c511dcfe0675f9f55c1f408c7833be620fdc02db6d05ed0fa36486ab4afa054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448dd3e000ebb9dea062a868f9c8dd"))
        backend.exchange_raw(bytes.fromhex("e00601013497d9345839ab5aa7cd53989854d7dc6750a2060303000502211a00000404010502000a0c68000000000000000506000474657374"))
        backend.exchange_raw(bytes.fromhex("b001000000"))
        backend.exchange_raw(bytes.fromhex("e00500000d038000002c800001f580000000"))
        backend.exchange_raw(bytes.fromhex("b00604009f01010102010235010336010110040106000013020002140101200c747275737465645f6e616d65300200073101043201213401013321036a94e7a42cd0c33fdf440c8e2ab2542cefbe5db7aa0b93a9fc814b9acfa75eb415463044022057eaa964e691e8d1999048b41398e7c4d3242d048b5d6b39c2f622cf5cb6717102204c1707ae12dab8e616d75420c934bd9c7f89847262f7d24f1863e553e927c5cc"))
        backend.exchange_raw(bytes.fromhex("e004000000"))
        backend.exchange_raw(bytes.fromhex("e020000000"))
        backend.exchange_raw(bytes.fromhex("e0210000ed010103020102700106710106202b77707a544e50594674474d507169766439756978424c7958586d464a323679593234586d6a625443457759230165222b51327933656d39665a455738595850746d3139786a7456314d345a58445765695a6b33536736775167457a732c464c5558426d506854334664314544564664673436595245714842654e79706e31683445626e547a5745525812048b88479c13010714010115483046022100c05ce448ce48f887868f2ba68aba0729b57f4d2655ea41c9875c8ea1878a6a6d022100a5789bb40ed112a90d98dc2021bd0e5bc29cc160b875e896e81601f494d02215"))
        backend.exchange_raw(bytes.fromhex("e0060102ff01038000002c800001f580000000010004079148d5d8007a60b16c3cb913a266c5f6b6564d602e55a17c050fb8a182db47f5e991451058c2d13e7fcbffae0e54b3e6f199c7008609cee798b7e6e307eba8b70e0ba07802ebc012f44ac9d69ed5ba392967ac898a51cfebfec51fe310a7e6470306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a4000000006ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfcd500c511dcfe0675f9f55c1f408c7833be620fdc02db6d05ed0fa36486ab4afa054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d3416354001486bdf3836be0130"))
        backend.exchange_raw(bytes.fromhex("e0060101346c64099857dae14a14ddcb79bcd21fc4a3440a0303000502211a00000404010502000a0c68000000000000000506000474657374"))
# => b001000000
# <= 0106536f6c616e6108323032322e302e3101029000
# => e00500000d038000002c800001f580000000
# <= 9148d5d8007a60b16c3cb913a266c5f6b6564d602e55a17c050fb8a182db47f59000
# => b00604009f01010102010235010336010110040106000013020002140101200c747275737465645f6e616d65300200073101043201213401013321036a94e7a42cd0c33fdf440c8e2ab2542cefbe5db7aa0b93a9fc814b9acfa75eb415463044022057eaa964e691e8d1999048b41398e7c4d3242d048b5d6b39c2f622cf5cb6717102204c1707ae12dab8e616d75420c934bd9c7f89847262f7d24f1863e553e927c5cc
# <= 9000
# => e004000000
# <= 0000e600019000
# => e020000000
# <= 7035ab199000
# => e0210000eb010103020102700106710106202b77707a544e50594674474d507169766439756978424c7958586d464a323679593234586d6a625443457759230165222b51327933656d39665a455738595850746d3139786a7456314d345a58445765695a6b33536736775167457a732c464c5558426d506854334664314544564664673436595245714842654e79706e31683445626e547a5745525812047035ab1913010714010115463044022044a0e545fcf2549adb99434fc34a1c2701032d041f5106c111204c8cde1798b6022079b8bc7e2d0e86f6e0d6e1842e0f84e9ca0c6a2da10e414cb0545aca917543ae
# <= 9000
# => e0060102ff01038000002c800001f580000000010004079148d5d8007a60b16c3cb913a266c5f6b6564d602e55a17c050fb8a182db47f5e991451058c2d13e7fcbffae0e54b3e6f199c7008609cee798b7e6e307eba8b70e0ba07802ebc012f44ac9d69ed5ba392967ac898a51cfebfec51fe310a7e6470306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a4000000006ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfcd500c511dcfe0675f9f55c1f408c7833be620fdc02db6d05ed0fa36486ab4afa054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448dd3e000ebb9dea062a868f9c8dd
# <= 9000
# => e00601013497d9345839ab5aa7cd53989854d7dc6750a2060303000502211a00000404010502000a0c68000000000000000506000474657374
# <= 6808
# => b001000000
# <= 0106536f6c616e6108323032322e302e3101029000
# => e00500000d038000002c800001f580000000
# <= 9148d5d8007a60b16c3cb913a266c5f6b6564d602e55a17c050fb8a182db47f59000
# => b00604009f01010102010235010336010110040106000013020002140101200c747275737465645f6e616d65300200073101043201213401013321036a94e7a42cd0c33fdf440c8e2ab2542cefbe5db7aa0b93a9fc814b9acfa75eb415463044022057eaa964e691e8d1999048b41398e7c4d3242d048b5d6b39c2f622cf5cb6717102204c1707ae12dab8e616d75420c934bd9c7f89847262f7d24f1863e553e927c5cc
# <= 9000
# => e004000000
# <= 0100e600019000
# => e020000000
# <= 8b88479c9000
# => e0210000ed010103020102700106710106202b77707a544e50594674474d507169766439756978424c7958586d464a323679593234586d6a625443457759230165222b51327933656d39665a455738595850746d3139786a7456314d345a58445765695a6b33536736775167457a732c464c5558426d506854334664314544564664673436595245714842654e79706e31683445626e547a5745525812048b88479c13010714010115483046022100c05ce448ce48f887868f2ba68aba0729b57f4d2655ea41c9875c8ea1878a6a6d022100a5789bb40ed112a90d98dc2021bd0e5bc29cc160b875e896e81601f494d02215
# <= 9000
# => e0060102ff01038000002c800001f580000000010004079148d5d8007a60b16c3cb913a266c5f6b6564d602e55a17c050fb8a182db47f5e991451058c2d13e7fcbffae0e54b3e6f199c7008609cee798b7e6e307eba8b70e0ba07802ebc012f44ac9d69ed5ba392967ac898a51cfebfec51fe310a7e6470306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a4000000006ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfcd500c511dcfe0675f9f55c1f408c7833be620fdc02db6d05ed0fa36486ab4afa054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d3416354001486bdf3836be0130
# <= 9000
# => e0060101346c64099857dae14a14ddcb79bcd21fc4a3440a0303000502211a00000404010502000a0c68000000000000000506000474657374
# <= fa890817c8d054f258c0d2a133fb4741fbc418daaaa3f08fd0320ba3f7df747745d9c3ce42a63e88fec8df0c6f1599ef2964f90f105e0a7ee0ad381e3e2825059000
