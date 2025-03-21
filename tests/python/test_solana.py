import pytest

from ragger.backend import RaisePolicy
from ragger.utils import RAPDU

from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, OffchainMessage
from .apps.solana_utils import FOREIGN_ADDRESS_STR, FOREIGN_PUBLIC_KEY, FOREIGN_PUBLIC_KEY_2, AMOUNT, AMOUNT_2, OWNED_ADDRESS_STR, SOL_PACKED_DERIVATION_PATH, SOL_PACKED_DERIVATION_PATH_2, ROOT_SCREENSHOT_PATH
from .apps.solana_utils import enable_blind_signing, enable_expert_mode

from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.hash import Hash
from solders.message import Message as MessageSolders
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import TransferCheckedParams, transfer_checked, ApproveCheckedParams, approve_checked, get_associated_token_address, create_associated_token_account
from spl.token.constants import TOKEN_PROGRAM_ID
from .apps import solana_utils as SOL
from solders.keypair import Keypair
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price


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


class TestOnchainSpendingApprove:

    TEST_CASE_DATA = [
        {
            'case_name': 'baaanx_delegate_with_compute_budget',
            'delegate_address': 'BaanxDe1egate111111111111111111111111111111',
            'compute_budget': (2_000_000, 100_500),
        },
        {
            'case_name': 'baaanx_delegate',
            'delegate_address': 'BaanxDe1egate111111111111111111111111111111',
            'compute_budget': None
        },
        {
            'case_name': 'unknown_delegate_with_compute_budget',
            'delegate_address': '8VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE',
            'compute_budget': (1_000_000, 100_000)
        },
        {
            'case_name': 'unknown_delegate',
            'delegate_address': '8VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE',
            'compute_budget': None
        },
        {
            'case_name': 'unknown_delegate_with_unknown_token',
            'delegate_address': '8VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE',
            'compute_budget': (2_000_000, 100_500),
            'token': 'FPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
        }
    ]


    @pytest.mark.parametrize("test_case_data", TEST_CASE_DATA, ids=lambda case: case["case_name"])
    def test_solana_spl_approve_spending(self, backend, scenario_navigator, test_case_data):
        sol = SolanaClient(backend)
        test_case_name = "test_solana_spl_approve_spending_" + test_case_data["case_name"]
        token_address = ""

        instructions = []

        # Set compute budget if required
        if test_case_data["compute_budget"]:
            compute_unit_limit_ix = set_compute_unit_limit(1_000_000)
            instructions.append(compute_unit_limit_ix)
            compute_unit_price_ix = set_compute_unit_price(100_000)
            instructions.append(compute_unit_price_ix)

        # Set token address
        if test_case_data.get('token'):
            token_address = test_case_data['token']
        else:
            # USDC Token mint address
            token_address = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)
        source = Pubkey.from_string("7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE")  # Token account that holds the tokens
        delegate = Pubkey.from_string(test_case_data["delegate_address"])  # Delegate address
        owner = Pubkey.from_string(OWNED_ADDRESS_STR)  # Owner of the token account
        sender_public_key = Pubkey.from_bytes(from_public_key)
        mint = Pubkey.from_string(token_address)  # Token mint address

        # Token USDC details
        amount = 1000 * (10**6)  # Approving 1000 tokens (assuming 6 decimals)
        decimals = 6  # Ensure the correct decimal count

        # Create ApproveChecked instruction
        approve_checked_ix = approve_checked(
            ApproveCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=source,
                mint=mint,
                delegate=delegate,
                owner=owner,
                amount=amount,
                decimals=decimals,
            )
        )
        instructions.append(approve_checked_ix)

        blockhash = Hash.default()
        message = MessageSolders.new_with_blockhash(
            instructions,
            sender_public_key,
            blockhash
        )
        tx = Transaction.new_unsigned(message)

        # Dump the message embedded in the transaction
        message = tx.message_data()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(
                path=ROOT_SCREENSHOT_PATH,
                test_name=test_case_name,
                custom_screen_text=None
            )

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

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
