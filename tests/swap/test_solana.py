import pytest
import struct
from ragger.error import ExceptionRAPDU

from ledger_app_clients.exchange.test_runner import ExchangeTestRunner, ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES
from application_client.solana import SolanaClient, ErrorType
from application_client.solana_cmd_builder import SystemInstructionTransfer, ComputeBudgetInstructionSetComputeUnitLimit, ComputeBudgetInstructionSetComputeUnitPrice, verify_signature
from application_client.solana_cmd_builder import Message as MessageCustom
from application_client.solana_utils import sol_to_lamports, lamports_to_bytes
from application_client import solana_utils as SOL

from . import cal_helper as cal

from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.hash import Hash
from solders.message import Message
from spl.token.constants import TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID
from spl.token.instructions import TransferCheckedParams, transfer_checked, get_associated_token_address, create_associated_token_account
from solders.instruction import Instruction, AccountMeta

# A bit hacky but way less hassle than actually writing an actual address decoder
SOLANA_ADDRESS_DECODER = {
    SOL.FOREIGN_ADDRESS: SOL.FOREIGN_PUBLIC_KEY,
    SOL.FOREIGN_ADDRESS_2: SOL.FOREIGN_PUBLIC_KEY_2,
}

FEES = sol_to_lamports(0.002123)
FEES_BYTES = lamports_to_bytes(FEES)

FEES_2 = sol_to_lamports(0.005543)
FEES_2_BYTES = lamports_to_bytes(FEES_2)

TRANSFER_FEE_EXTENSION = 26
TRANSFER_CHECKED_WITH_FEE = 1
TRANSFER_CHECKED = 12

# ExchangeTestRunner implementation for Solana
class GenericSolanaTests(ExchangeTestRunner):
    currency_configuration = cal.SOL_CURRENCY_CONFIGURATION
    valid_destination_1 = SOL.FOREIGN_ADDRESS
    valid_destination_2 = SOL.FOREIGN_ADDRESS_2
    valid_refund = SOL.OWNED_ADDRESS
    valid_send_amount_1 = SOL.AMOUNT
    valid_send_amount_2 = SOL.AMOUNT_2
    valid_fees_1 = FEES
    valid_fees_2 = FEES_2
    fake_refund = SOL.FOREIGN_ADDRESS
    fake_payout = SOL.FOREIGN_ADDRESS
    signature_refusal_error_code = ErrorType.SOLANA_SUMMARY_FINALIZE_FAILED

    partner_name = "Partner name"
    fund_user_id = "Daft Punk"
    fund_account_name = "Account 0"

    def perform_final_tx(self, destination, send_amount, fees, memo):
        decoded_destination = SOLANA_ADDRESS_DECODER[destination]
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(SOL.OWNED_PUBLIC_KEY, decoded_destination, send_amount)
        message: bytes = MessageCustom([instruction]).serialize()
        sol = SolanaClient(self.backend)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message, signature)


# Use a class to reuse the same Speculos instance
class TestsSolana:

    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_solana(self, backend, exchange_navigation_helper, test_to_run):
        GenericSolanaTests(backend, exchange_navigation_helper).run_test(test_to_run)

# ExchangeTestRunner implementation for Solana
class SolanaPriorityFeesTests(GenericSolanaTests):
    def perform_final_tx(self, destination, send_amount, fees, memo):
        decoded_destination = SOLANA_ADDRESS_DECODER[destination]
        computeUnitLimit: ComputeBudgetInstructionSetComputeUnitLimit = ComputeBudgetInstructionSetComputeUnitLimit(300)
        computeUnitPrice: ComputeBudgetInstructionSetComputeUnitPrice = ComputeBudgetInstructionSetComputeUnitPrice(20000)
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(SOL.OWNED_PUBLIC_KEY, decoded_destination, send_amount)
        message: bytes = MessageCustom([computeUnitLimit, computeUnitPrice, instruction]).serialize()
        sol = SolanaClient(self.backend)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message, signature)


# Use a class to reuse the same Speculos instance
class TestsSolanaPriorityFees:
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_solana_priority_fees(self, backend, exchange_navigation_helper, test_to_run):
        SolanaPriorityFeesTests(backend, exchange_navigation_helper).run_test(test_to_run)

def craft_tx(instructions, sender_public_key):
    blockhash = Hash.default()
    message = Message.new_with_blockhash(instructions, sender_public_key, blockhash)
    tx = Transaction.new_unsigned(message)
    print(tx)
    return tx.message_data()


class SPLTokenTests(GenericSolanaTests):
    currency_configuration = cal.SOL_USDC_CURRENCY_CONFIGURATION

    valid_destination_1 = "JA2zDGUjCJePxBWbW895rMPUSBPPU15Q5UbqspezSzwF"
    valid_destination_2 = str(
        get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR),
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR)
        )
    )
    valid_refund = SOL.OWNED_ADDRESS

    valid_send_amount_1 = SOL.AMOUNT
    valid_send_amount_2 = SOL.AMOUNT_2
    valid_fees_1 = FEES
    valid_fees_2 = FEES_2
    fake_refund = SOL.FOREIGN_ADDRESS_STR
    fake_payout = SOL.FOREIGN_ADDRESS_STR
    signature_refusal_error_code = ErrorType.SOLANA_SUMMARY_FINALIZE_FAILED

    def perform_final_tx(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR)
            )
        )
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR))

        # Create the transaction

        create_instruction = create_associated_token_account(
            payer=sender_ata,
            owner=Pubkey.from_string(destination),
            mint=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
        )
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination_ata),
                owner=sender_public_key,
                amount=send_amount,
                decimals=6  # Number of decimals for USDC token
            )
        )

        message_data = craft_tx([create_instruction, transfer_instruction], sender_public_key)

        sol = SolanaClient(self.backend)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

# Use a class to reuse the same Speculos instance
class TestsSPLToken:
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_solana_spl_token(self, backend, exchange_navigation_helper, test_to_run):
        SPLTokenTests(backend, exchange_navigation_helper).run_test(test_to_run)
        # message: bytes = bytes.fromhex("0100030621a36fe74e1234c35e62bfd700fd247b92c4d4e0e538401ac51f5c4ae97657a7276497ba0bb8659172b72edd8c66e18f561764d9c86a610a3a7e0f79c0baf9dbc71573813ea96479a79e579af14646413602b9b3dcbdc51cbf8e064b5685ed120479d9c7cc1035de7211f99eb48c09d70b2bdf5bdf9e2e56b8a1fbb5a2ea332706ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a938b19525b109c0e2517df8786389e33365afe2dc6bfabeb65458fd24a1ab5b13000000000000000000000000000000000000000000000000000000000000000001040501030205000a0c020000000000000006")

class SPLToken2022Tests(SPLTokenTests):
    def perform_final_tx(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                token_program_id=TOKEN_2022_PROGRAM_ID,
            )
        )
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(
            sender_public_key,
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
            token_program_id=TOKEN_2022_PROGRAM_ID,
        )

        accounts = [
            AccountMeta(pubkey=sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string(destination_ata), is_signer=False, is_writable=True),
            AccountMeta(pubkey=sender_public_key, is_signer=True, is_writable=False),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, send_amount, 6, 0)
        )

        message_data = craft_tx([transfer_instruction], sender_public_key)

        sol = SolanaClient(self.backend)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def perform_final_tx_with_transfer_fees(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                token_program_id=TOKEN_2022_PROGRAM_ID,
            )
        )
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(
            sender_public_key,
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
            token_program_id=TOKEN_2022_PROGRAM_ID,
        )

        accounts = [
            AccountMeta(pubkey=sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string(destination_ata), is_signer=False, is_writable=True),
            AccountMeta(pubkey=sender_public_key, is_signer=True, is_writable=False),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, send_amount, 6, 767)
        )
        message_data = craft_tx([transfer_instruction], sender_public_key)

        sol = SolanaClient(self.backend)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def perform_final_tx_with_unknown_transfer_fees(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                token_program_id=TOKEN_2022_PROGRAM_ID,
            )
        )
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(
            sender_public_key,
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
            token_program_id=TOKEN_2022_PROGRAM_ID,
        )

        # Create the transaction
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_2022_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination_ata),
                owner=sender_public_key,
                amount=send_amount,
                decimals=6  # Number of decimals for USDC token
            )
        )
        message_data = craft_tx([transfer_instruction], sender_public_key)

        sol = SolanaClient(self.backend)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def perform_final_tx_with_transfer_hook(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                token_program_id=TOKEN_2022_PROGRAM_ID,
            )
        )
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(
            sender_public_key,
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
            token_program_id=TOKEN_2022_PROGRAM_ID,
        )
        hook_account = Pubkey.from_string("FcheSyMboM2FKxieZPsT7r69s5UunZiK8tNSmSKts92i")

        accounts = [
            AccountMeta(pubkey=sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string(destination_ata), is_signer=False, is_writable=True),
            AccountMeta(pubkey=sender_public_key, is_signer=True, is_writable=False),
            AccountMeta(pubkey=hook_account, is_signer=False, is_writable=True),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, send_amount, 6, 0)
        )
        message_data = craft_tx([transfer_instruction], sender_public_key)

        sol = SolanaClient(self.backend)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

# Use a class to reuse the same Speculos instance
class TestsSPLToken2022:
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_solana_spl_token_2022(self, backend, exchange_navigation_helper, test_to_run):
        SPLToken2022Tests(backend, exchange_navigation_helper).run_test(test_to_run)

    def test_solana_spl_token_2022_token_fees(self, backend, exchange_navigation_helper):
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = SPLToken2022Tests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = test_class.perform_final_tx_with_transfer_fees
            test_class.run_test("swap_valid_1")
        assert e.value.status == test_class.signature_refusal_error_code

    def test_solana_spl_token_2022_unknown_token_fees(self, backend, exchange_navigation_helper):
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = SPLToken2022Tests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = test_class.perform_final_tx_with_unknown_transfer_fees
            test_class.run_test("swap_valid_1")
        assert e.value.status == test_class.signature_refusal_error_code

    def test_solana_spl_token_2022_token_hook(self, backend, exchange_navigation_helper):
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = SPLToken2022Tests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = test_class.perform_final_tx_with_transfer_hook
            test_class.run_test("swap_valid_1")
        assert e.value.status == test_class.signature_refusal_error_code
