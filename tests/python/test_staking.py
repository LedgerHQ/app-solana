import pytest
import base58
import struct
from enum import IntEnum
from ragger.error import ExceptionRAPDU

from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta

from application_client import solana_utils as SOL
from application_client.solana import SolanaClient, ErrorType
from application_client.solana_cmd_builder import verify_signature, PROGRAM_ID_SYSTEM

STAKE_PROGRAM_ID = Pubkey.from_string("Stake11111111111111111111111111111111111111")
SYSVAR_RENT = Pubkey.from_string("SysvarRent111111111111111111111111111111111")
SYSVAR_CLOCK = Pubkey.from_string("SysvarC1ock11111111111111111111111111111111")
SYSVAR_STAKE_HISTORY = Pubkey.from_string("SysvarStakeHistory1111111111111111111111111")
STAKE_CONFIG_ID = Pubkey.from_string("StakeConfig11111111111111111111111111111111")

class StakeInstruction(IntEnum):
    StakeInitialize = 0
    StakeAuthorize = 1
    StakeDelegate = 2
    StakeSplit = 3
    StakeWithdraw = 4
    StakeDeactivate = 5
    StakeSetLockup = 6
    StakeMerge = 7
    StakeAuthorizeWithSeed = 8
    StakeInitializeChecked = 9
    StakeAuthorizeChecked = 10
    StakeAuthorizeCheckedWithSeed = 11
    StakeSetLockupChecked = 12

class StakeAuthorize(IntEnum):
    StakeAuthorizeStaker = 0
    StakeAuthorizeWithdrawer = 1

class StakeLockupArgs(IntEnum):
    OptionNone = 0
    OptionSome = 1

class SystemInstruction(IntEnum):
    SystemCreateAccount = 0
    SystemAssign = 1
    SystemTransfer = 2
    SystemCreateAccountWithSeed = 3
    SystemAdvanceNonceAccount = 4
    SystemWithdrawNonceAccount = 5
    SystemInitializeNonceAccount = 6
    SystemAuthorizeNonceAccount = 7
    SystemAllocate = 8
    SystemAllocateWithSeed = 9
    SystemAssignWithSeed = 10

class TestStaking:
    # Reuse same values for all tests
    payer_pubkey = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
    stake_account = Pubkey.create_with_seed(payer_pubkey, seed="stake123", program_id=STAKE_PROGRAM_ID)

    def _send_and_validate_message(self, sol, transactions, scenario_navigator, root_pytest_dir, valid=True):
        message_data = sol.craft_tx(transactions, self.payer_pubkey)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            if valid:
                scenario_navigator.review_approve(path=root_pytest_dir)
            else:
                pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    @pytest.mark.parametrize("is_checked", ["checked", "unchecked"])
    def test_stake_initialize(self, sol, scenario_navigator, root_pytest_dir, is_checked, test_name):
        scenario_navigator.test_name = test_name + "_" + is_checked
        custodian_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        authority_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        withdraw_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)

        instruction = StakeInstruction.StakeInitializeChecked if is_checked == "checked" else StakeInstruction.StakeInitialize

        accounts=[
            AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
            AccountMeta(pubkey=SYSVAR_RENT, is_signer=False, is_writable=False),
        ]

        if is_checked == "checked":
            accounts.append(AccountMeta(pubkey=authority_pubkey, is_signer=False, is_writable=False))
            accounts.append(AccountMeta(pubkey=withdraw_pubkey, is_signer=False, is_writable=False))
            data = struct.pack("<I", instruction)
        else:
            data = struct.pack("<I", instruction) + bytes(self.payer_pubkey) + bytes(self.payer_pubkey) + struct.pack("<QQ", 0, 0) + bytes(custodian_pubkey)

        tx = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=accounts,
            data=data,
        )
        self._send_and_validate_message(sol, [tx], scenario_navigator, root_pytest_dir)

    @pytest.mark.parametrize("stake_authorize", ["StakeAuthorizeStaker", "StakeAuthorizeWithdrawer"])
    @pytest.mark.parametrize("custodian", ["with_custodian", "without_custodian"])
    @pytest.mark.parametrize("is_checked", ["checked", "unchecked"])
    def test_stake_authorize(self, sol, scenario_navigator, root_pytest_dir, stake_authorize, custodian, is_checked, test_name):
        scenario_navigator.test_name = test_name + "_" + stake_authorize + "_" + custodian + "_" + is_checked
        authority_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        custodian_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)

        stake_authorize = StakeAuthorize.StakeAuthorizeStaker if stake_authorize == "StakeAuthorizeStaker" else StakeAuthorize.StakeAuthorizeWithdrawer
        with_custodian = custodian == "with_custodian"

        instruction = StakeInstruction.StakeAuthorizeChecked if is_checked == "checked" else StakeInstruction.StakeAuthorize

        accounts=[
            AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
            AccountMeta(pubkey=SYSVAR_CLOCK, is_signer=False, is_writable=False),
            AccountMeta(pubkey=authority_pubkey, is_signer=False, is_writable=False),
        ]

        if is_checked == "checked":
            accounts.append(AccountMeta(pubkey=self.payer_pubkey, is_signer=False, is_writable=False))
            data = struct.pack("<I", instruction) + struct.pack("<I", stake_authorize)
        else:
            data = struct.pack("<I", instruction) + bytes(self.payer_pubkey) + struct.pack("<I", stake_authorize)

        if with_custodian:
            accounts.append(AccountMeta(pubkey=custodian_pubkey, is_signer=False, is_writable=False))

        tx = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=accounts,
            data=data,
        )

        self._send_and_validate_message(sol, [tx], scenario_navigator, root_pytest_dir)

    def _test_stake_delegate(self, sol, scenario_navigator, root_pytest_dir, vote_account):
        vote_account_pubkey = Pubkey.from_string(vote_account)
        authorized_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)

        tx = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=vote_account_pubkey, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_CLOCK, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_STAKE_HISTORY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=STAKE_CONFIG_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=authorized_pubkey, is_signer=False, is_writable=True),
            ],
            data=struct.pack("<I", StakeInstruction.StakeDelegate),
        )

        self._send_and_validate_message(sol, [tx], scenario_navigator, root_pytest_dir)

    def test_stake_delegate_unknown(self, sol, scenario_navigator, root_pytest_dir):
        self._test_stake_delegate(sol, scenario_navigator, root_pytest_dir, SOL.FOREIGN_ADDRESS_STR)

    def test_stake_delegate_figment(self, sol, scenario_navigator, root_pytest_dir):
        self._test_stake_delegate(sol, scenario_navigator, root_pytest_dir, SOL.FIGMENT_ADDRESS_STR)

    def test_stake_delegate_chorus_one(self, sol, scenario_navigator, root_pytest_dir):
        self._test_stake_delegate(sol, scenario_navigator, root_pytest_dir, SOL.CHORUS_ONE_ADDRESS_STR)

    def test_stake_split(self, sol, scenario_navigator, root_pytest_dir):
        split_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        authority_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)
        amount = 123456789

        tx = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=split_pubkey, is_signer=False, is_writable=False),
                AccountMeta(pubkey=authority_pubkey, is_signer=False, is_writable=False),
            ],
            data=struct.pack("<IQ", StakeInstruction.StakeSplit, amount)
        )
        self._send_and_validate_message(sol, [tx], scenario_navigator, root_pytest_dir)

    def test_stake_withdraw(self, sol, scenario_navigator, root_pytest_dir):
        to_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        authority_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)
        amount = 123456789

        tx = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=to_pubkey, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_CLOCK, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_STAKE_HISTORY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=authority_pubkey, is_signer=False, is_writable=False),
            ],
            data=struct.pack("<IQ", StakeInstruction.StakeWithdraw, amount)
        )
        self._send_and_validate_message(sol, [tx], scenario_navigator, root_pytest_dir)

    def test_stake_deactivate(self, sol, scenario_navigator, root_pytest_dir):
        authority_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)

        tx = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYSVAR_CLOCK, is_signer=False, is_writable=False),
                AccountMeta(pubkey=authority_pubkey, is_signer=False, is_writable=False),
            ],
            data=struct.pack("<I", StakeInstruction.StakeDeactivate)
        )
        self._send_and_validate_message(sol, [tx], scenario_navigator, root_pytest_dir)

    @pytest.mark.parametrize("is_checked", ["checked", "unchecked"])
    @pytest.mark.parametrize("options", ["with_options", "without_options"])
    def test_stake_set_lockup(self, sol, scenario_navigator, root_pytest_dir, is_checked, options, test_name):
        scenario_navigator.test_name = test_name + "_" + is_checked + "_" + options
        authority_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)
        custodian_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)

        instruction = StakeInstruction.StakeSetLockupChecked if is_checked == "checked" else StakeInstruction.StakeSetLockup

        if options == "with_options":
            data = struct.pack("<IBQBQ", instruction, StakeLockupArgs.OptionSome, 0, StakeLockupArgs.OptionSome, 0)
            if is_checked == "checked":
                data += bytes(custodian_pubkey)
            else:
                data += struct.pack("<Q", StakeLockupArgs.OptionSome) + bytes(custodian_pubkey)
        else:
            data = struct.pack("<IBBB", instruction, StakeLockupArgs.OptionNone, StakeLockupArgs.OptionNone, StakeLockupArgs.OptionNone)

        tx = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=custodian_pubkey, is_signer=False, is_writable=False),
            ],
            data=data,
        )
        self._send_and_validate_message(sol, [tx], scenario_navigator, root_pytest_dir)

    def test_stake_merge(self, sol, scenario_navigator, root_pytest_dir):
        to_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        authority_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)

        tx = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=to_pubkey, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYSVAR_CLOCK, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_STAKE_HISTORY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=authority_pubkey, is_signer=False, is_writable=False),
            ],
            data=struct.pack("<I", StakeInstruction.StakeMerge),
        )
        self._send_and_validate_message(sol, [tx], scenario_navigator, root_pytest_dir)

    @pytest.mark.parametrize("instruction", ["StakeAuthorizeWithSeed", "StakeAuthorizeCheckedWithSeed"])
    def test_stake_unsupported(self, sol, scenario_navigator, root_pytest_dir, instruction):
        authority_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)

        stake_instruction = StakeInstruction.StakeAuthorizeWithSeed if instruction == "StakeAuthorizeWithSeed" else StakeInstruction.StakeAuthorizeCheckedWithSeed
        tx = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
            ],
            data=struct.pack("<I", stake_instruction),
        )

        with pytest.raises(ExceptionRAPDU) as e:
            self._send_and_validate_message(sol, [tx], scenario_navigator, root_pytest_dir, valid=False)
        assert e.value.status == ErrorType.SDK_NOT_SUPPORTED

    def test_create_stake_account_and_delegate(self, sol, scenario_navigator, root_pytest_dir):
        create_account = Instruction(
            program_id=Pubkey.from_string(PROGRAM_ID_SYSTEM),
            accounts=[
                AccountMeta(pubkey=self.payer_pubkey, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
            ],
            data=struct.pack("<IQ", SystemInstruction.SystemCreateAccount, 123456789),
        )

        custodian_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
        stake_initialize = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYSVAR_RENT, is_signer=False, is_writable=False),
            ],
            data=struct.pack("<I", StakeInstruction.StakeInitialize) + bytes(self.payer_pubkey) + bytes(self.payer_pubkey) + struct.pack("<QQ", 0, 0) + bytes(custodian_pubkey),
        )

        vote_account_pubkey = Pubkey.from_string(SOL.FIGMENT_ADDRESS_STR)
        authorized_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR)
        stake_delegate = Instruction(
            program_id=STAKE_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.stake_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=vote_account_pubkey, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_CLOCK, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_STAKE_HISTORY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=STAKE_CONFIG_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=authorized_pubkey, is_signer=False, is_writable=True),
            ],
            data=struct.pack("<I", StakeInstruction.StakeDelegate),
        )

        self._send_and_validate_message(sol, [create_account, stake_initialize, stake_delegate], scenario_navigator, root_pytest_dir)
