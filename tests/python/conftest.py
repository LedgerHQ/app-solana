import pytest
from ragger.conftest import configuration
from .navigation_helper import NavigationHelper
from application_client.solana import SolanaClient

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

configuration.OPTIONAL.BACKEND_SCOPE = "function"

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )

@pytest.fixture(scope="function")
def navigation_helper(backend, navigator, scenario_navigator, test_name, root_pytest_dir):
    return NavigationHelper(backend=backend, navigator=navigator, scenario_navigator=scenario_navigator, test_name=test_name, root_pytest_dir=root_pytest_dir)

@pytest.fixture(scope="function")
def sol(backend):
    return SolanaClient(backend)

# Pytest is trying to do "smart" stuff and reorders tests using parametrize by alphabetical order of parameter
# This breaks the backend scope optim. We disable this
def pytest_collection_modifyitems(config, items):
    # The full generic clear-signing flow (finalize + NBGL review navigation) does
    # not yet run on Nano X. Skip those deep tests there while keeping the ones that
    # only validate PKI certificate acceptance and APDU verification. Deep tests are
    # identified by their use of the scenario_navigator fixture.
    if config.getoption("--device") == "nanox":
        skip_deep = pytest.mark.skip(reason="Generic clear-signing review flow not yet supported on Nano X")
        for item in items:
            if "test_clear_signing" in item.nodeid and "scenario_navigator" in item.fixturenames:
                item.add_marker(skip_deep)

    def param_part(item):
        # Sort by node id as usual
        return item.nodeid

    # re-order the items using the param_part function as key
    items[:] = sorted(items, key=param_part)
