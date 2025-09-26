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
