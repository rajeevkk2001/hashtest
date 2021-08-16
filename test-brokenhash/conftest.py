import pytest
from app_manager import App

@pytest.fixture()
def setup():

    print("\nOpening the App")
    test_helper = App()
    test_helper.open_application()
    yield
    print("\nAfter test ")