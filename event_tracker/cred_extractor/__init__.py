from abc import ABC, abstractmethod
from event_tracker.models import Credential


class CredentialExtractor(ABC):
    """
    Base class for a credential extractor.
    """

    @abstractmethod
    def extract(self, input_text: str, default_system: str) -> ([Credential], [Credential]):
        """
        Returns a tuple of:
          a list of new Credential objects found in the text to add to the database,
          a list of existing Credential objects superceeded as a result of the first list which should be deleted.

        Objects will be added and removed to/from the DB if required _by the caller_.
        """
        pass

    @classmethod
    def __subclasshook__(cls, C):
        if C is ABC:
            return False


class CredentialExtractorGenerator(CredentialExtractor, ABC):
    """
    Special type of CredentialExtractor which uses a generator method
    """
    def extract(self, input_text: str, default_system: str) -> ([Credential], [Credential]):
        return list(self.cred_generator(input_text, default_system)), list()

    @abstractmethod
    def cred_generator(self, input_text: str, default_system: str) -> Credential:
        """
        Generator method that yields Credential objects from the input_text
        """
        pass


valid_windows_domain = r'[^,~:!@#$%^&\')(}{_ \n]{2,155}'
valid_windows_username = r'[^"/\\[\]\:;|=,+*?<>\n]{1,64}'
EMPTY_LMHASH = "AAD3B435B51404EEAAD3B435B51404EE"
EMPTY_NTLMHASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
