from abc import ABC, abstractmethod
from event_tracker.models import Credential


class CredentialExtractor(ABC):
    """
    Base class for a credential extractor.
    """

    @abstractmethod
    def extract(self, input_text: str, default_system: str) -> [Credential]:
        """
        Returns a list of Credential objects found in the text.
        Objects will be added to the DB if required _by the caller_.
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
    def extract(self, input_text: str, default_system: str) -> [Credential]:
        return list(self.cred_generator(input_text, default_system))

    @abstractmethod
    def cred_generator(self, input_text: str, default_system: str) -> Credential:
        """
        Generator method that yields Credential objects from the input_text
        """
        pass


valid_windows_domain = r'[^,~:!@#$%^&\')(}{_ \n]{2,155}'
valid_windows_username = r'[^"/\\[\]\:;|=,+*?<>\n]{1,64}'
