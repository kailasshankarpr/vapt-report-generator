from abc import ABC, abstractmethod
from typing import List
from src.models.vulnerability import Vulnerability


class BaseParser(ABC):
    """Abstract base class for all scanner output parsers"""

    @abstractmethod
    def parse(self, file_path: str) -> List[Vulnerability]:
        """Parse input file and return list of normalized Vulnerability objects"""
        pass
