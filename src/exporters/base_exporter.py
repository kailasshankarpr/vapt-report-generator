from abc import ABC, abstractmethod
from src.models.vulnerability import ScanReport


class BaseExporter(ABC):
    """Abstract Base Class for Report Exporters"""

    @abstractmethod
    def export(self, report: ScanReport, output_path: str) -> str:
        """Export ScanReport to file and return output_path"""
        pass
