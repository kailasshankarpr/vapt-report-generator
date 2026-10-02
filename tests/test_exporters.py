import unittest
import os
from src.core.report_engine import ReportEngine
from src.exporters import HTMLExporter, PDFExporter, DOCXExporter, JSONExporter


class TestExporters(unittest.TestCase):

    def setUp(self):
        engine = ReportEngine()
        raw = engine.load_sources([
            {'path': 'samples/burp_sample.xml', 'type': 'burp'},
            {'path': 'samples/nuclei_sample.json', 'type': 'nuclei'}
        ])
        self.report = engine.create_report(raw, client_name="Test Client")
        os.makedirs("output_test", exist_ok=True)

    def test_html_export(self):
        path = "output_test/test_report.html"
        HTMLExporter().export(self.report, path)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(os.path.getsize(path) > 1000)

    def test_pdf_export(self):
        path = "output_test/test_report.pdf"
        PDFExporter().export(self.report, path)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(os.path.getsize(path) > 1000)

    def test_docx_export(self):
        path = "output_test/test_report.docx"
        DOCXExporter().export(self.report, path)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(os.path.getsize(path) > 1000)

    def test_json_export(self):
        path = "output_test/test_report.json"
        JSONExporter().export(self.report, path)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(os.path.getsize(path) > 500)


if __name__ == "__main__":
    unittest.main()
