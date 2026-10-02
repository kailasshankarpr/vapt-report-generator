import os
from datetime import datetime
import jinja2
from src.exporters.base_exporter import BaseExporter
from src.models.vulnerability import ScanReport


class HTMLExporter(BaseExporter):
    """Generates modern interactive HTML reports using Jinja2"""

    def __init__(self, template_dir: str = "src/templates"):
        self.template_dir = template_dir
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=True
        )

    def export(self, report: ScanReport, output_path: str) -> str:
        template = self.env.get_template("report.html")

        css_path = os.path.join(self.template_dir, "styles.css")
        css_content = ""
        if os.path.exists(css_path):
            with open(css_path, "r", encoding="utf-8") as f:
                css_content = f.read()

        rendered_html = template.render(
            report=report,
            css_content=css_content,
            now=datetime.now()
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        return output_path
