from setuptools import setup, find_packages

setup(
    name="vapt-report-generator",
    version="1.0.0",
    description="Enterprise VAPT Report Generator CLI and Core Engine",
    author="FlowGraph Security Team",
    packages=find_packages(),
    install_requires=[
        "jinja2>=3.1.0",
        "pyyaml>=6.0",
        "pydantic>=2.0.0",
        "lxml>=4.9.0",
        "beautifulsoup4>=4.12.0",
        "python-docx>=0.8.11",
        "markdown>=3.4.0",
        "reportlab>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "vapt-report=src.cli:main",
        ],
    },
    python_requires=">=3.8",
)
