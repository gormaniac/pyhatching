import os
import sys
sys.path.insert(0, os.path.abspath("../src"))

project = "PyHatching"
copyright = "2023, John Gorman"
author = "John Gorman"

extensions = ["sphinx.ext.autodoc"]

templates_path = ["_templates"]
exclude_patterns = []


html_theme = "shibuya"
html_static_path = ["_static"]
html_title = "PyHatching Docs"

html_baseurl = 'https://docs.gormo.co/pyhatching/'

html_theme_options = {
    "analytics_id": "G-6G9XWTWCQG",
    "accent_color": "teal",
    "color_mode": "auto",
    "nav_socials": [
        {
            "name": "GitHub",
            "url": "https://github.com/gormaniac/pyhatching",
            "icon": "simple-icons:github",
        },
        {
            "name": "PyPI",
            "url": "https://pypi.org/project/pyhatching/",
            "icon": "simple-icons:pypi",
        },
    ],
    "foot_socials": [
        {
            "name": "GitHub",
            "url": "https://github.com/gormaniac/pyhatching",
            "icon": "simple-icons:github",
        },
        {
            "name": "PyPI",
            "url": "https://pypi.org/project/pyhatching/",
            "icon": "simple-icons:pypi",
        },
    ]
}