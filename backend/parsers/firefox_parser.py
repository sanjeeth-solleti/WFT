"""Firefox parsing is now unified inside ChromiumParser (Hindsight Browser Engine)."""
from typing import Dict
from backend.parsers.base_parser import BaseParser

class FirefoxParser(BaseParser):
    def parse(self) -> Dict[str, int]:
        return {}
