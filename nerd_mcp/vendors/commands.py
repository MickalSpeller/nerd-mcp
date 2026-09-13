"""Public helpers for recognizing rejected fixed vendor commands."""

import re


def command_error(output: str) -> bool:
    return bool(re.search(
        r"(?im)^\s*(?:%\s*(?:Invalid|Unknown|Unrecognized|Incomplete|Ambiguous|Authorization|Error|Access denied)|"
        r"command fail\.|parse error|unknown action)",
        output,
    ))
