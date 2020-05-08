#!/usr/bin/env python3
from pygments.lexer import RegexLexer, bygroups, include
from pygments.token import *

from pygments.style import Style
from prompt_toolkit.styles.pygments import style_from_pygments_cls
from pygments.styles import get_style_by_name

PwncatStyle = style_from_pygments_cls(get_style_by_name("monokai"))


class LocalCommandLexer(RegexLexer):

    tokens = {
        "root": [
            (r"download", Name.Function),
            (r"upload", Name.Function),
            (r"sync", Name.Function),
            (r"help", Name.Function),
            (r"privesc", Name.Function),
            (r"--?[a-zA-Z-]+", Name.Label),
            (r"'", String.Single),
            (r".", Text),
        ],
        "single-string": [
            (r"\'", String.Single),
            (r"'", String.Single, "#pop"),
            (r".", String.Single),
        ],
        "double-string": [
            (r"\"", String.Double),
            (r'"', String.Double, "#pop"),
            (r".", String.Double),
        ],
    }
