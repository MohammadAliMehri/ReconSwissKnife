# -*- coding: utf-8 -*-
"""Python 2/Jython and Python 3 types for pure-core development tests."""
try:
    string_types = (basestring,)
    text_type = unicode
except NameError:
    string_types = (str,)
    text_type = str
