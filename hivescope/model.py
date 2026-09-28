"""
Report data model.

A report is a list of Section objects. Each section owns an ordered list
of typed elements that the text / HTML / GUI renderers know how to draw:

    ("kv",    [(key, value), ...])         key/value pairs
    ("sub",   "Sub-heading text")          a sub-heading
    ("path",  "HKLM\\SYSTEM\\...")         the full source registry key
    ("paths", ["HKLM\\...", "HKLM\\..."])  several source keys
    ("text",  "free text")                 a paragraph
    ("note",  "italic note")               a muted note (e.g. "no data")
    ("list",  [items])                     a bullet/mono list
    ("table", [headers], [[cells], ...])   a data table
"""

# Full-path builders:
#   SYSTEM  -> HKLM\SYSTEM\...
#   SOFTWARE-> HKLM\SOFTWARE\...
#   SAM     -> HKLM\SAM\SAM\...   (the SAM hive root contains a 'SAM' subkey)
#   NTUSER  -> HKU\<user>\...
def p_system(*parts):
    return "\\".join(("HKLM\\SYSTEM",) + tuple(parts))


def p_software(*parts):
    return "\\".join(("HKLM\\SOFTWARE",) + tuple(parts))


def p_sam(*parts):
    return "\\".join(("HKLM\\SAM\\SAM",) + tuple(parts))


def p_user(user, *parts):
    return "\\".join(("HKU\\" + str(user),) + tuple(parts))


class Section:
    def __init__(self, key, title):
        self.key = key
        self.title = title
        self.elements = []

    def kv(self, pairs):
        pairs = [(k, ("" if v is None else v)) for k, v in pairs]
        self.elements.append(("kv", pairs))
        return self

    def sub(self, text):
        self.elements.append(("sub", text))
        return self

    def path(self, p):
        self.elements.append(("path", p))
        return self

    def paths(self, ps):
        self.elements.append(("paths", list(ps)))
        return self

    def text(self, t):
        self.elements.append(("text", t))
        return self

    def listing(self, items):
        self.elements.append(("list", list(items)))
        return self

    def table(self, headers, rows):
        self.elements.append(("table", list(headers), [list(r) for r in rows]))
        return self

    def note(self, t):
        self.elements.append(("note", t))
        return self

    def is_empty(self):
        return len(self.elements) == 0
