from .const import TOOL_NAME, VERSION

__all__ = ["TOOL_NAME", "VERSION", "main"]
__version__ = VERSION


def main(argv=None):
    """Console entry point."""
    from .cli import main as _main
    return _main(argv)
