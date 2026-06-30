from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("kagesec")
except PackageNotFoundError:
    __version__ = "unknown"
