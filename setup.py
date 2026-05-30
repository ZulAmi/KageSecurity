from setuptools import setup

try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel

    class bdist_wheel(_bdist_wheel):
        def finalize_options(self):
            super().finalize_options()
            self.root_is_pure = False  # tells wheel this is a platform-specific dist

        def get_tag(self):
            _python, _abi, plat = super().get_tag()
            # Python code is version-agnostic; only the bundled binary is platform-specific
            return "py3", "none", plat

    cmdclass = {"bdist_wheel": bdist_wheel}
except ImportError:
    cmdclass = {}

setup(cmdclass=cmdclass)
