from distutils.core import setup

setup(
        name='dedex',
        version='1.0.0',
        packages=['dexdump'],
        url='',
        license='BSD',
        author='jrusnak',
        author_email='',
        description='dex parsing tool to find test annotations',
        scripts=['dexdump/dedex']
)
