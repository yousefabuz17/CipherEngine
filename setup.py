from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as lg_desc:
    long_description = lg_desc.read()

setup(
    name="cipher_engine",
    version="0.3.0",
    author="Yousef Abuzahrieh",
    author_email="yousefzahrieh17@gmail.com",
    description="Versatile cryptographic utility designed for secure encryption and decryption operations. \
                It supports various cryptographic algorithms, implements key derivation functions, \
                and facilitates secure storage using INI/JSON serializations.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yousefabuz17/CipherEngine/tree/main",
    download_url='https://github.com/yousefabuz17/CipherEngine.git',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    platforms=["Windows", "Linux", "MacOS"],
    license="Apache Software License",
    python_requires='>=3.10',
    install_requires=['cryptography~=41.0.4', 'numpy~=1.26.3',
                    'psutil~=5.9.7', 'pytest~=7.4.3',
                    'setuptools~=68.2.2'],
    classifiers=[
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: Apache Software License", 
    "Operating System :: OS Independent",
    ],
)
