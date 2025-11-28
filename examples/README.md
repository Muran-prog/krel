# KREL Examples

This directory contains examples demonstrating various use cases of the KREL library.

## Examples

### [basic.py](basic.py)
Simple encryption and decryption of a text file.

```bash
python basic.py
```

### [rekey.py](rekey.py)
Demonstrates instant password change without re-encryption.

```bash
python rekey.py
```

### [error_handling.py](error_handling.py)
Shows how to handle different error cases (wrong password, corrupted files, etc.).

```bash
python error_handling.py
```

### [async_example.py](async_example.py)
Using the async API for better performance with large files.

```bash
python async_example.py
```

## Running Examples

Make sure KREL is installed:

```bash
pip install krel
```

Or if developing locally:

```bash
maturin develop --release
```

Then run any example:

```bash
cd examples
python basic.py
```
