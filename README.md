# JWT Cracker

A Python tool for cracking JWT HS256 signature keys using dictionary attacks and brute force methods.

## Features

- **Common Secrets Attack**: Tests against a list of commonly used weak keys
- **Dictionary Attack**: Uses custom wordlists to find the signing key
- **Brute Force Attack**: Systematically tries all possible combinations within specified parameters
- **JWT Parsing**: Automatically decodes and displays JWT header and payload information

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd jwt_cracker_test
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Run with a JWT token:
```bash
python main.py <JWT_TOKEN>
```

### Advanced Options

```bash
python main.py <JWT_TOKEN> [OPTIONS]

Options:
  -w, --wordlist PATH     Path to custom wordlist file
  -b, --brute-force      Enable brute force attack
  --min-length INT       Minimum password length for brute force (default: 1)
  --max-length INT       Maximum password length for brute force (default: 6)
  --charset STRING       Custom character set for brute force
```

### Examples

1. **Basic cracking with built-in wordlist:**
```bash
python main.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9.signature
```

2. **Using custom wordlist:**
```bash
python main.py <JWT_TOKEN> -w passwords.txt
```

3. **Brute force attack:**
```bash
python main.py <JWT_TOKEN> -b --max-length 8
```

4. **Custom character set for brute force:**
```bash
python main.py <JWT_TOKEN> -b --charset "0123456789" --max-length 6
```

### Demo Mode

Run without arguments to see a demonstration:
```bash
python main.py
```

## Attack Methods

The tool uses a three-step approach:

1. **Common Secrets**: Tests ~50 commonly used weak keys including:
   - `secret`, `password`, `123456`
   - JWT-specific terms like `jwt_secret`, `secretkey`
   - Empty strings and common defaults

2. **Dictionary Attack**: Tests passwords from:
   - Custom wordlist file (if provided)
   - Built-in wordlist with common passwords and JWT-related terms
   - 4-digit number combinations (0000-9999)

3. **Brute Force**: Systematically generates and tests all combinations:
   - Configurable character set (default: lowercase + digits)
   - Adjustable length range
   - Real-time progress reporting

## Output

The tool provides detailed information including:
- Decoded JWT header and payload
- Progress updates during attacks
- Performance metrics (passwords tested per second)
- Success confirmation with the discovered key

## Security Note

This tool is intended for educational purposes and authorized security testing only. Use only on JWT tokens you own or have explicit permission to test.

## Requirements

- Python 3.6+
- PyJWT library

## License

This project is for educational and authorized security testing purposes only.