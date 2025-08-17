import subprocess
from typing import List, Optional

class CommandError(Exception):
    pass

ALLOWED_BINARIES = {
}

def safe_run(argv: List[str], *, timeout: Optional[int] = 10) -> subprocess.CompletedProcess:
    if not argv or not isinstance(argv, list) or not all(isinstance(x, str) for x in argv):
        raise CommandError("invalid argv")
    bin_path = argv[0]
    if ALLOWED_BINARIES and bin_path not in ALLOWED_BINARIES:
        raise CommandError("binary not allowed")
    try:
        return subprocess.run(argv, timeout=timeout, check=True, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        raise CommandError("timeout")
    except subprocess.CalledProcessError as e:
        raise CommandError(f"nonzero exit: {e.returncode}")
    except Exception as e:
        raise CommandError(str(e))
