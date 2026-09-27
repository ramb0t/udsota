"""`python -m udsota`: the same entry point as the udsota command."""
import sys

from .cli import main

sys.exit(main())
