"""Allow python -m attack_search after installing the package."""

from attack_search.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
