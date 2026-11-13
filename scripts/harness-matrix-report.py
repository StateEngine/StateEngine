#!/usr/bin/env python3
"""Summarize native harness smoke receipts; does not execute product commands."""
from harness_matrix.report import main

if __name__ == '__main__':
    raise SystemExit(main())
