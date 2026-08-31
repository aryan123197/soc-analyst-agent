"""Live event sources that feed items into the pipeline.

Each source runs as a background thread and calls run_pipeline for every item
it produces, so the live dashboard sees them exactly as it sees a manual
POST /ingest. See replay.py (synthetic traffic) and gmail.py (real inbox).
"""
