from dataclasses import replace
from pathlib import Path

from Vrin_TI.config import config


def test_config(directory: str, **overrides):
    feeds = {name: {**values, "enabled": False} for name, values in config.feeds.items()}
    values = dict(database_path=Path(directory) / "ti.db", log_dir=Path(directory) / "logs",
                  service_token="test-service-token-with-at-least-32-chars", transport="local",
                  allowed_hosts=["testserver", "127.0.0.1", "localhost"], feeds=feeds,
                  collect_on_start=False, external_enrichment=False, external_submission=False)
    values.update(overrides)
    return replace(config, **values)
