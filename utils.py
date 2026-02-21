import os
from typing import Tuple


def get_voc_creds() -> Tuple[str, str]:
    """
    Retrieve API key/base_url for Vocareum, stripping quotes/whitespace.

    Returns:
        (api_key, base_url)
    Raises:
        ValueError if no Vocareum API key is found.
    """
    api_key_raw = os.getenv("VOCAREUM_API_KEY") or ""
    api_key = str(api_key_raw).strip().strip("\"'")  # remove accidental quotes/newlines
    if not api_key:
        raise ValueError("VOCAREUM_API_KEY is not set")

    base_url_raw = os.getenv("VOCAREUM_API_BASE", "https://openai.vocareum.com/v1")
    base_url = str(base_url_raw).strip().strip("\"'")
    return api_key, base_url
