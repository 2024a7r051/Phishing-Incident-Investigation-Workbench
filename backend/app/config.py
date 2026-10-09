import os
from pydantic import BaseModel

class Settings(BaseModel):
    # Free API keys can be supplied via environment variables or .env
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    TIMEOUT_SECONDS: float = float(os.getenv("ENRICHMENT_TIMEOUT", "4.0"))

settings = Settings()
