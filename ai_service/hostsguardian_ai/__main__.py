import logging

import uvicorn
from pydantic import ValidationError

from .config import Settings


def main():
    try:
        settings = Settings()
    except ValidationError:
        raise SystemExit("Invalid AI configuration; check HG_AI settings") from None
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s %(message)s")
    uvicorn.run("hostsguardian_ai.api:create_app", factory=True, host=settings.host,
                port=settings.port, log_level=settings.log_level.lower(), access_log=False,
                workers=1, limit_concurrency=settings.max_concurrent_investigations + 16)


if __name__ == "__main__":
    main()
