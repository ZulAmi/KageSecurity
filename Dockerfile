FROM python:3.12-slim

# System deps for Playwright Chromium + lxml + PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxslt-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -e ".[all]" \
    && playwright install chromium --with-deps

ENTRYPOINT ["kagesec"]
CMD ["--help"]
