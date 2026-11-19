FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY exposureintel ./exposureintel
RUN pip install --no-cache-dir --no-deps .

RUN useradd --create-home appuser
USER appuser

ENTRYPOINT ["exposureintel"]