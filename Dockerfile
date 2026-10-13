# SecureMailScope Analysis Engine Container
# Base image: Python 3.11-slim-bookworm pinned by verified cryptographic digest (Decisions 006, 020)
FROM python:3.11-slim-bookworm@sha256:7f4d22197ae71221f7db19eb0b1f4806a143b879c5dc2ab440056e4c76b1f237

# Install pinned dependencies
RUN pip install --no-cache-dir \
    dpkt==1.9.8 \
    cryptography==48.0.0 \
    jsonschema==4.25.1 \
    pyyaml==6.0.2

# Create non-root engine user
RUN useradd -m -u 1000 -U engineuser

WORKDIR /app

# Copy strictly required engine components only
COPY engine /app/engine
COPY ruleset /app/ruleset
COPY lab/ca/out/client_trust.crt /app/lab/ca/out/client_trust.crt

# Ensure non-root user has read access
RUN chown -R engineuser:engineuser /app

# Set PYTHONPATH so python -m smscope finds the package
ENV PYTHONPATH=/app/engine
ENV PYTHONUNBUFFERED=1

USER engineuser

# Pinned Entrypoint per Prompt 5.8 specification
ENTRYPOINT ["python", "-m", "smscope"]
