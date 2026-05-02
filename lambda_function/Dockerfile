# ─────────────────────────────────────────────────────────────
#  Hotel PII Redaction Lambda — Container Image
#  Base: AWS Lambda Python 3.12 runtime
#
#  spaCy en_core_web_lg (~750 MB) is baked into the image so
#  Lambda cold starts don't need internet access at runtime.
#
#  THREE MODEL INSTALL METHODS — choose one:
#
#  METHOD A (default): pip install from GitHub release URL
#    Works if your Docker build machine has internet access.
#    docker build --build-arg MODEL_METHOD=github .
#
#  METHOD B: install from a .whl pre-downloaded into this folder
#    Use when GitHub is blocked (corporate firewalls, CI/CD).
#    1. Download on a machine with internet:
#       wget https://github.com/explosion/spacy-models/releases/download/\
#            en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
#    2. Put the .whl file in this same folder (next to Dockerfile)
#    3. docker build --build-arg MODEL_METHOD=local .
#
#  METHOD C: install from your own S3 bucket
#    Use in fully air-gapped environments.
#    1. Upload the .whl to s3://your-bucket/models/en_core_web_lg-3.8.0.whl
#    2. docker build --build-arg MODEL_METHOD=s3 \
#         --build-arg MODEL_S3_URI=s3://your-bucket/models/en_core_web_lg-3.8.0.whl .
# ─────────────────────────────────────────────────────────────

FROM public.ecr.aws/lambda/python:3.12

ARG MODEL_METHOD=github
ARG MODEL_S3_URI=""
ARG BUILD_DATE=""
ARG IMAGE_TAG=""

# Labels for traceability
LABEL build.date="${BUILD_DATE}" \
      build.tag="${IMAGE_TAG}" \
      model.method="${MODEL_METHOD}"

WORKDIR ${LAMBDA_TASK_ROOT}

# ── System deps (spaCy needs gcc for C extensions) ────────────
RUN dnf install -y gcc gcc-c++ && dnf clean all

# ── Python dependencies ────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── spaCy model — METHOD A: from GitHub release URL ───────────
# Runs if MODEL_METHOD=github (default)
RUN if [ "$MODEL_METHOD" = "github" ]; then \
      echo "Installing en_core_web_lg from GitHub..." && \
      pip install --no-cache-dir \
        "https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl" && \
      echo "Model installed OK"; \
    fi

# ── spaCy model — METHOD B: from local .whl file ──────────────
# Copy the .whl only if it exists in build context
# (Docker COPY fails if source missing, so we use a workaround)
COPY en_core_web_lg*.whl* /tmp/models/
RUN if [ "$MODEL_METHOD" = "local" ]; then \
      WHL=$(ls /tmp/models/en_core_web_lg*.whl 2>/dev/null | head -1) && \
      if [ -z "$WHL" ]; then \
        echo "ERROR: MODEL_METHOD=local but no en_core_web_lg*.whl found in build context." && \
        echo "Download it first: wget https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl" && \
        exit 1; \
      fi && \
      echo "Installing en_core_web_lg from local file: $WHL" && \
      pip install --no-cache-dir "$WHL" && \
      echo "Model installed OK"; \
    fi

# ── spaCy model — METHOD C: from S3 ───────────────────────────
RUN if [ "$MODEL_METHOD" = "s3" ]; then \
      if [ -z "$MODEL_S3_URI" ]; then \
        echo "ERROR: MODEL_METHOD=s3 but MODEL_S3_URI is not set." && exit 1; \
      fi && \
      echo "Downloading en_core_web_lg from S3: $MODEL_S3_URI" && \
      aws s3 cp "$MODEL_S3_URI" /tmp/en_core_web_lg.whl && \
      pip install --no-cache-dir /tmp/en_core_web_lg.whl && \
      rm /tmp/en_core_web_lg.whl && \
      echo "Model installed OK"; \
    fi

# ── Verify model is installed ──────────────────────────────────
RUN python -c "import en_core_web_lg; nlp = en_core_web_lg.load(); print('Model verified:', nlp.meta['name'], nlp.meta['version'])"

# ── Pre-warm names-dataset (~200 MB pickle, loads once) ───────
RUN python -c "from names_dataset import NameDataset; nd = NameDataset(); print('names-dataset verified:', len(nd.first_names), 'first names')"

# ── Lambda function code ───────────────────────────────────────
COPY handler.py  .
COPY redactor.py .

# ── Entry point ────────────────────────────────────────────────
CMD ["handler.lambda_handler"]
