# Hotel PII Redaction — AWS Lambda (Presidio)

Redacts guest names, phone numbers, emails, credit cards, room numbers
and other PII from hotel transcripts using **Presidio + spaCy en_core_web_lg
+ names-dataset**, deployed as a container-based AWS Lambda.

---

## Architecture

```
S3 input bucket
      │  (ObjectCreated trigger)
      ▼
Lambda (container image from ECR)
  ├── Presidio Analyzer  (NER + 20+ built-in recognisers)
  ├── en_core_web_lg     (large spaCy model — better accuracy)
  ├── names-dataset      (160k+ names, validates NER detections)
  └── Hotel patterns     (room numbers, spelled-out names, partial cards)
      │
      ├──▶ S3 output bucket        (redacted transcript)
      └──▶ S3 token-map bucket     (token_map.json, AES-256 encrypted)
```

---

## Project structure

```
hotel_pii_lambda/
├── lambda_function/
│   ├── handler.py        # Lambda entry point
│   ├── redactor.py       # Presidio + names-dataset core logic
│   ├── Dockerfile        # Container image (bakes in spaCy model)
│   └── requirements.txt
├── terraform/
│   └── main.tf           # All AWS resources
├── deploy.sh             # Build + push + deploy script
├── local_test.py         # Test locally before deploying
└── README.md
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.12+ | python.org |
| Docker | 24+ | docker.com |
| AWS CLI | 2+ | `pip install awscli` |
| Terraform | 1.5+ | terraform.io |
| jq | any | `brew install jq` |

---

## Step 1 — Test locally first

```bash
# Install dependencies
pip install presidio-analyzer presidio-anonymizer spacy names-dataset

# Download the large spaCy model (~750 MB, one-time)
python -m spacy download en_core_web_lg

# Run on a transcript
python local_test.py --input my_transcript.txt --mode tokenize
```

---

## Step 2 — Configure AWS credentials

```bash
aws configure
# Enter: Access Key ID, Secret Access Key, Region (e.g. us-east-1), Output (json)
```

---

## Step 3 — Deploy to AWS

```bash
chmod +x deploy.sh

# Full deploy (Terraform + Docker build + push + Lambda update)
./deploy.sh

# Or if infrastructure already exists, just rebuild the image:
./deploy.sh --image-only
```

The deploy script:
1. Runs `terraform apply` to create S3 buckets, ECR repo, Lambda, IAM roles
2. Builds the Docker image (bakes in spaCy lg model — ~5 min first time)
3. Pushes to ECR
4. Updates the Lambda function
5. Runs a smoke test

---

## Step 4 — Upload a transcript

```bash
# Get the input bucket name
INPUT_BUCKET=$(cd terraform && terraform output -raw input_bucket)

# Upload a transcript — Lambda triggers automatically
aws s3 cp my_transcript.txt s3://${INPUT_BUCKET}/my_transcript.txt

# Check output (~30 seconds later)
OUTPUT_BUCKET=$(cd terraform && terraform output -raw output_bucket)
aws s3 ls s3://${OUTPUT_BUCKET}/
aws s3 cp s3://${OUTPUT_BUCKET}/my_transcript_redacted.txt .
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OUTPUT_BUCKET` | (required) | S3 bucket for redacted transcripts |
| `TOKEN_MAP_BUCKET` | (required) | S3 bucket for token maps |
| `MODE` | `redact` | `redact` or `tokenize` |
| `CONFIDENCE_THRESHOLD` | `0.6` | Presidio confidence cutoff (0–1) |

Override in Terraform `main.tf` under the `environment` block, or via:

```bash
aws lambda update-function-configuration \
  --function-name hotel-pii-redaction-prod \
  --environment "Variables={MODE=tokenize,CONFIDENCE_THRESHOLD=0.65}"
```

---

## What gets redacted

| Entity | Examples |
|--------|---------|
| `PERSON` | Guest names (with/without titles, multicultural, spelled-out) |
| `PHONE_NUMBER` | 732-423-8389, (704) 609-4376 |
| `EMAIL_ADDRESS` | guest@example.com |
| `CREDIT_CARD` | 4532 1234 5678 9010 |
| `CREDIT_CARD_PARTIAL` | last 4 of credit card 7756 |
| `ROOM_NUMBER` | Room 224, Room no 452 |
| `US_SSN` | 123-45-6789 |
| `IP_ADDRESS` | 192.168.1.1 |
| `DATE_TIME` | DOB: 01/15/1985 |

---

## Costs (approximate)

| Resource | Cost |
|----------|------|
| Lambda (5 GB, 300s, 1000 files/month) | ~$8/month |
| S3 storage (100 GB) | ~$2.30/month |
| ECR (image storage ~3 GB) | ~$0.30/month |
| CloudWatch logs | ~$0.50/month |
| **Total** | **~$11/month** |

---

## Changing the spaCy model

The Dockerfile uses `en_core_web_lg` (large, ~750 MB, best accuracy).
To use `en_core_web_trf` (transformer-based, highest accuracy but ~1.5 GB):

```dockerfile
# In Dockerfile, replace:
RUN python -m spacy download en_core_web_lg
# With:
RUN pip install spacy[transformers] && python -m spacy download en_core_web_trf
```

And in `local_test.py` / Lambda env var:
```bash
--model en_core_web_trf
```

---

## Destroying all resources

```bash
cd terraform
terraform destroy -auto-approve
```
