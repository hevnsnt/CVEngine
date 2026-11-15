#!/usr/bin/env bash
# Writes an encrypted pg_dump of this server's database to an S3-compatible bucket (DigitalOcean Spaces): the final export before a server is
# destroyed, or the nightly dump.
#
#   cvl-export.sh --key <object key> [--bucket B] [--endpoint URL] [--recipient AGE_PUBLIC_KEY] [--no-quiesce]
#
# The dump is `pg_dump -Fc` (compressed custom format; restore with pg_restore), encrypted with age to the PUBLIC key given, streamed straight into
# `aws s3 cp -` (the AWS CLI, which speaks to Spaces with --endpoint-url): no plaintext dump is ever written to disk or to the bucket, and an export
# without a recipient is refused. Settings: CVL_S3_BUCKET, CVL_S3_ENDPOINT (for example https://nyc3.digitaloceanspaces.com), CVL_AGE_RECIPIENT
# (an age1... public key; the private key stays with the operator); the bucket's access keys are the AWS CLI's usual AWS_ACCESS_KEY_ID and
# AWS_SECRET_ACCESS_KEY in the environment (never arguments, never printed, never written to a file here).
# Unless --no-quiesce, celery, celery-beat and web are stopped first, so nothing changes after the dump (the final export before deprovision);
# they are not started again. The upload is checked with head-object afterwards: an empty or missing object is a failure.
# Stdout: one JSON line {"ok":true,"bucket":"...","key":"...","bytes":N}. Errors: stderr and a non-zero exit.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
umask 077

key='' bucket=${CVL_S3_BUCKET:-} endpoint=${CVL_S3_ENDPOINT:-} recipient=${CVL_AGE_RECIPIENT:-} quiesce=1
while [ $# -gt 0 ]; do
  case $1 in
    --key) key=${2:-}; shift 2 || cvl_die "--key needs a value" ;;
    --bucket) bucket=${2:-}; shift 2 || cvl_die "--bucket needs a value" ;;
    --endpoint) endpoint=${2:-}; shift 2 || cvl_die "--endpoint needs a value" ;;
    --recipient) recipient=${2:-}; shift 2 || cvl_die "--recipient needs a value" ;;
    --no-quiesce) quiesce=0; shift ;;
    *) cvl_die "usage: $0 --key <object key> [--bucket B] [--endpoint URL] [--recipient AGE_PUBLIC_KEY] [--no-quiesce]" ;;
  esac
done
cvl_root_or_die
cvl_need aws age

[[ $key =~ ^[A-Za-z0-9][A-Za-z0-9._/=-]{0,500}$ && $key != *..* ]] || cvl_die "--key must be a plain object key (letters, digits and . _ / = -)"
[[ $bucket =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || cvl_die "the bucket (--bucket or CVL_S3_BUCKET) is missing or not a bucket name"
[[ $endpoint =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || cvl_die "the endpoint (--endpoint or CVL_S3_ENDPOINT) must be https://<host>"
[[ $recipient =~ ^age1[a-z0-9]{50,}$ ]] || cvl_die "an age public key is required (--recipient or CVL_AGE_RECIPIENT, age1...): a dump is never uploaded unencrypted"
[ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ] || cvl_die "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in the environment"

cvl_compose_layout
"${COMPOSE[@]}" ps -q --status running db 2>/dev/null </dev/null | grep -q . || cvl_die "the database container is not running"
if [ "$quiesce" = 1 ]; then
  cvl_log "stopping celery, celery-beat and web so nothing changes after the dump"
  "${COMPOSE[@]}" stop celery celery-beat web </dev/null >&2 || cvl_die "could not stop the application services"
fi

cvl_log "dumping the database to s3://$bucket/$key (encrypted)"
# shellcheck disable=SC2016  # the variables are the database container's own, expanded there
"${COMPOSE[@]}" exec -T db sh -c 'pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"' </dev/null \
  | age -r "$recipient" \
  | aws s3 cp - "s3://$bucket/$key" --endpoint-url "$endpoint" --only-show-errors >&2

size=$(aws s3api head-object --bucket "$bucket" --key "$key" --endpoint-url "$endpoint" --query ContentLength --output text) \
  || cvl_die "the uploaded object cannot be read back"
[[ $size =~ ^[0-9]+$ ]] && [ "$size" -gt 200 ] || cvl_die "the uploaded object is empty or too small ($size bytes)"
printf '{"ok":true,"bucket":"%s","key":"%s","bytes":%s}\n' "$bucket" "$key" "$size"
