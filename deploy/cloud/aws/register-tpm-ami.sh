#!/usr/bin/env bash
#
# register-tpm-ami.sh — re-register a stock Ubuntu 24.04 AMI with
# TpmSupport=v2.0 so AWS NitroTPM 2.0 instances expose /dev/tpm*.
#
# Phase 6 #118 lets the agent seal cert material against TPM PCR 7.
# AWS NitroTPM 2.0 satisfies the contract for cloud workloads, but
# Canonical's stock Ubuntu 24.04 amd64 AMIs ship with TpmSupport=None,
# so a stock m7a.large boots without /dev/tpm* and the agent silently
# falls back to the keyring → file chain.
#
# This recipe takes the stock AMI's root snapshot and registers a new
# AMI on top of it with TpmSupport=v2.0 + boot_mode=uefi. No copying,
# no rebuild — same blocks, new metadata. Cost: a single register-image
# API call. Once the new AMI exists, launch m7a/m7i instances from it
# and the agent's TPM probe succeeds.
#
# Usage:
#   ./register-tpm-ami.sh --source-ami ami-0abcdef1234567890 \
#     [--region us-west-2] [--name slither-ubuntu-24.04-tpm-amd64]
#
# Requires: aws CLI v2 with permissions for:
#   ec2:DescribeImages, ec2:RegisterImage
# Output: the new AMI ID on stdout.

set -euo pipefail

NAME="slither-ubuntu-24.04-tpm-amd64"
REGION="${AWS_REGION:-us-west-2}"
SOURCE_AMI=""
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-ami)  SOURCE_AMI="$2"; shift 2;;
        --region)      REGION="$2"; shift 2;;
        --name)        NAME="$2"; shift 2;;
        --dry-run)     DRY_RUN="true"; shift;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0;;
        *) echo "unknown flag: $1" >&2; exit 2;;
    esac
done

if [[ -z "${SOURCE_AMI}" ]]; then
    echo "error: --source-ami is required" >&2
    echo "  hint: find the latest Canonical Ubuntu 24.04 amd64 AMI for ${REGION} via" >&2
    echo "        aws ec2 describe-images --owners 099720109477 \\" >&2
    echo "          --filters 'Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*' \\" >&2
    echo "          --region ${REGION} --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text" >&2
    exit 2
fi

echo "→ resolving root snapshot for ${SOURCE_AMI} in ${REGION}"
read -r ROOT_DEVICE SNAPSHOT_ID <<<"$(aws ec2 describe-images \
    --region "${REGION}" \
    --image-ids "${SOURCE_AMI}" \
    --query 'Images[0].[RootDeviceName,BlockDeviceMappings[0].Ebs.SnapshotId]' \
    --output text)"

if [[ -z "${SNAPSHOT_ID}" || "${SNAPSHOT_ID}" == "None" ]]; then
    echo "error: could not resolve root snapshot for ${SOURCE_AMI}" >&2
    exit 1
fi

echo "  root device: ${ROOT_DEVICE}"
echo "  snapshot:    ${SNAPSHOT_ID}"
echo "  new AMI:     ${NAME}"
echo "  TpmSupport:  v2.0  (boot_mode=uefi)"

if [[ "${DRY_RUN}" == "true" ]]; then
    echo "(dry-run; not calling register-image)"
    exit 0
fi

NEW_AMI="$(aws ec2 register-image \
    --region "${REGION}" \
    --name "${NAME}" \
    --architecture x86_64 \
    --root-device-name "${ROOT_DEVICE}" \
    --boot-mode uefi \
    --tpm-support v2.0 \
    --ena-support \
    --virtualization-type hvm \
    --block-device-mappings "DeviceName=${ROOT_DEVICE},Ebs={SnapshotId=${SNAPSHOT_ID},VolumeType=gp3,DeleteOnTermination=true}" \
    --query ImageId --output text)"

echo "${NEW_AMI}"
