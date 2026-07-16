#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: MP_SPDZ_HOME=/path/to/MP-SPDZ $0 /path/to/generated_instance" >&2
  exit 2
fi

if [[ -z "${MP_SPDZ_HOME:-}" ]]; then
  echo "MP_SPDZ_HOME is required" >&2
  exit 2
fi

INSTANCE_DIR="$1"
PROGRAM_PATHS=("${INSTANCE_DIR}"/*.mpc)
if [[ ${#PROGRAM_PATHS[@]} -ne 1 ]]; then
  echo "expected exactly one .mpc program in ${INSTANCE_DIR}" >&2
  exit 2
fi
PROGRAM_NAME="$(basename "${PROGRAM_PATHS[0]}" .mpc)"

cp "${PROGRAM_PATHS[0]}" "${MP_SPDZ_HOME}/Programs/Source/${PROGRAM_NAME}.mpc"
mkdir -p "${MP_SPDZ_HOME}/Player-Data"
cp "${INSTANCE_DIR}"/Player-Data/Input-P*-0 "${MP_SPDZ_HOME}/Player-Data/"

(
  cd "${MP_SPDZ_HOME}"
  ./compile.py "${PROGRAM_NAME}"
  PLAYERS=3 Scripts/semi.sh "${PROGRAM_NAME}"
)
