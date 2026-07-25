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
INPUT_PATHS=("${INSTANCE_DIR}"/Player-Data/Input-P*-0)
PLAYERS=${#INPUT_PATHS[@]}
if [[ ${PLAYERS} -lt 3 ]]; then
  echo "expected one query gateway and at least two data-party inputs" >&2
  exit 2
fi

cp "${PROGRAM_PATHS[0]}" "${MP_SPDZ_HOME}/Programs/Source/${PROGRAM_NAME}.mpc"
mkdir -p "${MP_SPDZ_HOME}/Player-Data"
cp "${INPUT_PATHS[@]}" "${MP_SPDZ_HOME}/Player-Data/"

(
  cd "${MP_SPDZ_HOME}"
  if [[ "${MP_SPDZ_SKIP_COMPILE:-0}" != "1" ]]; then
    ./compile.py --preserve-mem-order "${PROGRAM_NAME}"
  fi
  PROTOCOL="${MP_SPDZ_PROTOCOL:-semi}"
  case "${PROTOCOL}" in
    semi|semi2k|replicated|ring|ps-rep-ring|sy-rep-ring|rep4-ring|shamir)
      PLAYERS="${PLAYERS}" "Scripts/${PROTOCOL}.sh" "${PROGRAM_NAME}"
      ;;
    *)
      echo "unsupported MP_SPDZ_PROTOCOL=${PROTOCOL}" >&2
      exit 2
      ;;
  esac
)
