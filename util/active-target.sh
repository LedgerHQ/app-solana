#!/usr/bin/env bash

declare -r nanos_sdk=NANOS_SDK
declare -r nanox_sdk=NANOX_SDK
declare -r nanosp_sdk=NANOSP_SDK
declare -r stax_sdk=STAX_SDK

sdk_mnemonic_to_bolos_variable() {
  local -r sdk_mnemonic="${1:?}"
  local bolos_sdk_var=
  case "$sdk_mnemonic" in
    s)
      bolos_sdk_var="$nanos_sdk"
      ;;
    x)
      bolos_sdk_var="$nanox_sdk"
      ;;
    sp)
      bolos_sdk_var="$nanosp_sdk"
      ;;
    stax)
      bolos_sdk_var="$stax_sdk"
      ;;
    *)
      echo "unimplemented sdk mnemonic: \`$sdk\`" 1>&2
      exit 1
      ;;
  esac
  echo "$bolos_sdk_var"
}

get_last_target_sdk_stamp_filepath() {
  local -r app_root="${1:?'missing required arg 1: `app_root`'}"
  local -r stamp_dir="${app_root}"/obj
  local -r last_target_sdk_stamp_filepath="${stamp_dir}"/.target_sdk.stamp
  mkdir -p "${stamp_dir}"
  echo "${last_target_sdk_stamp_filepath}"
}

normalize_mnemonic() {
  local -r target_sdk_mnemonic="${1:?'missing required arg 1: `target_sdk_mnemonic`'}"
  local -r fail_unimplemented="${2:?'missing required arg 2: `fail_unimplemented`'}"
  local -r l_target_sdk_mnemonic="$(tr '[:upper:]' '[:lower:]' <<<"$target_sdk_mnemonic")"
  local normalized_target_sdk_mnemonic=
  case "$l_target_sdk_mnemonic" in
    s|x|sp|stax)
      normalized_target_sdk_mnemonic="$l_target_sdk_mnemonic"
      ;;
    "")
      ;;
    *)
      if $fail_unimplemented; then
        echo "unimplemented sdk mnemonic: \`$l_target_sdk_mnemonic\`" 1>&2
        exit 1
      fi
      ;;
  esac
  echo "$normalized_target_sdk_mnemonic"
}

read_last_target_sdk_mnemonic() {
  local -r app_root="${1:?'missing required arg 1: `app_root`'}"
  local -r target_sdk_stamp_filepath="$(get_last_target_sdk_stamp_filepath "$app_root")"
  local last_target_sdk_mnemonic=
  if [[ -r "$target_sdk_stamp_filepath" ]]; then
    last_target_sdk_mnemonic="$(normalize_mnemonic "$(<"$target_sdk_stamp_filepath")" true)"
  fi
  echo "$last_target_sdk_mnemonic"
}

write_last_target_sdk_mnemonic() {
  local -r app_root="${1:?'missing required arg 1: `app_root`'}"
  local -r last_target_sdk_mnemonic="${2:?'missing required arg 2: `last_target_sdk_mnemonic`'}"
  local -r target_sdk_stamp_filepath="$(get_last_target_sdk_stamp_filepath "$app_root")"
  if [[ ! -e "$target_sdk_stamp_filepath" ]]; then
    echo "$last_target_sdk_mnemonic" > "$target_sdk_stamp_filepath"
  else
    echo "failed to write target sdk mnemonic. stamp file already exists: \`$target_sdk_stamp_filepath\`" 1>&2
    exit 1
  fi
}
