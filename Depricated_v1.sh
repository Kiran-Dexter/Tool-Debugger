#!/usr/bin/env bash
set -euo pipefail

PYXIS_URL="${PYXIS_URL:-https://catalog.redhat.com/api/containers/v1}"
UBI_REPO_REGEX="${UBI_REPO_REGEX:-^ubi[0-9]+/}"
PAGE_SIZE="${PAGE_SIZE:-200}"
FORMAT="${FORMAT:-json}"     # json | txt
OUTFILE="${OUTFILE:-deprecated_ubi_repos.${FORMAT}}"
API_KEY="${API_KEY:-}"       # optional

FILTER="release_categories==Deprecated;repository=iregex=\"${UBI_REPO_REGEX}\""

curl_pyxis() {
  local url="$1"; shift
  if [[ -n "${API_KEY}" ]]; then
    curl -sS -H "X-API-KEY: ${API_KEY}" "$url" "$@"
  else
    curl -sS "$url" "$@"
  fi
}

get_page() {
  local page="$1"
  local url="${PYXIS_URL}/repositories"

  local tmp code body
  tmp="$(mktemp)"
  code="$(
    curl_pyxis "$url" -G \
      --data-urlencode "filter=${FILTER}" \
      --data-urlencode "page_size=${PAGE_SIZE}" \
      --data-urlencode "page=${page}" \
      -o "$tmp" -w "%{http_code}"
  )"
  body="$(cat "$tmp")"
  rm -f "$tmp"

  if [[ "$code" != "200" ]]; then
    echo "ERROR: Pyxis returned HTTP $code" >&2
    echo "Filter: $FILTER" >&2
    echo "Body:" >&2
    echo "$body" >&2
    exit 1
  fi
  printf '%s' "$body"
}

acc="$(mktemp)"
echo "[]" > "$acc"

page=0
while true; do
  resp="$(get_page "$page")"
  count="$(jq '.data | length' <<<"$resp")"
  [[ "$count" -eq 0 ]] && break

  jq -s '.[0] + .[1].data' "$acc" <(printf '%s' "$resp") > "${acc}.new"
  mv "${acc}.new" "$acc"
  page=$((page + 1))
done

if [[ "$FORMAT" == "json" ]]; then
  jq 'map({
        repository: (.repository // null),
        registry: (.registry // null),
        release_categories: (.release_categories // []),
        replaced_by: (.replaced_by_repository_name // null),
        eol_date: (.eol_date // null),
        published: (.published // null),
        last_update_date: (.last_update_date // null),
        creation_date: (.creation_date // null)
      })' "$acc" > "$OUTFILE"
else
  {
    echo -e "registry\trepository\trelease_categories\treplaced_by\teol_date\tpublished\tlast_update_date"
    jq -r '.[] | [
      (.registry // "-"),
      (.repository // "-"),
      ((.release_categories // []) | join(",")),
      (.replaced_by_repository_name // "-"),
      (.eol_date // "-"),
      ((.published // false) | tostring),
      (.last_update_date // "-")
    ] | @tsv' "$acc"
  } > "$OUTFILE"
fi

rm -f "$acc"
echo "Done -> $OUTFILE"
