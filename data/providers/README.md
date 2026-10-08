# Provider price data

Machine-readable price and capability profiles for storage providers. They feed the cost estimates and the provider comparison, so they must be accurate and traceable.

| File | Purpose |
| --- | --- |
| `schema.json` | JSON Schema (draft 2020-12) every profile must satisfy |
| `aws-s3.json` | Amazon S3, region eu-central-1 (Frankfurt) |
| `scaleway-object-storage.json` | Scaleway Object Storage, region fr-par (Paris) |
| `hetzner-storage-box.json` | Hetzner Storage Box (prices not yet verified, see below) |

## Rules

1. **No price without a source and a date.** Every numeric value carries `source_url` (an `https://` URL of the official page or machine-readable price list) and `last_verified` (ISO date, `YYYY-MM-DD`, the day a person or tool actually read the value there). The schema rejects a number without both.
2. **Unknown means `null` plus a note.** If a value cannot be verified from an official source, set `"value": null` and explain in `note` why. Never fill a gap from memory, from a third-party listing or from an estimate. A `null` is a statement that the value is unknown, not that it is zero.
3. **Use official sources first**: the provider's own pricing page, price-list API or documentation. State the exact item (page section, usage type, SKU) in `note` so the next person can re-check it.
4. **Warn when older than 90 days.** `scripts/data/validate-providers.sh` prints a warning for every `last_verified` older than 90 days. Re-verify before relying on the number, then update the value and the date together.
5. **Say what a profile covers.** Prices are only valid for the regions listed in `applies_to_regions`. Do not extend a price to other regions without verifying them.
6. **One currency per profile**, in `currency`, as the provider lists it. Do not convert. State whether tax is included in `prices_include_tax` (`null` if unknown).
7. **Absence is not zero.** If a price list simply has no line for a fee, record `null` with a note (or `0` only when the source says the item is free or included).
8. **Do not copy prices elsewhere.** Planning documents link to these files instead of repeating numbers.

## Units

- Storage: price per GB-month, as the provider bills it. `storage_price_per_gb_month` is a list of volume bands (`from_gb`, `up_to_gb`; the last band has `up_to_gb: null`). Providers with a flat plan use `pricing_model: "fixed_plan"` and `plans`.
- Requests: price per 1000 requests. If the provider lists a price per 10,000 requests, divide and say so in `note`.
- Egress: price per GB after the free allowance (`free_allowance_gb_per_month`), by volume band.
- Retrieval: price per GB for cold classes, with the typical delay as quoted by the provider (`typical_delay`).
- `minimum_storage_duration_days`, `minimum_billable_object_size_kb`, `per_object_overhead_kb`: as published; early deletion is normally billed pro rata for the remaining days.
- Other fields: `protocols` (`s3`, `sftp`, `webdav`, `rclone` and a few more), `regions` (code, city, ISO country), `object_lock` (immutability support).

## Validating

```bash
scripts/data/validate-providers.sh                 # all profiles
scripts/data/validate-providers.sh data/providers/aws-s3.json
scripts/data/validate-providers.sh --max-age-days 30 --fail-on-stale
```

The script uses the first validator it finds: `check-jsonschema`, `ajv` (with `ajv-formats`) or Python 3 with the `jsonschema` package, and prints install instructions if none is available. Exit codes: 0 valid, 1 invalid (or stale with `--fail-on-stale`), 2 usage error or no validator.

## Adding or updating a provider

1. Copy the closest existing profile and adjust it.
2. Read each value from an official source on the day you record it; write the source and date next to it.
3. Run the validator. Fix errors; read the age warnings.
4. In the pull request, list what you could not verify.

## Known gaps

- `hetzner-storage-box.json`: the monthly plan prices are `null`. The official product page renders prices with client-side scripts and no official static source could be read. Fill them in from the product page and verify before using this profile in estimates.
- Request prices for archive classes (LIST in particular), per-request retrieval fees and the cold-class delay for bulk retrievals are modelled only where verified; see the notes in each profile.
