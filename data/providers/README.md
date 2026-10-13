# Provider price data

Machine-readable price and capability profiles for storage providers. They feed the cost estimates and the provider comparison, so they must be accurate and traceable.

| File | Purpose |
| --- | --- |
| `schema.json` | JSON Schema (draft 2020-12) every profile must satisfy |
| `aws-s3.json` | Amazon S3 (USD); prices for eu-central-1 Frankfurt and S3 Standard in eu-north-1 Stockholm |
| `backblaze-b2.json` | Backblaze B2 (USD) |
| `cleura-object-storage.json` | Cleura Public Cloud Object Storage (EUR), Karlskrona, Stockholm, Frankfurt |
| `cloudflare-r2.json` | Cloudflare R2 (USD), Standard and Infrequent Access |
| `contabo-object-storage.json` | Contabo Object Storage (EUR); prices unknown, see gaps |
| `digitalocean-spaces.json` | DigitalOcean Spaces (USD), subscription plus overage, Cold Storage |
| `exoscale-sos.json` | Exoscale Simple Object Storage (EUR) |
| `filebase.json` | Filebase (USD), Free and Pro plans |
| `google-cloud-storage.json` | Google Cloud Storage through its S3-compatible XML API (USD), europe-north1, europe-west1, europe-west4 |
| `hetzner-object-storage.json` | Hetzner Object Storage (EUR), base price with included storage and egress |
| `hetzner-storage-box.json` | Hetzner Storage Box (not S3; prices not yet verified, see below) |
| `idrive-e2.json` | IDrive e2 (USD) |
| `impossible-cloud.json` | Impossible Cloud (EUR), EU regions |
| `ionos-object-storage.json` | IONOS Cloud Object Storage (EUR), EU regions |
| `linode-object-storage.json` | Akamai Cloud (Linode) Object Storage (USD), subscription plus overage |
| `minio.json` | MinIO, self-hosted: no prices, endpoint hint only |
| `ovhcloud-object-storage.json` | OVHcloud Object Storage (EUR), 1-AZ and 3-AZ classes, archive classes |
| `safespring-storage.json` | Safespring Storage (EUR), Oslo and Stockholm |
| `scaleway-object-storage.json` | Scaleway Object Storage (EUR), Paris, Amsterdam, Warsaw, Milan |
| `stackit-object-storage.json` | STACKIT Object Storage (EUR), eu01 and eu02 |
| `storj.json` | Storj (USD) |
| `synology-c2-object-storage.json` | Synology C2 Object Storage (EUR), per-TB plans |
| `tigris.json` | Tigris (USD) |
| `upcloud-object-storage.json` | UpCloud Managed Object Storage (EUR); storage price unknown, see gaps |
| `wasabi.json` | Wasabi (USD) |

The profiles are embedded in the app at build time (`crates/varsto-core/src/providers.rs`; a test fails when a file here is not embedded or breaks the rules below). The Add storage form lists every profile with S3 endpoints: choosing a provider and region fills in the endpoint, region and URL style, shows the headline prices with their date and source, and a "Compare providers" table lists them side by side (`GET /api/providers`). A storage whose endpoint matches a profile gets that profile's prices as defaults for its cost estimates.

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
- Subscriptions: a plan fee that includes the first gigabytes is a `plans` entry; the included gigabytes are a first band priced `0` and the overage the next band. The app shows and estimates with the overage band.
- A class priced differently in another region is a separate class with id `<class id>-<region>` (for example `standard-eu-north-1`); the app picks it for that region.
- S3 access: `s3_endpoints` lists, per region, the endpoint URL (placeholders in braces, such as `{account_id}`, are for the user to fill in), the signing `region`, `price_region` when the prices of a different `regions` code apply (a provider that signs every endpoint as `us-east-1`), and `path_style` (`true`: bucket in the path; `false`: virtual-hosted style), each with its source.
- `default_storage_class` names the class whose prices are the headline; `free_tier` and `egress_fair_use` are text facts (null with a note when none is stated); `signup_url`, `pricing_url` and `tax_note` are for people. `kind: "self_hosted"` marks software you run yourself: such a profile has endpoint hints and no prices.
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

Checked 2026-10-13. Each null in a profile says why in its note; the larger gaps:

- `hetzner-storage-box.json`: the monthly plan prices are `null`. The official product page renders prices with client-side scripts and no official static source could be read.
- `upcloud-object-storage.json`: the storage price and request fees are `null`; the pricing page refused automated reading and the price API needs an account. Read them in a browser.
- `contabo-object-storage.json`: the product page now redirects elsewhere and no official price could be found; nearly every price is `null`. Confirm the product is still sold.
- `safespring-storage.json`: storage prices are listed per TB without saying how large a TB is, so the per-GB values are `null` (the per-TB figures are in the notes).
- `hetzner-object-storage.json`: storage above the included 1 TB is published only per TB-hour, so it is in the notes, not as a per-GB-month band. `exoscale-sos.json`: volume tiers 2 and 3 are published only per GiB-hour and are `null`.
- `stackit-object-storage.json`: request and egress prices are `null` (no price item found).
- Units: OVHcloud and Exoscale publish per GiB; their values are divided by 1.073741824 to per GB, with the original figure in the note. Backblaze B2, Storj, Wasabi, Impossible Cloud and IONOS publish per TB; each note says which TB the provider uses.
- Addressing style is not documented for Impossible Cloud and Synology C2; `path_style: true` is a cautious choice there. Backblaze B2 documents only `us-east-005`; the other regions are templates (`eu-central-{nnn}`) that the user completes from the bucket details. Storj does not document a signing region (`us1` is used). Linode signs with `us-east-1` on every endpoint (`price_region` maps the prices); Contabo signs with `default`.
- Request prices for archive classes (LIST in particular), per-request retrieval fees and the cold-class delay for bulk retrievals are modelled only where verified; see the notes in each profile.
- Checked and left out because no official price could be read: Vultr (pages refuse automated reading), Infomaniak (prices rendered by scripts), Elastx, Open Telekom Cloud and Leaseweb.
