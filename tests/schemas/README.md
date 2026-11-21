# Schemas used by the tests

- `sarif-schema-2.1.0.json`: the official JSON schema for SARIF 2.1.0 (errata 01), unmodified,
  from the OASIS SARIF Technical Committee:
  https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json.
  It's kept here so the tests can validate SARIF output offline.

The CycloneDX 1.6 schema used for CBOM validation comes with the `cyclonedx-python-lib` package.
