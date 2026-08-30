<p align="center">
  <a href="https://query.farm">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://query.farm/media-kit/logo/wordmark-dark.svg">
      <img alt="Query.Farm" src="https://query.farm/media-kit/logo/wordmark-light.svg" height="64">
    </picture>
  </a>
</p>

# DuckDB HTTP Server Extension

[![DuckDB](https://img.shields.io/badge/DuckDB-community_extension-fdf1e0?logo=duckdb&logoColor=fff000)](https://duckdb.org/community_extensions/extensions/httpserver.html)
[![v1.5 build](https://github.com/Query-farm/httpserver/actions/workflows/MainDistributionPipeline.yml/badge.svg?branch=v1.5)](https://github.com/Query-farm/httpserver/actions/workflows/MainDistributionPipeline.yml?query=branch%3Av1.5)

This extension transforms **DuckDB** instances into tiny multi-player **HTTP OLAP API** services. Supports Authentication (Basic Auth or X-Token) and includes the *play* SQL user interface.

## Documentation

Full documentation, including installation, usage, the function reference, and cookbook examples, is available at:

**[https://query.farm/products/extensions/httpserver](https://query.farm/products/extensions/httpserver)**

## Installation

```sql
INSTALL httpserver FROM community;
LOAD httpserver;
```

## Development

For instructions on building the extension from source and running its tests, see [BUILDING.md](BUILDING.md).
