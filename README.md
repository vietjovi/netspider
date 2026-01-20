# netspider

A fast web spider tool written in Python for discovering URLs, subdomains, and resources from websites.

## Features

### Core Functionality
- **Web Crawling**: Automatically crawls websites and discovers URLs
- **File Analysis**: Extracts links from JavaScript, CSS, HTML, and text files
- **Subdomain Discovery**: Finds subdomains from crawled content
- **Sitemap & Robots**: Automatically parses sitemap.xml and robots.txt (always enabled)
- **Concurrent Processing**: Multi-threaded crawling for faster results

### Passive Information Gathering
Fetches URLs from multiple passive sources (always enabled):
- **Wayback Machine**: Historical URLs from Internet Archive
- **Common Crawl**: URLs from Common Crawl datasets
- **AlienVault OTX**: Threat intelligence URLs
- **URLScan.io**: Scan results and discovered URLs
- **VirusTotal**: URLs from VirusTotal (requires `VT_API_KEY`)
- **GrayHatWarfare**: Public S3 bucket discovery (optional `GRAYHATWARFARE_TOKEN`)
- **Shodan**: URLs from Shodan search (requires `SHODAN_API_KEY`)
- **Censys**: URLs from Censys search (requires `CENSYS_API_ID` and `CENSYS_API_SECRET`)

### Output & Analysis
- **Clean Output Mode**: Clean output with type tags, removes duplicates, and displays summary
- **HTTP Status Checking**: Optional HTTP status code verification
- **AWS Resource Detection**: Automatically detects AWS S3 buckets and CloudFront URLs

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Docker Installation

```bash
# Build the Docker image
docker build -t netspider .

# Verify installation
docker run --rm netspider --version
```

## Usage

### Docker Usage

```bash
# Basic crawl
docker run --rm netspider -s example.com

# With output directory (mount volume)
docker run --rm -v $(pwd)/output:/app/output netspider -s example.com -o /app/output

# With environment variables (e.g., VirusTotal API key)
docker run --rm -e VT_API_KEY=your_key netspider -s example.com

# With custom options
docker run --rm netspider -s example.com -d 2 -c 10 -q
```

### Basic Usage

```bash
# Crawl a single site
python netspider.py -s example.com

# Crawl with custom depth and concurrency
python netspider.py -s example.com -d 2 -c 10

# Save output to file
python netspider.py -s example.com -o output/

# Clean mode (Recommend)
python netspider.py -s example.com --clean
```

### Options

#### Required Arguments
- `-s, --site`: Site to crawl (required, e.g., `example.com` or `https://example.com`)

#### Input/Output Options
- `-S, --sites`: File containing list of sites to crawl (one per line)
- `-o, --output`: Output folder to save results
- `-q, --quiet`: Suppress output, only show URLs
- `--json`: JSON output format
- `--clean`: **Recommended** - Clean output with type tags, removes duplicates, and displays summary

#### Crawling Options
- `-d, --depth`: Maximum crawl depth (default: `1`, use `0` for infinite)
- `-c, --concurrent`: Number of concurrent requests (default: `5`)
- `-t, --threads`: Number of threads for parallel site processing (default: `1`)
- `--find-url-from`: Find URLs from files with specified extensions (comma-separated, e.g., `js,css,txt,html`, default: `js`)

#### Filtering Options
- `--exclude`: Exclude URLs matching regex pattern
- `--include`: Only include URLs matching regex pattern
- `-w, --include-subs`: Include subdomains from passive sources (enabled by default)
- `--no-subs`: Disable including subdomains from passive sources

#### Advanced Options
- `--check`: Check HTTP status code of discovered URLs
- `--wbm-limit`: Wayback Machine result limit (default: `100000`)
- `-H, --header`: Add custom HTTP header (can be used multiple times)
- `--cookie`: Set cookies (format: `key1=value1; key2=value2`)
- `-p, --proxy`: Use proxy (format: `http://127.0.0.1:8080`)
- `-k, --delay`: Delay before creating a new request (seconds)
- `-K, --random-delay`: Random delay added to delay (seconds)
- `-m, --timeout`: Request timeout (seconds, default: `10`)
- `-l, --length`: Show response length in output
- `-v, --verbose`: Verbose output
- `--debug`: Enable debug mode

### Environment Variables

- `VT_API_KEY`: VirusTotal API key (optional, for VirusTotal source)
- `SHODAN_API_KEY`: Shodan API key (optional, for Shodan source)
- `CENSYS_API_ID`: Censys API ID (optional, for Censys source)
- `CENSYS_API_SECRET`: Censys API secret (optional, for Censys source)
- `GRAYHATWARFARE_TOKEN`: GrayHatWarfare API token (optional, for GrayHatWarfare source)

### Examples

#### Basic Usage

```bash
# Simple crawl (recommended: use --clean)
python netspider.py -s example.com --clean

# Crawl with custom depth and concurrency
python netspider.py -s example.com -d 2 -c 10 --clean

# Save output to file
python netspider.py -s example.com -o output/ --clean
```

#### File Type Analysis

```bash
# Find URLs from JavaScript files only (default)
python netspider.py -s example.com --find-url-from js --clean

# Find URLs from multiple file types
python netspider.py -s example.com --find-url-from js,css,txt,html --clean

# Find URLs from CSS and HTML files
python netspider.py -s example.com --find-url-from css,html --clean
```

#### Advanced Usage

```bash
# Check HTTP status codes
python netspider.py -s example.com --check --clean

# Deep crawl with high concurrency
python netspider.py -s example.com -d 3 -c 20 --clean

# Multiple sites from file
python netspider.py -S sites.txt -o results/ --clean

# With custom headers
python netspider.py -s example.com -H "Authorization: Bearer token" --clean

# JSON output format
python netspider.py -s example.com --json

# Using proxy
python netspider.py -s example.com -p http://127.0.0.1:8080 --clean
```

#### Docker Examples

```bash
# Basic crawl with Docker
docker run --rm netspider -s example.com --clean

# With output directory (mount volume)
docker run --rm -v $(pwd)/output:/app/output netspider -s example.com -o /app/output --clean

# With environment variables (API keys)
docker run --rm -e VT_API_KEY=your_key netspider -s example.com --clean
```

## Output Formats

### Clean Output Mode (`--clean`) - Recommended

The `--clean` option provides the cleanest, most parseable output with type tags and a summary:

**Output Format:**
```
[URL] https://example.com/page
[SUBDOMAIN] http://sub.example.com
[JAVASCRIPT] https://example.com/js/app.js
[CSS] https://example.com/css/style.css
[HTML] https://example.com/page.html
[AWS S3] https://bucket.s3.amazonaws.com/file
[AWS CloudFront] https://d123.cloudfront.net/file
```

**Summary (shown at the end):**
```
============================================================
Crawl Summary
============================================================
URLs discovered: 150
Subdomains found: 5
JavaScript files: 20
Forms found: 2
AWS S3 Buckets: 1
AWS CloudFront URLs: 3
Wayback machine: 50 Urls
OTX: 10 Urls
============================================================
```

**Type Tags:**
- `[URL]` - Regular URLs
- `[SUBDOMAIN]` - Discovered subdomains
- `[JAVASCRIPT]` - JavaScript files
- `[CSS]` - CSS stylesheets
- `[HTML]` - HTML pages
- `[TEXT]` - Text files
- `[FORM]` - HTML forms
- `[AWS S3]` - AWS S3 buckets
- `[AWS CloudFront]` - CloudFront URLs

### Standard Output Format

Without `--clean`, output includes source information:

```
[WEB] https://example.com/page [200]
[WEB] [SUBDOMAINS] http://sub.example.com
[WEB] [JAVASCRIPT] https://example.com/js/app.js
[Wayback Machine] https://example.com/old-page
[OTX] https://example.com/api
```

### Other Output Modes

- **`-q, --quiet`**: Only URLs (no tags or formatting)
- **`--json`**: JSON format output (structured data)

## License

See LICENSE file for details.

## Author

@vietjovi
