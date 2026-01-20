#!/usr/bin/env python3
"""
netspider - A web spider tool written in Python
author: @vietjovi
"""

import argparse
import json
import os
import re
import sys
import time
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, parse_qsl, urlencode, unquote
from urllib.robotparser import RobotFileParser
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# Version info
VERSION = "v1.0.0"
AUTHOR = "@vietjovi"

# Default blacklist regex
DEFAULT_BLACKLIST = r'(?i)\.(png|apng|bmp|gif|ico|cur|jpg|jpeg|jfif|pjp|pjpeg|svg|tif|tiff|webp|xbm|3gp|aac|flac|mpg|mpeg|mp3|mp4|m4a|m4v|m4p|oga|ogg|ogv|mov|wav|webm|eot|woff|woff2|ttf|otf|css)(?:\?|#|$)'

# Link finder regex
LINKFINDER_REGEX = re.compile(r'(?:"|\')(((?:[a-zA-Z]{1,10}://|//)[^"\'/]{1,}\.[a-zA-Z]{2,}[^"\']{0,})|((?:/|\.\./|\./)[^"\'><,;| *()(%%$^/\\\[\]][^"\'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|\']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|\']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|\']{0,}|)))(?:"|\')')

# Subdomain regex
SUBRE = r'(?i)(([a-zA-Z0-9]{1}|[_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+'

# AWS S3 regex
AWSS3_REGEX = re.compile(r'(?i)[a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.s3-[a-z0-9-]\.amazonaws\.com|[a-z0-9.-]+\.s3-website[.-](eu|ap|us|ca|sa|cn)|//s3\.amazonaws\.com/[a-z0-9._-]+|//s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+')

# Name strip regex
NAME_STRIP_RE = re.compile(r'(?i)^((20)|(25)|(2b)|(2f)|(3d)|(3a)|(40))+')

# User agents
WEB_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
]

MOBILE_USER_AGENTS = [
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
]


class StringSet:
    """Thread-safe string set for deduplication"""
    def __init__(self):
        self._set = set()
        self._lock = threading.Lock()
    
    def duplicate(self, s):
        """Check if string exists, add if not. Returns True if duplicate."""
        with self._lock:
            s_lower = s.lower()
            if s_lower in self._set:
                return True
            self._set.add(s_lower)
            return False
    
    def has(self, s):
        """Check if string exists without adding"""
        with self._lock:
            return s.lower() in self._set


class Output:
    """Thread-safe file output"""
    def __init__(self, folder, filename):
        self.folder = folder
        self.filename = filename
        self.filepath = os.path.join(folder, filename)
        self._lock = threading.Lock()
        self._file = open(self.filepath, 'a', encoding='utf-8')
    
    def write(self, msg):
        with self._lock:
            self._file.write(msg + '\n')
            self._file.flush()
    
    def close(self):
        with self._lock:
            self._file.close()


class Logger:
    """Simple logger"""
    def __init__(self, debug=False, verbose=False, quiet=False, clean=False):
        self._debug_enabled = debug
        self._verbose_enabled = verbose
        self.quiet = quiet
        self.clean = clean
    
    def _log(self, level, msg):
        if self.clean and level != 'error':
            # In clean mode, suppress all output except errors
            return
        if self.quiet and level != 'error':
            return
        if not self._debug_enabled and not self._verbose_enabled and level == 'debug':
            return
        prefix = f"[{level.upper()}]" if level != 'info' else ""
        print(f"{prefix} {msg}", file=sys.stderr if level == 'error' else sys.stdout)
    
    def info(self, msg):
        self._log('info', msg)
    
    def debug(self, msg):
        self._log('debug', msg)
    
    def warn(self, msg):
        self._log('warn', msg)
    
    def error(self, msg):
        self._log('error', msg)


def get_domain(url):
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return ""
        # Simple domain extraction (can be improved with tldextract)
        parts = hostname.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return hostname
    except:
        return ""


def fix_url(main_site, next_loc):
    """Fix relative URLs to absolute"""
    try:
        return urljoin(main_site, next_loc)
    except:
        return ""


def get_ext_type(url):
    """Get file extension from URL"""
    try:
        parsed = urlparse(url)
        path = parsed.path
        if '.' in path:
            return os.path.splitext(path)[1]
        return ""
    except:
        return ""


def decode_chars(s):
    """Decode URL and JSON encoded characters"""
    try:
        s = unquote(s)
    except:
        pass
    s = s.replace('\\u002f', '/')
    s = s.replace('\\u0026', '&')
    return s


def filter_newlines(s):
    """Filter newlines and tabs"""
    return re.sub(r'[\t\r\n]+', ' ', s.strip())


def clean_subdomain(s):
    """Clean subdomain string"""
    s = s.strip().lower()
    s = s.lstrip('*.')
    s = clean_name(s)
    return s


def clean_name(name):
    """Clean name string"""
    while True:
        match = NAME_STRIP_RE.search(name)
        if match:
            name = name[match.end():]
        else:
            break
    name = name.strip('-')
    if len(name) > 1 and name[0] == '.':
        name = name[1:]
    return name


def unique(lst):
    """Remove duplicates while preserving order"""
    return list(OrderedDict.fromkeys(lst))


def get_subdomains(source, domain):
    """Extract subdomains from source"""
    subs = []
    pattern = SUBRE + re.escape(domain)
    regex = re.compile(pattern)
    for match in regex.finditer(source):
        sub = clean_subdomain(match.group(0))
        if sub and sub != domain:
            subs.append(sub)
    return unique(subs)


def get_aws_s3(source):
    """Extract AWS S3 buckets from source"""
    aws = []
    for match in AWSS3_REGEX.finditer(source):
        aws.append(decode_chars(match.group(0)))
    return unique(aws)


def link_finder(source):
    """Extract links from JavaScript source"""
    links = []
    if len(source) > 1000000:
        source = source.replace(';', ';\r\n')
        source = source.replace(',', ',\r\n')
    source = decode_chars(source)
    
    for match in LINKFINDER_REGEX.finditer(source):
        match_group = filter_newlines(match.group(1))
        if match_group:
            links.append(match_group)
    
    return unique(links)


def in_scope(url_str, url_filters):
    """Check if URL matches any filter"""
    if not url_filters:
        return True
    for pattern in url_filters:
        if pattern.search(url_str):
            return True
    return False


def reading_lines(filename):
    """Read lines from file"""
    result = []
    if filename.startswith('~'):
        filename = os.path.expanduser(filename)
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    result.append(line)
    except:
        pass
    return result


def get_random_user_agent(ua_type):
    """Get random user agent"""
    import random
    if ua_type == 'mobi':
        return random.choice(MOBILE_USER_AGENTS)
    elif ua_type == 'web':
        return random.choice(WEB_USER_AGENTS)
    else:
        return ua_type


class Crawler:
    """Main crawler class"""
    def __init__(self, site, args, logger):
        # Add scheme if missing
        if not site.startswith(('http://', 'https://')):
            site = 'https://' + site
        self.site = site
        self.args = args
        self.logger = logger
        self.domain = get_domain(site)
        self.input_url = site
        
        # Parse find_url_from extensions
        if args.find_url_from:
            self.find_url_extensions = [ext.strip().lower() for ext in args.find_url_from.split(',') if ext.strip()]
            # Normalize extensions (remove leading dot if present, add dot for comparison)
            self.find_url_extensions = [ext.lstrip('.') for ext in self.find_url_extensions]
        else:
            self.find_url_extensions = ['js']  # Default to js
        
        # Initialize sets
        self.sub_set = StringSet()
        self.aws_set = StringSet()
        self.js_set = StringSet()
        self.url_set = StringSet()
        self.form_set = StringSet()
        
        # Track printed URLs to avoid duplicates
        self.printed_urls = set()
        self.printed_lock = threading.Lock()
        
        # Track URL sources for subdomain attribution
        self.url_sources = {}  # url -> source
        self.url_sources_lock = threading.Lock()
        
        # Statistics tracking
        self.stats = {
            'urls': 0,
            'subdomains': set(),  # Track unique subdomains
            'javascript': 0,
            'forms': 0,
            'aws_s3': 0,
            'aws_cloudfront': 0,
            'passive': {}
        }
        self.stats_lock = threading.Lock()
        
        # Initialize output
        self.output = None
        if args.output:
            filename = site.replace('://', '_').replace('/', '_').replace('.', '_')
            if filename.endswith('_'):
                filename = filename[:-1]
            if not filename:
                filename = 'output'
            self.output = Output(args.output, filename)
        
        # Initialize session
        self.session = requests.Session()
        self._setup_session()
        
        # URL filters
        self.url_filters = []
        self.disallowed_filters = []
        self._setup_filters()
        
        # Visited URLs tracking
        self.visited = set()
        self.visited_lock = threading.Lock()
        
        # URL queue for concurrent processing
        self.url_queue = []
        self.queue_lock = threading.Lock()
        # Create thread pool executor for concurrent requests
        self.executor = ThreadPoolExecutor(max_workers=args.concurrent)
        
    
    def _setup_session(self):
        """Setup HTTP session"""
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # SSL verification
        self.session.verify = False
        
        # Timeout
        self.timeout = self.args.timeout if self.args.timeout > 0 else 10
        
        # Proxy
        if self.args.proxy:
            self.session.proxies = {
                'http': self.args.proxy,
                'https': self.args.proxy
            }
        
        # Headers and cookies
        headers = {}
        cookies_str = ""
        
        # Add custom headers
        if self.args.header:
            for h in self.args.header:
                if ':' in h:
                    key, value = h.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # Add cookies
        if self.args.cookie:
            cookies_str = self.args.cookie
        
        # User agent
        ua = get_random_user_agent(self.args.user_agent)
        headers['User-Agent'] = ua
        
        # Set headers
        self.session.headers.update(headers)
        
        # Set cookies
        if cookies_str:
            for cookie in cookies_str.split(';'):
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    self.session.cookies.set(key.strip(), value.strip())
    
    def _setup_filters(self):
        """Setup URL filters"""
        # Default blacklist
        self.disallowed_filters.append(re.compile(DEFAULT_BLACKLIST))
        
        # Custom exclude filter
        if self.args.exclude:
            self.disallowed_filters.append(re.compile(self.args.exclude))
        
        # Include filter
        if self.args.include:
            self.url_filters.append(re.compile(self.args.include))
        else:
            # Always include subdomains by default
            hostname = urlparse(self.site).hostname
            if hostname:
                self.url_filters.append(re.compile(re.escape(hostname)))
    
    def _should_visit(self, url):
        """Check if URL should be visited"""
        # Check if already visited
        with self.visited_lock:
            if url in self.visited:
                return False
        
        # Check disallowed filters
        for pattern in self.disallowed_filters:
            if pattern.search(url):
                return False
        
        # Check URL filters
        if self.url_filters:
            if not in_scope(url, self.url_filters):
                return False
        
        # Mark as visited
        with self.visited_lock:
            self.visited.add(url)
        
        return True
    
    def _check_status_code(self, url):
        """Check HTTP status code for a URL"""
        try:
            # Use HEAD request first for efficiency
            response = self.session.head(url, allow_redirects=True, timeout=self.args.timeout)
            status_code = response.status_code
        except (requests.exceptions.RequestException, requests.exceptions.Timeout, 
                requests.exceptions.ConnectionError):
            try:
                # Fallback to GET if HEAD fails
                response = self.session.get(url, allow_redirects=True, timeout=self.args.timeout, stream=True)
                status_code = response.status_code
            except (requests.exceptions.RequestException, requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError):
                status_code = None
        return status_code
    
    def _output(self, output_type, source, url, status_code=None, length=None, from_url=None):
        """Output result"""
        # Check for duplicates (normalize URL for comparison)
        url_normalized = url.lower().strip()
        with self.printed_lock:
            if url_normalized in self.printed_urls:
                return  # Skip duplicate
            self.printed_urls.add(url_normalized)
        
        # Check status code if --check is enabled and status_code is not already provided
        if self.args.check and status_code is None:
            # Only check status codes for URLs (not for forms, javascript files, etc.)
            if output_type in ['url', 'href', 'sitemap', 'robots', 'linkfinder', 'subdomain', 'subdomains'] or output_type.startswith('passive-'):
                status_code = self._check_status_code(url)
        
        # Format output type for better readability
        type_display = output_type.upper().replace('-', '_')
        
        # Map source to readable format
        source_map = {
            'body': 'WEB',
            'javascript': 'WEB',
            'linkfinder': 'WEB',
            'wayback': 'Wayback Machine',
            'commoncrawl': 'Common Crawl',
            'otx': 'OTX',
            'urlscan': 'URLScan',
            'virustotal': 'VirusTotal',
            'grayhatwarfare': 'GrayHatWarfare',
            'shodan': 'Shodan',
            'censys': 'Censys',
            'sitemap': 'Sitemap',
            'robots': 'Robots',
        }
        
        # Get readable source name
        source_display = source_map.get(source, source.upper())
        
        # For passive sources, use the provider name from output_type
        if output_type.startswith('passive-'):
            provider = output_type.replace('passive-', '')
            source_display = source_map.get(provider, provider.upper())
        
        # Update statistics
        with self.stats_lock:
            # Check for AWS S3 and CloudFront in ALL URLs (regardless of output_type)
            url_lower = url.lower()
            if 's3.amazonaws.com' in url_lower:
                self.stats['aws_s3'] += 1
            elif '.cloudfront.net' in url_lower:
                self.stats['aws_cloudfront'] += 1
            
            # Count all URL types as URLs (url, href, sitemap, robots, passive-*, linkfinder, etc.)
            if output_type in ['url', 'href', 'sitemap', 'robots', 'linkfinder'] or output_type.startswith('passive-'):
                self.stats['urls'] += 1
                # Note: Passive source counts are tracked in process_other_sources() to include duplicates
            elif output_type in ['subdomain', 'subdomains']:
                # Extract domain from URL (remove http:// and https://)
                domain_only = url.replace('http://', '').replace('https://', '').split('/')[0].split('?')[0].strip()
                if domain_only and domain_only != self.domain:
                    self.stats['subdomains'].add(domain_only)
            elif output_type == 'javascript':
                self.stats['javascript'] += 1
            elif output_type in ['form', 'upload-form']:
                self.stats['forms'] += 1
            elif output_type == 'aws-s3':
                self.stats['aws_s3'] += 1
        
        if self.args.json:
            sout = {
                "input": self.input_url,
                "source": source,
                "type": output_type,
                "url": url,
            }
            if status_code is not None:
                sout["status"] = status_code
            if length is not None:
                sout["length"] = length
            if from_url:
                sout["from"] = from_url
            output_format = json.dumps(sout)
        elif self.args.quiet:
            output_format = url
        elif self.args.clean:
            # In clean mode, output with type tags but no source tags
            # Map output_type to clean tag format
            type_tag_map = {
                'url': 'URL',
                'href': 'URL',
                'sitemap': 'URL',
                'robots': 'URL',
                'linkfinder': 'URL',
                'javascript': 'JAVASCRIPT',
                'subdomain': 'SUBDOMAIN',
                'subdomains': 'SUBDOMAIN',
                'form': 'FORM',
                'upload-form': 'FORM',
                'aws-s3': 'AWS S3',
            }
            
            # Handle passive sources - they're just URLs
            if output_type.startswith('passive-'):
                tag = 'URL'
            else:
                tag = type_tag_map.get(output_type, 'URL')
            
            # Check for AWS S3 and CloudFront in URL (highest priority)
            url_lower = url.lower()
            if 's3.amazonaws.com' in url_lower or 's3-website' in url_lower or 's3-' in url_lower and '.amazonaws.com' in url_lower:
                tag = 'AWS S3'
            elif '.cloudfront.net' in url_lower:
                tag = 'AWS CloudFront'
            # Check file extension for better categorization
            elif output_type == 'javascript':
                file_ext = get_ext_type(url).lstrip('.').lower()
                if file_ext == 'css':
                    tag = 'CSS'
                elif file_ext in ['js', 'jsx', 'mjs']:
                    tag = 'JAVASCRIPT'
                elif file_ext in ['txt', 'text']:
                    tag = 'TEXT'
                elif file_ext in ['html', 'htm']:
                    tag = 'HTML'
                # Keep JAVASCRIPT as default for javascript output_type
            
            output_format = f"[{tag}] {url}"
        else:
            # Build readable output format with source
            parts = []
            
            # Add source
            parts.append(f"[{source_display}]")
            
            # Add type for special types (not for regular URLs or passive sources)
            if output_type.startswith('passive-'):
                # Passive sources: just show source, no type
                pass
            elif output_type in ['javascript', 'subdomains', 'subdomain', 'form', 'upload-form', 'aws-s3']:
                # Special types: show both source and type
                parts.append(f"[{type_display}]")
            # For regular URLs (url, href, sitemap, robots, linkfinder), don't show type
            
            if self.args.length and length is not None:
                parts.append(f"[{length:,} bytes]")
            
            if from_url:
                parts.append(f"[from: {from_url[:50]}...]" if len(from_url) > 50 else f"[from: {from_url}]")
            
            # Add URL
            parts.append(url)
            
            # Add status code at the end if available
            if status_code is not None:
                parts.append(f"[{status_code}]")
            
            output_format = " ".join(parts)
        
        if not self.args.quiet or self.args.clean or self.args.json:
            print(output_format)
        
        if self.output:
            self.output.write(output_format)
    
    def _fetch(self, url, allow_redirects=True):
        """Fetch URL with error handling"""
        try:
            if not allow_redirects:
                # Manual redirect handling
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '')
                    if location and self.site in location:
                        return self._fetch(location, allow_redirects=True)
                    return None
                return resp
            else:
                return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            self.logger.debug(f"Error fetching {url}: {e}")
            return None
    
    def _process_response(self, url, response, source="body"):
        """Process HTTP response"""
        if not response:
            return
        
        status_code = response.status_code
        content = response.text
        content_length = len(content)
        
        # Skip certain status codes
        if status_code in [404, 429] or status_code < 100 or status_code >= 500:
            return
        
        # Track URL source for subdomain attribution
        url_normalized = url.lower().strip()
        with self.url_sources_lock:
            if url_normalized not in self.url_sources:
                self.url_sources[url_normalized] = source
        
        # Output URL
        self._output("url", source, url, status_code, content_length)
        
        # Check if in scope
        if in_scope(url, self.url_filters):
            # Find subdomains (pass source for attribution)
            self._find_subdomains(content, source)
            
            # Find AWS S3
            self._find_aws_s3(content)
        
        # Link finder for specified file types
        # Check if the URL's extension matches any of the find_url_from extensions
        url_ext = get_ext_type(url).lstrip('.').lower()
        if url_ext in self.find_url_extensions:
            self._process_linkfinder(url, content)
    
    def _find_subdomains(self, content, source="body"):
        """Find subdomains in content"""
        subs = get_subdomains(content, self.domain)
        for sub in subs:
            if not self.sub_set.duplicate(sub):
                # Use the source where this content came from
                if self.args.json:
                    self._output("subdomain", source, sub)
                elif not self.args.quiet:
                    self._output("subdomains", source, f"http://{sub}")
                    self._output("subdomains", source, f"https://{sub}")
                else:
                    if self.output:
                        self.output.write(f"[subdomains] - http://{sub}")
                        self.output.write(f"[subdomains] - https://{sub}")
    
    def _find_aws_s3(self, content):
        """Find AWS S3 buckets in content"""
        aws = get_aws_s3(content)
        for bucket in aws:
            if not self.aws_set.duplicate(bucket):
                self._output("aws-s3", "body", bucket)
    
    def _process_linkfinder(self, js_url, content):
        """Process linkfinder on JavaScript content"""
        paths = link_finder(content)
        
        try:
            current_path_url = urlparse(js_url)
        except:
            current_path_url = None
        
        for rel_path in paths:
            # Try to rebuild URL
            rebuild_url = ""
            if current_path_url:
                rebuild_url = fix_url(js_url, rel_path)
            else:
                rebuild_url = fix_url(self.site, rel_path)
            
            if not rebuild_url:
                continue
            
            file_ext = get_ext_type(rebuild_url).lstrip('.').lower()
            
            # If it's a file with extension in find_url_from list, feed to linkfinder
            if file_ext in self.find_url_extensions:
                if not self.js_set.duplicate(rebuild_url):
                    self._output("javascript", "javascript", rebuild_url)
                    # Try to get original JS if minified
                    if '.min.js' in rebuild_url:
                        original_js = rebuild_url.replace('.min.js', '.js')
                        if self.executor:
                            self.executor.submit(self._crawl_url, original_js, 0, True)
                        else:
                            self._crawl_url(original_js, 0, True)
                    if self.executor:
                        self.executor.submit(self._crawl_url, rebuild_url, 0, True)
                    else:
                        self._crawl_url(rebuild_url, 0, True)
            else:
                # Regular URL
                if not self.url_set.duplicate(rebuild_url):
                    if self.args.json:
                        self._output("linkfinder", js_url, rebuild_url)
                    elif not self.args.quiet:
                        self._output("linkfinder", js_url, rebuild_url)
                    else:
                        if self.output:
                            self.output.write(f"[linkfinder] - {rebuild_url}")
                    if self.executor:
                        self.executor.submit(self._crawl_url, rebuild_url, 0, False)
                    else:
                        self._crawl_url(rebuild_url, 0, False)
            
            # Also try with main site
            url_with_js_host = fix_url(self.site, rel_path)
            if url_with_js_host and url_with_js_host != rebuild_url:
                file_ext = get_ext_type(url_with_js_host)
                if file_ext in ['.js', '.xml', '.json', '.map']:
                    if not self.js_set.duplicate(url_with_js_host):
                        self._output("linkfinder", js_url, url_with_js_host)
                        if self.executor:
                            self.executor.submit(self._crawl_url, url_with_js_host, 0, True)
                        else:
                            self._crawl_url(url_with_js_host, 0, True)
                else:
                    if not self.url_set.duplicate(url_with_js_host):
                        if not self.args.quiet:
                            self._output("linkfinder", js_url, url_with_js_host)
                        if self.executor:
                            self.executor.submit(self._crawl_url, url_with_js_host, 0, False)
                        else:
                            self._crawl_url(url_with_js_host, 0, False)
    
    def _crawl_url(self, url, depth=0, linkfinder=False, source=None):
        """Crawl a single URL"""
        if not self._should_visit(url):
            return
        
        # Check depth
        if self.args.depth > 0 and depth > self.args.depth:
            return
        
        # Delay
        if self.args.delay > 0:
            time.sleep(self.args.delay)
        if self.args.random_delay > 0:
            import random
            time.sleep(random.uniform(0, self.args.random_delay))
        
        # Fetch URL
        response = self._fetch(url)
        if not response:
            return
        
        # Determine source - use provided source, or check if URL was from passive source
        if source is None:
            url_normalized = url.lower().strip()
            with self.url_sources_lock:
                source = self.url_sources.get(url_normalized, "body")
        
        # If still no source, use default
        if source == "body" and linkfinder:
            source = "linkfinder"
        elif source == "body":
            source = "body"
        
        # Process response
        self._process_response(url, response, source)
        
        # Parse HTML for links
        if not linkfinder and depth < (self.args.depth if self.args.depth > 0 else 999):
            try:
                # Suppress BeautifulSoup warnings (e.g., MarkupResemblesLocatorWarning)
                # This can occur when content doesn't look like HTML but we still want to try parsing it
                with warnings.catch_warnings():
                    warnings.filterwarnings('ignore', category=UserWarning, module='bs4')
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find href links
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    if href:
                        abs_url = fix_url(url, href)
                        if abs_url:
                            if not self.url_set.duplicate(abs_url):
                                self._output("href", "body", abs_url)
                            # Submit to executor for concurrent processing
                            if self.executor:
                                self.executor.submit(self._crawl_url, abs_url, depth + 1, False)
                            else:
                                self._crawl_url(abs_url, depth + 1, False)
                
                # Find forms
                for form in soup.find_all('form', action=True):
                    form_url = url
                    if not self.form_set.duplicate(form_url):
                        self._output("form", "body", form_url)
                
                # Find upload forms
                for input_tag in soup.find_all('input', type='file'):
                    upload_url = url
                    if not self.form_set.duplicate(upload_url):
                        self._output("upload-form", "body", upload_url)
                
                # Find files with specified extensions
                for script in soup.find_all(['script', 'link'], src=True):
                    src = script.get('src')
                    if src:
                        file_url = fix_url(url, src)
                        if file_url:
                            file_ext = get_ext_type(file_url).lstrip('.').lower()
                            # Check if file extension matches any of the find_url_from extensions
                            if file_ext in self.find_url_extensions:
                                if not self.js_set.duplicate(file_url):
                                    self._output("javascript", "body", file_url)
                                    if self.executor:
                                        self.executor.submit(self._crawl_url, file_url, depth + 1, True)
                                    else:
                                        self._crawl_url(file_url, depth + 1, True)
            except Exception as e:
                self.logger.debug(f"Error parsing HTML for {url}: {e}")
    
    def start(self):
        """Start crawling"""
        self.logger.info(f"Start crawling: {self.site}")
        try:
            # Start with initial URL
            self._crawl_url(self.site, depth=0)
            # Note: Executor shutdown is handled in crawl_site() after all threads complete
        except Exception as e:
            self.logger.error(f"Error in crawler: {e}")
    
    def parse_robots(self):
        """Parse robots.txt"""
        robots_url = urljoin(self.site, '/robots.txt')
        response = self._fetch(robots_url)
        if response and response.status_code == 200:
            self.logger.info(f"Found robots.txt: {robots_url}")
            lines = response.text.split('\n')
            for line in lines:
                if 'llow: ' in line.lower():
                    url_path = re.sub(r'.*llow: ', '', line, flags=re.IGNORECASE).strip()
                    url = fix_url(self.site, url_path)
                    if url:
                        self._output("robots", "robots", url)
                        if self.executor:
                            self.executor.submit(self._crawl_url, url, 0, False)
                        else:
                            self._crawl_url(url, 0, False)
    
    def parse_sitemap(self):
        """Parse sitemap.xml"""
        sitemap_paths = [
            '/sitemap.xml', '/sitemap_news.xml', '/sitemap_index.xml',
            '/sitemap-index.xml', '/sitemapindex.xml', '/sitemap-news.xml',
            '/post-sitemap.xml', '/page-sitemap.xml', '/portfolio-sitemap.xml',
            '/home_slider-sitemap.xml', '/category-sitemap.xml', '/author-sitemap.xml'
        ]
        
        for path in sitemap_paths:
            sitemap_url = urljoin(self.site, path)
            self.logger.info(f"Trying to find {sitemap_url}")
            response = self._fetch(sitemap_url)
            if response and response.status_code == 200:
                try:
                    # Suppress BeautifulSoup warnings for XML parsing
                    with warnings.catch_warnings():
                        warnings.filterwarnings('ignore', category=UserWarning, module='bs4')
                    soup = BeautifulSoup(response.text, 'xml')
                    # Find all URL tags
                    for url_tag in soup.find_all('url'):
                        loc = url_tag.find('loc')
                        if loc and loc.text:
                            self._output("sitemap", "sitemap", loc.text)
                            if self.executor:
                                self.executor.submit(self._crawl_url, loc.text, 0, False)
                            else:
                                self._crawl_url(loc.text, 0, False)
                    
                    # Also check for sitemapindex
                    for sitemap_tag in soup.find_all('sitemap'):
                        loc = sitemap_tag.find('loc')
                        if loc and loc.text:
                            self.parse_sitemap_url(loc.text)
                except Exception as e:
                    self.logger.debug(f"Error parsing sitemap {sitemap_url}: {e}")
    
    def parse_sitemap_url(self, sitemap_url):
        """Parse a specific sitemap URL"""
        response = self._fetch(sitemap_url)
        if response and response.status_code == 200:
            try:
                # Suppress BeautifulSoup warnings for XML parsing
                with warnings.catch_warnings():
                    warnings.filterwarnings('ignore', category=UserWarning, module='bs4')
                soup = BeautifulSoup(response.text, 'xml')
                for url_tag in soup.find_all('url'):
                    loc = url_tag.find('loc')
                    if loc and loc.text:
                        self._output("sitemap", "sitemap", loc.text)
                        if self.executor:
                            self.executor.submit(self._crawl_url, loc.text, 0, False)
                        else:
                            self._crawl_url(loc.text, 0, False)
            except:
                pass


def normalize_url(url_str):
    """Normalize URL: lowercase scheme/host, remove default port, sort query params, strip fragment"""
    try:
        parsed = urlparse(url_str)
        scheme = (parsed.scheme or 'https').lower()
        netloc = parsed.netloc.lower()
        
        # Remove default port
        if ':' in netloc:
            host, port = netloc.split(':', 1)
            if (scheme == 'https' and port == '443') or (scheme == 'http' and port == '80'):
                netloc = host
        
        # Normalize path (remove double slashes, but keep leading slash)
        path = parsed.path or '/'
        path = re.sub(r'/+', '/', path)
        
        # Sort query parameters
        query_parts = []
        if parsed.query:
            params = parse_qsl(parsed.query, keep_blank_values=True)
            params.sort()
            query_parts = urlencode(params)
        
        # Reconstruct URL without fragment
        normalized = urlunparse((scheme, netloc, path, parsed.params, query_parts, ''))
        return normalized
    except:
        return url_str


def get_wayback_urls(domain, no_subs=False, since=None, until=None, filter_status=None, limit=100000):
    """Get URLs from Wayback Machine CDX API"""
    urls = []
    
    try:
        params = {
            'url': domain,
            'matchType': 'domain',
            'limit': limit,
            'output': 'json'
        }
        
        if filter_status:
            params['filter'] = f'statuscode:{filter_status}'
        else:
            params['filter'] = 'statuscode:200'  # Default to 200 only
        
        if since:
            params['from'] = since  # Format: YYYYMMDDHHmmss
        if until:
            params['to'] = until
        
        url = "http://web.archive.org/cdx/search/cdx"
        response = requests.get(url, params=params, timeout=60)
        if response.status_code == 200:
            try:
                data = response.json()
                if data and len(data) > 1:
                    for row in data[1:]:  # Skip header
                        if len(row) > 2:
                            url_str = row[2]  # Original URL is at index 2
                            normalized = normalize_url(url_str)
                            if normalized:
                                urls.append(normalized)
            except (json.JSONDecodeError, ValueError, KeyError, IndexError) as e:
                # Invalid JSON response or malformed data - silently fail
                pass
        elif response.status_code == 429:
            # Rate limited - silently fail
            pass
        else:
            # Other HTTP errors - silently fail
            pass
    except (requests.exceptions.RequestException, requests.exceptions.Timeout, 
            requests.exceptions.ConnectionError) as e:
        # Network errors - silently fail
        pass
    except Exception as e:
        # Unexpected errors - silently fail
        pass
    
    return unique(urls)


def get_commoncrawl_indexes():
    """Get list of available Common Crawl indexes"""
    try:
        response = requests.get("https://index.commoncrawl.org/collinfo.json", timeout=30)
        if response.status_code == 200:
            indexes = response.json()
            # Return the latest index
            if indexes:
                return indexes[0]['id']
    except:
        pass
    # Fallback to a known recent index
    return "CC-MAIN-2023-23"


def get_commoncrawl_urls(domain, no_subs=False, since=None, until=None):
    """Get URLs from Common Crawl"""
    urls = []
    subs_wildcard = "*." if not no_subs else ""
    
    try:
        # Get latest index
        index_id = get_commoncrawl_indexes()
        
        url = f"https://index.commoncrawl.org/{index_id}-index"
        params = {
            'url': f"{subs_wildcard}{domain}/*",
            'output': 'json'
        }
        
        response = requests.get(url, params=params, timeout=60, stream=True)
        
        if response.status_code == 200:
            for line in response.iter_lines(decode_unicode=True):
                if line:
                    try:
                        data = json.loads(line)
                        if 'url' in data:
                            url_str = data['url']
                            # Filter by date if provided
                            if since or until:
                                timestamp = data.get('timestamp', '')
                                if timestamp:
                                    if since and timestamp < since:
                                        continue
                                    if until and timestamp > until:
                                        continue
                            urls.append(normalize_url(url_str))
                    except:
                        pass
    except:
        pass
    
    return unique(urls)


def get_virustotal_urls(domain, no_subs=False):
    """Get URLs from VirusTotal"""
    urls = []
    api_key = os.getenv('VT_API_KEY')
    if not api_key:
        return urls
    
    try:
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {
            'apikey': api_key,
            'domain': domain
        }
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            # Check for detected URLs
            if 'detected_urls' in data:
                for item in data['detected_urls']:
                    if 'url' in item:
                        urls.append(normalize_url(item['url']))
            
            # Also check for undetected URLs if available
            if 'undetected_urls' in data:
                for item in data['undetected_urls']:
                    if 'url' in item:
                        urls.append(normalize_url(item['url']))
    except:
        pass
    
    return unique(urls)


def get_otx_urls(domain, no_subs=False):
    """Get URLs from AlienVault OTX"""
    urls = []
    page = 0
    max_pages = 100  # Limit to prevent infinite loops
    
    while page < max_pages:
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
            params = {
                'limit': 50,
                'page': page
            }
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if 'url_list' in data and data['url_list']:
                    for item in data['url_list']:
                        if 'url' in item:
                            urls.append(normalize_url(item['url']))
                    
                    if not data.get('has_next', False):
                        break
                    page += 1
                else:
                    break
            elif response.status_code == 404:
                    break
            else:
                break
        except:
            break
    
    return unique(urls)


def get_urlscan_urls(domain, no_subs=False):
    """Get URLs from URLScan.io (GAU implementation)"""
    urls = []
    try:
        # URLScan public API endpoint
        url = f"https://urlscan.io/api/v1/search/"
        params = {
            'q': f'domain:{domain}',
            'size': 100
        }
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            if 'results' in data:
                for result in data['results']:
                    if 'page' in result and 'url' in result['page']:
                        urls.append(normalize_url(result['page']['url']))
                
                # Handle pagination
                total = data.get('total', 0)
                if total > 100:
                    # Fetch more pages (limited to first 1000 results)
                    for page in range(1, min(10, (total // 100) + 1)):
                        params['page'] = page
                        try:
                            resp = requests.get(url, params=params, timeout=30)
                            if resp.status_code == 200:
                                page_data = resp.json()
                                if 'results' in page_data:
                                    for result in page_data['results']:
                                        if 'page' in result and 'url' in result['page']:
                                            urls.append(normalize_url(result['page']['url']))
                        except:
                            break
    except:
        pass
    
    return unique(urls)


def get_grayhatwarfare_urls(domain, no_subs=False):
    """Get URLs from GrayHatWarfare (buckets.grayhatwarfare.com) - searches for exposed S3 buckets and files"""
    urls = []
    
    try:
        # GrayHatWarfare v2 API endpoint
        search_url = "https://buckets.grayhatwarfare.com/api/v2/files"
        
        # API parameters
        params = {
            'keywords': domain,
            'full-path': '1',  # Get full file paths
            'types': 'aws,azure',  # Search both AWS and Azure buckets
            'limit': 100  # Limit results to avoid rate limits
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Add authorization token if available via environment variable
        auth_token = os.getenv('GRAYHATWARFARE_TOKEN')
        if auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        
        # Make API request
        response = requests.get(search_url, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            try:
                data = response.json()
                
                # v2 API returns files directly
                files = []
                if isinstance(data, dict):
                    # Check common response formats
                    if 'files' in data:
                        files = data['files']
                    elif 'results' in data:
                        files = data['results']
                    elif 'data' in data:
                        files = data['data']
                    elif 'items' in data:
                        files = data['items']
                elif isinstance(data, list):
                    files = data
                
                # Extract URLs from files
                for file_info in files:
                    if isinstance(file_info, dict):
                        # Try different possible URL fields
                        file_url = (file_info.get('url') or 
                                   file_info.get('file_url') or 
                                   file_info.get('path') or 
                                   file_info.get('full_path') or
                                   file_info.get('link'))
                        
                        if file_url:
                            # Ensure URL is complete
                            if not file_url.startswith(('http://', 'https://')):
                                # Try to construct full URL
                                bucket_name = file_info.get('bucket') or file_info.get('bucket_name')
                                if bucket_name:
                                    if 's3' in bucket_name.lower() or 'amazonaws' in bucket_name.lower():
                                        file_url = f"https://{bucket_name}/{file_url.lstrip('/')}"
                                    else:
                                        file_url = f"https://{bucket_name}.s3.amazonaws.com/{file_url.lstrip('/')}"
                            
                            # Filter by domain if needed
                            if domain in file_url or (not no_subs and f'.{domain}' in file_url):
                                urls.append(normalize_url(file_url))
                        
                        # Also check for bucket URL
                        bucket_url = file_info.get('bucket_url') or file_info.get('bucket_link')
                        if bucket_url:
                            if domain in bucket_url or (not no_subs and f'.{domain}' in bucket_url):
                                urls.append(normalize_url(bucket_url))
            except (json.JSONDecodeError, KeyError, TypeError):
                # If JSON parsing fails, skip silently
                pass
    except:
        pass
    
    return unique(urls)


def get_shodan_urls(domain, no_subs=False):
    """Get URLs from Shodan (requires SHODAN_API_KEY environment variable)"""
    urls = []
    api_key = os.getenv('SHODAN_API_KEY')
    if not api_key:
        return urls
    
    try:
        # Shodan host search API
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            'key': api_key,
            'query': f'hostname:{domain}',
            'minify': True
        }
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            if 'matches' in data:
                for match in data['matches']:
                    # Extract URLs from hostnames and ports
                    hostnames = match.get('hostnames', [])
                    ip = match.get('ip_str', '')
                    port = match.get('port', 80)
                    
                    # Try to build URLs
                    if hostnames:
                        for host in hostnames:
                            if not no_subs or host == domain or host.endswith('.' + domain):
                                scheme = 'https' if port == 443 else 'http'
                                urls.append(normalize_url(f"{scheme}://{host}:{port}"))
                                urls.append(normalize_url(f"{scheme}://{host}"))
                    
                    # Also add IP-based URLs if no hostname
                    if ip and not hostnames:
                        scheme = 'https' if port == 443 else 'http'
                        urls.append(normalize_url(f"{scheme}://{ip}:{port}"))
    except:
        pass
    
    return unique(urls)


def get_censys_urls(domain, no_subs=False):
    """Get URLs from Censys.io (requires CENSYS_API_ID and CENSYS_API_SECRET environment variables)"""
    urls = []
    api_id = os.getenv('CENSYS_API_ID')
    api_secret = os.getenv('CENSYS_API_SECRET')
    
    if not api_id or not api_secret:
        return urls
    
    try:
        import base64
        # Censys v2 API - search certificates/websites
        url = "https://search.censys.io/api/v2/hosts/search"
        auth_string = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {
            'Authorization': f'Basic {auth_string}'
        }
        
        # Search for domain in certificates and services
        query = f'services.tls.certificates.leaf_data.subject.common_name:{domain}'
        if not no_subs:
            query += f' OR services.tls.certificates.leaf_data.subject.common_name:*.{domain}'
        
        params = {
            'q': query,
            'per_page': 100
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            if 'result' in data and 'hits' in data['result']:
                for hit in data['result']['hits']:
                    # Extract services/ports
                    services = hit.get('services', [])
                    ip = hit.get('ip', '')
                    
                    for service in services:
                        port = service.get('port', 443)
                        service_name = service.get('service_name', '').lower()
                        
                        # Build URL
                        if 'http' in service_name or port in [80, 443, 8080, 8443]:
                            scheme = 'https' if port in [443, 8443] else 'http'
                            
                            # Try to get hostname from certificate
                            if 'tls' in service:
                                cert = service.get('tls', {}).get('certificates', {}).get('leaf_data', {})
                                subject = cert.get('subject', {})
                                common_names = subject.get('common_name', [])
                                
                                for cn in common_names:
                                    if not no_subs or cn == domain or cn.endswith('.' + domain):
                                        if port not in [443, 8443]:
                                            urls.append(normalize_url(f"{scheme}://{cn}:{port}"))
                                        else:
                                            urls.append(normalize_url(f"{scheme}://{cn}"))
                            
                            # Fallback to IP
                            if ip:
                                if port not in [443, 8443]:
                                    urls.append(normalize_url(f"{scheme}://{ip}:{port}"))
                                else:
                                    urls.append(normalize_url(f"{scheme}://{ip}"))
    except:
        pass
    
    return unique(urls)


def filter_urls_by_extension(urls, blacklist_ext=None):
    """Filter URLs by file extension blacklist (GAU feature)"""
    if not blacklist_ext:
        return urls
    
    if isinstance(blacklist_ext, str):
        blacklist_ext = [ext.strip() for ext in blacklist_ext.split(',')]
    
    filtered = []
    for url in urls:
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            # Check if path ends with any blacklisted extension
            is_blacklisted = any(path.endswith(f'.{ext.lower()}') for ext in blacklist_ext if ext)
            if not is_blacklisted:
                filtered.append(url)
        except:
            filtered.append(url)  # Include if parsing fails
    
    return filtered


def filter_urls_by_status(urls, filter_status=None, match_status=None):
    """Filter URLs by HTTP status code (GAU feature: --fc and --mc)"""
    # Note: This requires checking each URL, which can be slow
    # For now, return as-is. Status filtering should be done when fetching
    return urls


def remove_query_params(url):
    """Remove query parameters from URL (GAU --fp feature)"""
    try:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, '', parsed.fragment))
    except:
        return url


def other_sources(domain, include_subs=False, providers=None, since=None, until=None, 
                 blacklist_ext=None, filter_params=False, wbm_limit=100000):
    """Get URLs from 3rd party sources
    Returns list of tuples: (url, provider_name)"""
    no_subs = not include_subs
    all_urls = []
    
    # Default providers
    if providers is None:
        providers = ['wayback', 'commoncrawl', 'otx', 'urlscan', 'virustotal', 'grayhatwarfare', 'shodan', 'censys']
    
    provider_functions = {
        'wayback': lambda: get_wayback_urls(domain, no_subs, since, until, None, wbm_limit),
        'commoncrawl': lambda: get_commoncrawl_urls(domain, no_subs, since, until),
        'otx': lambda: get_otx_urls(domain, no_subs),
        'urlscan': lambda: get_urlscan_urls(domain, no_subs),
        'virustotal': lambda: get_virustotal_urls(domain, no_subs),
        'grayhatwarfare': lambda: get_grayhatwarfare_urls(domain, no_subs),
        'shodan': lambda: get_shodan_urls(domain, no_subs),
        'censys': lambda: get_censys_urls(domain, no_subs),
    }
    
    # Create provider mapping for tracking
    provider_tasks = []
    for provider in providers:
        if provider.lower() in provider_functions:
            provider_tasks.append((provider.lower(), provider_functions[provider.lower()]))
    
    if not provider_tasks:
        return []
    
    with ThreadPoolExecutor(max_workers=len(provider_tasks)) as executor:
        futures = {executor.submit(fn): provider_name for provider_name, fn in provider_tasks}
        for future in as_completed(futures):
            provider_name = futures[future]
            try:
                urls = future.result()
                # Tag each URL with its provider
                for url in urls:
                    all_urls.append((url, provider_name))
            except Exception as e:
                # Silently fail for individual provider errors
                pass
    
    # Apply filters
    # Deduplicate by URL (keep first occurrence with provider info)
    seen_urls = set()
    unique_urls = []
    for url, provider in all_urls:
        url_lower = url.lower()
        if url_lower not in seen_urls:
            seen_urls.add(url_lower)
            unique_urls.append((url, provider))
    
    result = unique_urls
    
    # Filter by extension blacklist
    if blacklist_ext:
        filtered = []
        if isinstance(blacklist_ext, str):
            ext_list = [ext.strip() for ext in blacklist_ext.split(',')]
        else:
            ext_list = blacklist_ext
        
        for url, provider in result:
            is_blacklisted = any(url.lower().endswith(f'.{ext.lower()}') for ext in ext_list if ext)
            if not is_blacklisted:
                filtered.append((url, provider))
        result = filtered
    
    # Remove query parameters if requested
    if filter_params:
        result = [(remove_query_params(url), provider) for url, provider in result]
        # Re-deduplicate after removing query params
        seen_urls = set()
        unique_result = []
        for url, provider in result:
            url_lower = url.lower()
            if url_lower not in seen_urls:
                seen_urls.add(url_lower)
                unique_result.append((url, provider))
        result = unique_result
    
    return result


def crawl_site(site, args, logger):
    """Crawl a single site"""
    crawler = Crawler(site, args, logger)
    
    threads = []
    
    # Start main crawler
    t = threading.Thread(target=crawler.start)
    t.start()
    threads.append(t)
    
    # Parse sitemap (always enabled)
    t = threading.Thread(target=crawler.parse_sitemap)
    t.start()
    threads.append(t)
    
    # Parse robots (always enabled)
    t = threading.Thread(target=crawler.parse_robots)
    t.start()
    threads.append(t)
    
    # Other sources (always enabled)
    def process_other_sources():
        try:
            domain = crawler.domain
            if not domain:
                logger.warn(f"Could not extract domain from {site}, skipping passive sources")
                return
            
            logger.info(f"Fetching URLs from passive sources for {domain}...")
            try:
                results = other_sources(domain, args.include_subs, wbm_limit=args.wbm_limit)
                logger.info(f"Found {len(results)} URLs from passive sources")
                if len(results) == 0:
                    logger.warn(f"No URLs found from passive sources for {domain}")
            except Exception as e:
                logger.error(f"Error fetching URLs from passive sources: {e}")
                import traceback
                logger.error(traceback.format_exc())
                return
            
            # Track passive source counts (count all URLs from passive sources, even if duplicates)
            provider_counts = {}
            for url, provider in results:
                url = url.strip()
                if not url:
                    continue
                
                # Count URLs from each passive source
                provider_counts[provider] = provider_counts.get(provider, 0) + 1
                # Output with provider information
                output_type = f"passive-{provider}"
                crawler._output(output_type, provider, url)
                # Track source for this URL
                url_normalized = url.lower().strip()
                with crawler.url_sources_lock:
                    crawler.url_sources[url_normalized] = provider
                # Crawl with provider source so subdomains found will show correct source
                # Only submit if executor is still active
                try:
                    crawler.executor.submit(crawler._crawl_url, url, 0, False, provider)
                except (RuntimeError, AttributeError):
                    # Executor has been shut down or doesn't exist, skip crawling this URL
                    pass
            
            # Update passive source stats with all URLs found (including duplicates)
            with crawler.stats_lock:
                for provider, count in provider_counts.items():
                    crawler.stats['passive'][provider] = crawler.stats['passive'].get(provider, 0) + count
        except Exception as e:
            logger.error(f"Error in process_other_sources: {e}")
        
        t = threading.Thread(target=process_other_sources)
        t.start()
        threads.append(t)
    
    # Wait for all threads
    for t in threads:
        t.join()
    
    # Shutdown executor after all threads complete
    if crawler.executor:
        crawler.executor.shutdown(wait=True)
    
    # Print summary statistics
    if not args.quiet and not args.json or args.clean:
        # In clean mode, always show summary
        if args.clean:
            print("")
            print("=" * 60)
            print("Crawl Summary")
            print("=" * 60)
        else:
            logger.info("")
            logger.info("=" * 60)
            logger.info("Crawl Summary")
            logger.info("=" * 60)
        with crawler.stats_lock:
            if args.clean:
                print(f"URLs discovered: {crawler.stats['urls']}")
                print(f"Subdomains found: {len(crawler.stats['subdomains'])}")
                print(f"JavaScript files: {crawler.stats['javascript']}")
                print(f"Forms found: {crawler.stats['forms']}")
                print(f"AWS S3 Buckets: {crawler.stats['aws_s3']}")
                print(f"AWS CloudFront URLs: {crawler.stats['aws_cloudfront']}")
            else:
                logger.info(f"URLs discovered: {crawler.stats['urls']}")
                logger.info(f"Subdomains found: {len(crawler.stats['subdomains'])}")
                logger.info(f"JavaScript files: {crawler.stats['javascript']}")
                logger.info(f"Forms found: {crawler.stats['forms']}")
                logger.info(f"AWS S3 Buckets: {crawler.stats['aws_s3']}")
                logger.info(f"AWS CloudFront URLs: {crawler.stats['aws_cloudfront']}")
            # Map provider names to readable format
            provider_names = {
                'wayback': 'Wayback machine',
                'commoncrawl': 'Common Crawl',
                'otx': 'OTX',
                'urlscan': 'URLScan',
                'virustotal': 'VirusTotal',
                'grayhatwarfare': 'GrayHatWarfare',
                'shodan': 'Shodan',
                'censys': 'Censys'
            }
            # Show passive sources that have URLs found
            for provider, count in sorted(crawler.stats['passive'].items()):
                if count > 0:
                    readable_name = provider_names.get(provider, provider.capitalize())
                    if args.clean:
                        print(f"{readable_name}: {count} Urls")
                    else:
                        logger.info(f"{readable_name}: {count} Urls")
        if args.clean:
            print("=" * 60)
        else:
            logger.info("=" * 60)
    
    if crawler.output:
        crawler.output.close()


def main():
    parser = argparse.ArgumentParser(
        description=f'Fast web spider written in Python - {VERSION} by {AUTHOR}',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-s', '--site', help='Site to crawl')
    parser.add_argument('-S', '--sites', help='Site list to crawl')
    parser.add_argument('-p', '--proxy', help='Proxy (Ex: http://127.0.0.1:8080)')
    parser.add_argument('-o', '--output', help='Output folder')
    parser.add_argument('-u', '--user-agent', default='web', 
                       help='User Agent to use (web/mobi/custom)')
    parser.add_argument('--cookie', help='Cookie to use (testA=a; testB=b)')
    parser.add_argument('-H', '--header', action='append', 
                       help='Header to use (Use multiple flag to set multiple header)')
    parser.add_argument('--exclude', help='Exclude URL Regex (URLs matching this pattern will be excluded)')
    parser.add_argument('--include', help='Include URL Regex (Only URLs matching this pattern will be included)')
    
    parser.add_argument('-t', '--threads', type=int, default=1,
                       help='Number of threads (Run sites in parallel)')
    parser.add_argument('-c', '--concurrent', type=int, default=5,
                       help='The number of the maximum allowed concurrent requests')
    parser.add_argument('-d', '--depth', type=int, default=1,
                       help='MaxDepth limits the recursion depth (Set it to 0 for infinite, default: 1)')
    parser.add_argument('-k', '--delay', type=int, default=0,
                       help='Delay before creating a new request (second)')
    parser.add_argument('-K', '--random-delay', type=int, default=0,
                       help='RandomDelay added to Delay (second)')
    parser.add_argument('-m', '--timeout', type=int, default=10,
                       help='Request timeout (second)')
    parser.add_argument('--wbm-limit', type=int, default=100000,
                       help='Wayback Machine result limit (default: 100000)')
    parser.add_argument('--check', action='store_true', default=False,
                       help='Check HTTP status code of discovered URLs')
    
    parser.add_argument('--find-url-from', dest='find_url_from', type=str, default='js',
                       help='Find URLs from files with specified extensions (comma-separated, e.g., js,css,txt, default: js)')
    parser.add_argument('-w', '--include-subs', dest='include_subs', action='store_true', default=True,
                       help='Include subdomains crawled from 3rd party (enabled by default)')
    parser.add_argument('--no-subs', dest='include_subs', action='store_false',
                       help='Disable including subdomains from 3rd party')
    
    parser.add_argument('--debug', action='store_true',
                       help='Turn on debug mode')
    parser.add_argument('--json', action='store_true',
                       help='Enable JSON output')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Turn on verbose')
    parser.add_argument('-l', '--length', action='store_true',
                       help='Turn on length')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress all the output and only show URL')
    parser.add_argument('--clean', action='store_true',
                       help='Suppress all output, remove duplicates, and show only summary')
    parser.add_argument('--version', action='store_true',
                       help='Check version')
    
    args = parser.parse_args()
    
    if args.version:
        print(f"Version: {VERSION}")
        print("\nExamples Command:")
        print('gospider -q -s "https://target.com/"')
        print('gospider -s "https://target.com/" -o output -c 10 -d 1')
        print('gospider -s "https://target.com/" -o output -c 10 -d 1')
        print('echo "http://target.com" | gospider -o output -c 10 -d 1')
        sys.exit(0)
    
    logger = Logger(debug=args.debug, verbose=args.verbose, quiet=args.quiet, clean=args.clean)
    
    # Create output folder
    if args.output:
        os.makedirs(args.output, exist_ok=True)
    
    # Parse sites input
    site_list = []
    if args.site:
        site_list.append(args.site)
    if args.sites:
        sites_file = reading_lines(args.sites)
        site_list.extend(sites_file)
    
    # Read from stdin
    if not sys.stdin.isatty():
        for line in sys.stdin:
            target = line.strip()
            if target:
                site_list.append(target)
    
    if not site_list:
        logger.error("No site in list. Please check your site input again")
        logger.info("Example: python netspider.py -s 'example.com'")
        logger.info("Example: python netspider.py -s 'https://example.com'")
        logger.info("For help: python netspider.py -h")
        sys.exit(1)
    
    # Process sites
    if args.threads > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(crawl_site, site, args, logger): site for site in site_list}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error crawling site: {e}")
    else:
        for site in site_list:
            try:
                crawl_site(site, args, logger)
            except Exception as e:
                logger.error(f"Error crawling site {site}: {e}")
    
    logger.info("Done.")


if __name__ == '__main__':
    main()
