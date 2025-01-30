import asyncio
import dns.resolver
import requests
import argparse
import aiohttp
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List, Set, Dict
import socket
import ssl
import logging
from datetime import datetime
from pathlib import Path
import os
import time
from bs4 import BeautifulSoup
from tqdm import tqdm

class SubdomainScanner:
    def __init__(self, target_domain: str, wordlist_path: str = None, scan_speed: int = 3):
        self.target_domain = target_domain
        self.discovered_subdomains: Set[str] = set()
        self.wordlist_path = wordlist_path or "wordlists/subdomains.txt"
        self.scan_speed = scan_speed
        self.dns_servers = [
            "8.8.8.8", "8.8.4.4",  # Google
            "1.1.1.1", "1.0.0.1",  # Cloudflare
            "9.9.9.9",  # Quad9
        ]
        self.setup_logging()
        self.progress_bar = None
        self.total_words = 0
        self.processed_words = 0
        self.executor = ThreadPoolExecutor(max_workers=10)  # ThreadPoolExecutor ekledim

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[ 
                logging.FileHandler(f'scan_{self.target_domain}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def update_progress(self, amount=1):
        """İlerleme çubuğunu güncelle"""
        if self.progress_bar:
            self.processed_words += amount
            self.progress_bar.update(amount)
            self.progress_bar.set_postfix({
                'Bulunan': len(self.discovered_subdomains),
                'Tamamlanan': f"{(self.processed_words/self.total_words)*100:.1f}%"
            })

    async def scan(self):
        self.logger.info(f"Tarama başlatılıyor: {self.target_domain}")

        tasks = [
            self.passive_scan(),
            self.active_scan(),
            self.dns_enumeration()
        ]

        results = await asyncio.gather(*tasks)
        all_subdomains = set().union(*results)

        self.logger.info("Subdomainler doğrulanıyor...")
        valid_subdomains = await self.validate_subdomains(all_subdomains)

        return valid_subdomains

    async def passive_scan(self) -> Set[str]:
        self.logger.info("Pasif tarama başlatılıyor...")
        passive_sources = [
            self.search_crtsh(),
        ]

        results = await asyncio.gather(*passive_sources)
        return set().union(*results)

    async def search_crtsh(self) -> Set[str]:
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{self.target_domain}&output=json"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        subdomains.update({entry['name_value'] for entry in data if 'name_value' in entry})
                        self.logger.info(f"crt.sh'den {len(subdomains)} subdomain bulundu")
        except Exception as e:
            self.logger.error(f"crt.sh sorgusu başarısız: {e}")

        return subdomains

    async def active_scan(self) -> Set[str]:
        wordlist = self.load_wordlist()
        if not wordlist:
            self.logger.error("Wordlist yüklenemedi veya boş!")
            return set()

        self.total_words = len(wordlist)
        self.logger.info(f"Aktif tarama başlatılıyor... (Toplam {self.total_words} kelime)")

        # Progress bar oluştur
        self.progress_bar = tqdm(
            total=self.total_words,
            desc="Subdomain Taraması",
            unit="domain",
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
        )

        chunks = self.chunk_list(wordlist, 1000 // self.scan_speed)
        subdomains = set()

        for chunk in chunks:
            tasks = [self.check_subdomain(subdomain) for subdomain in chunk]
            results = await asyncio.gather(*tasks)
            found_subdomains = [r for r in results if r]
            subdomains.update(found_subdomains)
            self.discovered_subdomains.update(found_subdomains)
            self.update_progress(len(chunk))

        self.progress_bar.close()
        return subdomains

    async def check_subdomain(self, subdomain: str) -> str:
        full_domain = f"{subdomain}.{self.target_domain}"
        try:
            answers = await self.resolve_ip(full_domain)
            if answers:
                self.logger.info(f"Bulunan subdomain: {full_domain}")
                return full_domain
        except Exception:
            pass
        return ""

    async def resolve_ip(self, domain: str) -> List[str]:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(self.executor, self.resolve_ip_sync, domain)
        return result

    def resolve_ip_sync(self, domain: str) -> List[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_servers[0]]
            answers = resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    async def dns_enumeration(self) -> Set[str]:
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV']
        subdomains = set()

        async def dns_query(dns_server: str, record_type: str):
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]

            try:
                answers = resolver.resolve(self.target_domain, record_type)
                return [str(rdata.target).rstrip('.') if record_type == 'CNAME' else str(rdata).rstrip('.') for rdata in answers]
            except Exception:
                return []

        tasks = []
        for dns_server in self.dns_servers:
            for record_type in record_types:
                tasks.append(dns_query(dns_server, record_type))

        results = await asyncio.gather(*tasks)
        for result in results:
            subdomains.update(result)

        return subdomains

    async def validate_subdomains(self, subdomains: Set[str]) -> List[Dict]:
        if not subdomains:
            return []

        valid_subdomains = []
        validation_progress = tqdm(
            total=len(subdomains),
            desc="Subdomain Doğrulama",
            unit="domain"
        )

        async def validate_single(subdomain: str):
            try:
                ip_addresses = await self.resolve_ip(subdomain)
                if ip_addresses:
                    http_info = await self.get_http_info(subdomain)
                    ssl_info = await self.get_ssl_info(subdomain)
                    validation_progress.update(1)
                    return {
                        "subdomain": subdomain,
                        "ip_addresses": ip_addresses,
                        "http_status": http_info.get("status"),
                        "server": http_info.get("server"),
                        "title": http_info.get("title"),
                        "ssl_valid": ssl_info.get("valid"),
                        "ssl_issuer": ssl_info.get("issuer"),
                        "ssl_expiry": ssl_info.get("expiry")
                    }
            except Exception as e:
                self.logger.debug(f"Doğrulama hatası {subdomain}: {e}")
                validation_progress.update(1)
                return None

        tasks = [validate_single(subdomain) for subdomain in subdomains]
        results = await asyncio.gather(*tasks)
        validation_progress.close()

        return [r for r in results if r]

    def load_wordlist(self) -> List[str]:
        try:
            encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
            for encoding in encodings:
                try:
                    with open(self.wordlist_path, encoding=encoding) as f:
                        words = [line.strip() for line in f if line.strip()]
                        if words:
                            self.logger.info(f"Wordlist başarıyla yüklendi ({encoding} encoding)")
                            return words
                except UnicodeDecodeError:
                    continue
            
            with open(self.wordlist_path, 'rb') as f:
                words = [line.decode('latin-1').strip() for line in f if line.strip()]
                if words:
                    self.logger.info("Wordlist binary mode'da yüklendi")
                    return words
                
            self.logger.error("Wordlist yüklenemedi!")
            return []
        except FileNotFoundError:
            self.logger.error(f"Wordlist dosyası bulunamadı: {self.wordlist_path}")
            return []
        except Exception as e:
            self.logger.error(f"Wordlist yükleme hatası: {str(e)}")
            return []

    def chunk_list(self, lst: list, chunk_size: int):
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

    def export_results(self, results: List[Dict], format: str = "json"):
        if not results:
            self.logger.warning("Sonuç bulunamadı!")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results_{self.target_domain}_{timestamp}.{format}"

        try:
            if format == "json":
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=4)
            elif format == "csv":
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=results[0].keys())
                    writer.writeheader()
                    writer.writerows(results)

            self.logger.info(f"Sonuçlar kaydedildi: {filename}")
            self.logger.info(f"Toplam taranan kelime sayısı: {self.total_words}")
            self.logger.info(f"Bulunan subdomain sayısı: {len(results)}")
        except Exception as e:
            self.logger.error(f"Sonuçlar kaydedilirken hata oluştu: {str(e)}")

async def main():
    parser = argparse.ArgumentParser(description="Gelişmiş Subdomain Keşif Aracı")
    parser.add_argument("domain", help="Hedef domain")
    parser.add_argument("-w", "--wordlist", help="Özel wordlist dosyası")
    parser.add_argument("-o", "--output", choices=["json", "csv"], default="json",
                      help="Çıktı formatı (default: json)")
    parser.add_argument("-t", "--threads", type=int, choices=range(1, 6), default=3,
                      help="Tarama hızı (1-5 arası)")
    args = parser.parse_args()

    scanner = SubdomainScanner(args.domain, args.wordlist, args.threads)
    results = await scanner.scan()
    scanner.export_results(results, args.output)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTarama kullanıcı tarafından durduruldu!")
        sys.exit(0)