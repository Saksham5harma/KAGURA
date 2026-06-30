import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


class DiscoveryEngine:

    def __init__(self):

        self.common_paths = [
            "admin",
            "login",
            "dashboard",
            "api",
            "api/v1",
            "swagger",
            "swagger-ui",
            "graphql",
            "robots.txt",
            "sitemap.xml",
            ".git",
            ".env",
            "backup",
            "config",
            "uploads"
        ]

    def find_endpoints(self, target):

        discovered = set()

        if not target.startswith("http"):
            target = f"https://{target}"

        try:

            response = requests.get(
                target,
                timeout=10,
                verify=False,
                allow_redirects=True
            )

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            for tag in soup.find_all("a", href=True):

                endpoint = urljoin(
                    target,
                    tag["href"]
                )

                discovered.add(endpoint)

            js_files = []

            for tag in soup.find_all("script", src=True):

                js_url = urljoin(
                    target,
                    tag["src"]
                )

                js_files.append(js_url)

                discovered.add(js_url)

            for path in self.common_paths:

                url = f"{target}/{path}"

                try:

                    r = requests.get(
                        url,
                        timeout=5,
                        verify=False
                    )

                    if r.status_code in [
                        200,
                        301,
                        302,
                        403
                    ]:

                        discovered.add(url)

                except:
                    pass

            robots = f"{target}/robots.txt"

            try:

                r = requests.get(
                    robots,
                    timeout=5,
                    verify=False
                )

                if r.status_code == 200:

                    discovered.add(robots)

                    for line in r.text.splitlines():

                        if line.startswith(
                            "Disallow:"
                        ):

                            endpoint = line.replace(
                                "Disallow:",
                                ""
                            ).strip()

                            if endpoint:

                                discovered.add(
                                    urljoin(
                                        target,
                                        endpoint
                                    )
                                )

            except:
                pass

            for js in js_files:

                try:

                    r = requests.get(
                        js,
                        timeout=5,
                        verify=False
                    )

                    urls = re.findall(
                        r'https?://[^\s"\']+',
                        r.text
                    )

                    for url in urls:

                        discovered.add(url)

                except:
                    pass

        except Exception as e:

            print(
                f"[Discovery Error] {e}"
            )

        return sorted(
            list(discovered)
        )
