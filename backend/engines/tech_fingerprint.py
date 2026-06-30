import requests
import urllib3
import re
from bs4 import BeautifulSoup

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


class TechFingerprint:

    def identify(self, target):

        technologies = []

        if not target.startswith("http"):
            target = f"https://{target}"

        try:

            r = requests.get(
                target,
                timeout=15,
                verify=False,
                allow_redirects=True
            )

            headers = r.headers
            body = r.text
            body_lower = body.lower()

            soup = BeautifulSoup(
                body,
                "html.parser"
            )

            self.detect_server(
                headers,
                technologies
            )

            self.detect_frameworks(
                body_lower,
                headers,
                technologies
            )

            self.detect_cms(
                body_lower,
                technologies
            )

            self.detect_waf(
                headers,
                technologies
            )

            self.detect_cdn(
                headers,
                technologies
            )

            self.detect_security_headers(
                headers,
                technologies
            )

            self.detect_cookies(
                headers,
                technologies
            )

            self.detect_js_libraries(
                soup,
                technologies
            )

        except Exception as e:

            print(
                f"[Fingerprint Error] {e}"
            )

        return technologies

    def detect_server(
        self,
        headers,
        technologies
    ):

        server = headers.get(
            "Server",
            ""
        )

        if server:

            technologies.append({
                "type": "Server",
                "value": server
            })

        powered = headers.get(
            "X-Powered-By",
            ""
        )

        if powered:

            technologies.append({
                "type": "Backend",
                "value": powered
            })

    def detect_frameworks(
        self,
        body,
        headers,
        technologies
    ):

        signatures = {
            "React": [
                "react",
                "__react"
            ],
            "NextJS": [
                "__next",
                "_next/static"
            ],
            "VueJS": [
                "vue"
            ],
            "Angular": [
                "ng-app",
                "angular"
            ],
            "Laravel": [
                "laravel_session"
            ],
            "Django": [
                "csrftoken"
            ]
        }

        for tech, patterns in signatures.items():

            for pattern in patterns:

                if pattern in body:

                    technologies.append({
                        "type": "Framework",
                        "value": tech
                    })

                    break

    def detect_cms(
        self,
        body,
        technologies
    ):

        cms = {
            "WordPress": [
                "wp-content",
                "wp-json"
            ],
            "Drupal": [
                "drupal-settings-json"
            ],
            "Joomla": [
                "joomla"
            ]
        }

        for name, patterns in cms.items():

            for pattern in patterns:

                if pattern in body:

                    technologies.append({
                        "type": "CMS",
                        "value": name
                    })

                    break

    def detect_waf(
        self,
        headers,
        technologies
    ):

        waf_signatures = {

            "Cloudflare":
            "cloudflare",

            "Sucuri":
            "sucuri",

            "Akamai":
            "akamai",

            "Imperva":
            "imperva"
        }

        header_blob = str(
            headers
        ).lower()

        for waf, sig in waf_signatures.items():

            if sig in header_blob:

                technologies.append({
                    "type": "WAF",
                    "value": waf
                })

    def detect_cdn(
        self,
        headers,
        technologies
    ):

        cdn_headers = str(
            headers
        ).lower()

        if "cloudflare" in cdn_headers:

            technologies.append({
                "type": "CDN",
                "value": "Cloudflare"
            })

        if "akamai" in cdn_headers:

            technologies.append({
                "type": "CDN",
                "value": "Akamai"
            })

    def detect_security_headers(
        self,
        headers,
        technologies
    ):

        security_headers = [

            "Content-Security-Policy",

            "Strict-Transport-Security",

            "X-Frame-Options",

            "X-Content-Type-Options",

            "Referrer-Policy"
        ]

        present = []

        for header in security_headers:

            if header in headers:

                present.append(
                    header
                )

        technologies.append({
            "type": "SecurityHeaders",
            "value": present
        })

    def detect_cookies(
        self,
        headers,
        technologies
    ):

        cookies = headers.get(
            "Set-Cookie",
            ""
        )

        if "PHPSESSID" in cookies:

            technologies.append({
                "type": "Backend",
                "value": "PHP"
            })

        if "JSESSIONID" in cookies:

            technologies.append({
                "type": "Backend",
                "value": "Java"
            })

        if "ASP.NET" in cookies:

            technologies.append({
                "type": "Backend",
                "value": "ASP.NET"
            })

    def detect_js_libraries(
        self,
        soup,
        technologies
    ):

        scripts = soup.find_all(
            "script",
            src=True
        )

        for script in scripts:

            src = script["src"].lower()

            if "jquery" in src:

                version = self.extract_version(src)

                technologies.append({
                    "type": "Library",
                    "value": "jQuery",
                    "version": version
                })

            if "bootstrap" in src:

                version = self.extract_version(src)

                technologies.append({
                    "type": "Library",
                    "value": "Bootstrap",
                    "version": version
                })

    def extract_version(
        self,
        text
    ):

        match = re.search(
            r'(\d+\.\d+(\.\d+)?)',
            text
        )

        if match:

            return match.group(1)

        return "unknown"
