import requests


class SubdomainEnum:

    def enumerate(self, domain):

        subdomains = set()

        sources = [
            self.from_hackertarget,
            self.from_otx
        ]

        for source in sources:

            try:

                results = source(domain)

                for sub in results:
                    subdomains.add(sub)

            except Exception as e:
                print(f"[!] Source Error: {e}")

        filtered = []

        for sub in subdomains:

            if sub.count(".") >= 2:

                if not sub[0].isdigit():

                    filtered.append(sub)

        return sorted(filtered)

    def from_hackertarget(self, domain):

        url = (
            f"https://api.hackertarget.com/"
            f"hostsearch/?q={domain}"
        )

        response = requests.get(
            url,
            timeout=15
        )

        found = []

        if response.status_code == 200:

            for line in response.text.splitlines():

                if "," in line:

                    found.append(
                        line.split(",")[0].strip()
                    )

        return found

    def from_otx(self, domain):

        url = (
            f"https://otx.alienvault.com/api/v1/"
            f"indicators/domain/{domain}/passive_dns"
        )

        response = requests.get(
            url,
            timeout=15
        )

        found = []

        if response.status_code == 200:

            data = response.json()

            for item in data.get(
                "passive_dns",
                []
            ):

                hostname = item.get(
                    "hostname",
                    ""
                )

                if hostname.endswith(domain):

                    found.append(
                        hostname
                    )

        return found
