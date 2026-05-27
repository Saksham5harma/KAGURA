def classify_endpoint(url: str) -> str:
    url = (url or "").lower()

    if any(x in url for x in ["/api/", "graphql", "v1", "v2", "rest"]):
        return "API"

    if url.endswith(".js") or ".js?" in url:
        return "JS"

    if any(x in url for x in ["login", "auth", "signin", "oauth", "sso"]):
        return "AUTH"

    if any(x in url for x in ["env", ".git", "backup", "dump", "config"]):
        return "LEAK"

    if any(ext in url for ext in [".png", ".jpg", ".jpeg", ".gif", ".css", ".avif", ".svg"]):
        return "ASSET"

    return "ASSET"
