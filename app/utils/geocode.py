"""Simple reverse geocoding helper using Nominatim (OpenStreetMap)."""

from __future__ import annotations

import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def reverse_geocode(lat, lon, timeout=5):
    """Return (city, country_code) for given coordinates or (None, None).

    Uses OpenStreetMap Nominatim reverse geocoding. This is intended for
    demonstration and low-volume use. For production use a paid geocoding
    provider or an on-premise service.
    """
    try:
        params = {"format": "jsonv2", "lat": str(lat), "lon": str(lon), "zoom": 10, "addressdetails": 1}
        url = "https://nominatim.openstreetmap.org/reverse?" + urlencode(params)
        req = Request(url, headers={"User-Agent": "TrustSphere/1.0 (+https://trustsphere.com)"})
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        address = data.get("address", {}) if isinstance(data, dict) else {}
        # Prefer common place fields
        city = address.get("city") or address.get("town") or address.get("village") or address.get("hamlet") or address.get("county")
        country_code = (address.get("country_code") or "").upper()
        return city, country_code
    except Exception:
        return None, None
