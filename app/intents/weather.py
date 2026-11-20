"""WEATHER_CHECK_TEMPERATURE: current air temperature for a resolvable place (Open-Meteo, keyless, worldwide)."""
from __future__ import annotations

import re
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.sources.base import Fetcher, SourceError

GEOCODE = "https://geocoding-api.open-meteo.com/v1/search"
FORECAST = "https://api.open-meteo.com/v1/forecast"
COORDS = re.compile(r"(-?\d{1,2}(?:\.\d+)?)\s*[, ]\s*(-?\d{1,3}(?:\.\d+)?)")
US_STATES = dict(zip(
    "AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC".split(),
    ["Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado", "Connecticut", "Delaware", "Florida", "Georgia", "Hawaii",
     "Idaho", "Illinois", "Indiana", "Iowa", "Kansas", "Kentucky", "Louisiana", "Maine", "Maryland", "Massachusetts", "Michigan",
     "Minnesota", "Mississippi", "Missouri", "Montana", "Nebraska", "Nevada", "New Hampshire", "New Jersey", "New Mexico", "New York",
     "North Carolina", "North Dakota", "Ohio", "Oklahoma", "Oregon", "Pennsylvania", "Rhode Island", "South Carolina", "South Dakota",
     "Tennessee", "Texas", "Utah", "Vermont", "Virginia", "Washington", "West Virginia", "Wisconsin", "Wyoming", "District of Columbia"]))
_TAIL = re.compile(r"\s*\b(?:right now|now|today|currently|at the moment|at present|outside|please)\b.*$", re.I)
_PLACE = re.compile(r"\b(?:in|at|for|near|of)\s+(.+?)\s*[?.!]*$", re.I)


def parse_location(params: dict[str, Any]) -> tuple[str, float | None, float | None]:
    """-> ("coords", lat, lon) | ("place:<text>", None, None) | ("none", None, None)."""
    lat, lon = first(params, "latitude", "lat"), first(params, "longitude", "lon", "lng")
    if lat and lon:
        try:
            return "coords", float(lat), float(lon)
        except ValueError:
            pass
    raw = first(params, "location", "city", "place", "q_location")
    if raw is None:
        text = free_text(params)
        m = _PLACE.search(_TAIL.sub("", text)) if text else None
        raw = m.group(1) if m else None
    if not raw:
        return "none", None, None
    m = COORDS.fullmatch(raw.strip())
    if m:
        return "coords", float(m.group(1)), float(m.group(2))
    return "place:" + _TAIL.sub("", raw).strip(" ?.!"), None, None


def _qualifier_matches(row: dict[str, Any], q: str) -> bool:
    q = q.strip().lower()
    names = {str(row.get(k, "")).lower() for k in ("admin1", "admin2", "country", "country_code")}
    return q in names or US_STATES.get(q.upper(), "").lower() in names


async def _geocode(f: Fetcher, text: str, timeout: float, deadline: float | None):
    name, _, qual = (p.strip() for p in text.partition(","))
    status, js = await f.get_json(GEOCODE, {"name": name, "count": 10, "language": "en", "format": "json"},
                                  timeout=timeout, deadline=deadline)
    rows = (js or {}).get("results") or []
    if qual:
        rows = [r for r in rows if _qualifier_matches(r, qual) or any(_qualifier_matches(r, w) for w in qual.split())]
    return rows


async def lookup(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None) -> dict[str, Any]:
    kind, lat, lon = parse_location(params)
    if kind == "none":
        return soft("no_location", "No location was found in the request, so no temperature is given. Supply location "
                    "(a city such as London, or latitude,longitude).", temperature_c=None)
    place, note, conf = None, None, 0.95
    if kind.startswith("place:"):
        text = kind[6:]
        try:
            rows = await _geocode(f, text, timeout, deadline)
        except SourceError as e:
            return soft("unavailable", f"The geocoder was unavailable ({e.kind}), so '{text}' could not be located and no temperature is given.",
                        temperature_c=None)
        if not rows:
            return soft("location_not_resolved", f"'{text}' did not match a known place, so no temperature is given. "
                        "Add a country or state, e.g. 'Springfield, Illinois'.", temperature_c=None)
        top = rows[0]
        rivals = [r for r in rows[1:4] if (r.get("population") or 0) >= 0.5 * (top.get("population") or 1)
                  and (r.get("country_code"), r.get("admin1")) != (top.get("country_code"), top.get("admin1"))]
        if rivals:
            conf, note = 0.6, "Several places share this name; the most populous match was used."
        lat, lon = top["latitude"], top["longitude"]
        place = ", ".join(str(x) for x in (top.get("name"), top.get("admin1"), top.get("country")) if x)
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return soft("invalid_coordinates", "Coordinates are out of range, so no temperature is given.", temperature_c=None)
    try:
        _, js = await f.get_json(FORECAST, {"latitude": lat, "longitude": lon, "current": "temperature_2m", "timezone": "GMT"},
                                 timeout=timeout, deadline=deadline)
        cur = js["current"]
        temp, observed = float(cur["temperature_2m"]), cur.get("time")
    except SourceError as e:
        return soft("unavailable", f"The weather source was unavailable ({e.kind}), so no temperature is given rather than a guess.",
                    temperature_c=None, place=place)
    except (KeyError, TypeError, ValueError):
        return soft("unavailable", "The weather source returned no current temperature.", temperature_c=None, place=place)
    where = place or f"{lat:.2f}, {lon:.2f}"
    answer = f"The current air temperature in {where} is {temp:.1f} °C ({temp * 9 / 5 + 32:.1f} °F), observed {observed} UTC (Open-Meteo)."
    if note:
        answer += " " + note
    return ok(answer, conf, temperature_c=round(temp, 1), temperature_f=round(temp * 9 / 5 + 32, 1), place=place,
              latitude=lat, longitude=lon, observed_at=observed, source="Open-Meteo", note=note)
