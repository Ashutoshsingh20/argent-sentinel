from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List

import httpx

from runtime_settings import settings

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None

try:
    from azure.identity import DefaultAzureCredential  # type: ignore
    from azure.mgmt.resource import ResourceManagementClient  # type: ignore
except Exception:  # pragma: no cover
    DefaultAzureCredential = None
    ResourceManagementClient = None


@dataclass
class CacheEntry:
    payload: Dict[str, Any]
    ts: float


class CloudFeatureRegistry:
    def __init__(self) -> None:
        self._cache = CacheEntry(payload={}, ts=0.0)

    def _from_external_manifests(self) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = {"aws": [], "azure": [], "gcp": [], "other": []}
        urls = settings.cloud_feature_manifest_urls()
        if not urls:
            return out

        for url in urls:
            try:
                with httpx.Client(timeout=4.0) as client:
                    res = client.get(url)
                    if res.status_code != 200:
                        continue
                    data = res.json()
                for cloud_name, features in data.items():
                    key = str(cloud_name).strip().lower()
                    if key not in out:
                        key = "other"
                    if isinstance(features, list):
                        for item in features:
                            if isinstance(item, dict):
                                out[key].append(item)
                            else:
                                out[key].append({"name": str(item), "source": url})
            except Exception:
                continue

        return out

    def _aws_features(self) -> List[Dict[str, Any]]:
        if boto3 is None:
            return []
        try:
            session = boto3.session.Session()
            services = sorted(session.get_available_services())
            return [{"name": svc, "source": "boto3"} for svc in services]
        except Exception:
            return []

    def _azure_features(self) -> List[Dict[str, Any]]:
        if not settings.azure_cloud_actions_enabled:
            return []
        if DefaultAzureCredential is None or ResourceManagementClient is None:
            return []

        scope = settings.azure_tag_scope
        if not scope.startswith("/subscriptions/"):
            return []
        sub_id = scope.split("/")[2]
        if not sub_id:
            return []

        try:
            credential = DefaultAzureCredential()
            rm_client = ResourceManagementClient(credential, sub_id)
            providers = []
            for p in rm_client.providers.list():
                ns = getattr(p, "namespace", None)
                if ns:
                    providers.append(str(ns))
            return [{"name": ns, "source": "azure-rm-provider"} for ns in sorted(set(providers))]
        except Exception:
            return []

    def _gcp_features(self) -> List[Dict[str, Any]]:
        # Without serviceusage API dependency, keep portable baseline list.
        base = [
            "compute.googleapis.com",
            "storage.googleapis.com",
            "iam.googleapis.com",
            "cloudresourcemanager.googleapis.com",
        ]
        return [{"name": x, "source": "baseline"} for x in base]

    def _build_payload(self) -> Dict[str, Any]:
        manifests = self._from_external_manifests()
        aws = self._aws_features() + manifests.get("aws", [])
        azure = self._azure_features() + manifests.get("azure", [])
        gcp = self._gcp_features() + manifests.get("gcp", [])
        other = manifests.get("other", [])

        def dedupe(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            seen = set()
            out = []
            for it in items:
                name = str(it.get("name", "")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                out.append(it)
            return out

        aws = dedupe(aws)
        azure = dedupe(azure)
        gcp = dedupe(gcp)
        other = dedupe(other)

        return {
            "updated_at": time.time(),
            "providers": {
                "aws": {"count": len(aws), "features": aws},
                "azure": {"count": len(azure), "features": azure},
                "gcp": {"count": len(gcp), "features": gcp},
                "other": {"count": len(other), "features": other},
            },
        }

    def get(self, force: bool = False) -> Dict[str, Any]:
        now = time.time()
        if not force and self._cache.payload and (now - self._cache.ts) <= settings.cloud_feature_refresh_seconds:
            return self._cache.payload

        payload = self._build_payload()
        self._cache = CacheEntry(payload=payload, ts=now)
        return payload


registry = CloudFeatureRegistry()
