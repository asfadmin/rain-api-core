from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

# A unique object to signal that a bucket is public
_PUBLIC = object()


@dataclass()
class BucketMapEntry():
    bucket: str
    bucket_path: str
    object_key: str
    headers: dict
    _access_control: Optional[dict]

    def is_accessible(self, groups: Iterable[str] = ()) -> bool:
        if not self._access_control:
            # By default, buckets are completely locked down
            return False

        # NOTE: Key order is important here. Most deeply nested keys need to be
        # checked first.
        for key_prefix, access in self._access_control.items():
            if not self.object_key.startswith(key_prefix):
                continue

            if access is _PUBLIC:
                return True

            if groups and not access.isdisjoint(groups):
                return True

        return False


class BucketMap():
    def __init__(
        self,
        bucket_map: dict,
        bucket_name_prefix: str = "",
        reverse: bool = False
    ):
        self.bucket_map = bucket_map
        self.bucket_name_prefix = bucket_name_prefix
        self.reverse = reverse

    def get(self, key: str) -> Optional[BucketMapEntry]:
        """Search for a bucket entry for a given path.

        This is equivalent to performing route matching if you think of the
        BucketMap as an URL router.
        """
        path = key.split("/")

        if len(path) < 2:
            return None

        if self.reverse and len(path) == 3:
            path[0], path[1] = path[1], path[0]

        return self.get_path(path)

    def get_path(self, path: Sequence[str]) -> Optional[BucketMapEntry]:
        # Old and REVERSE format has no 'MAP'.
        node = self.bucket_map.get("MAP", self.bucket_map)

        headers = None
        # Walk the bucket map to see if this path is valid
        for i, path_part in enumerate(path):
            # Check if we hit a leaf of the YAML tree
            if isinstance(node, str):
                bucket = node
            elif "bucket" in node:
                bucket = node["bucket"]
                headers = node.get("headers")

            elif path_part in node:
                node = node[path_part]
                continue
            else:
                break

            assert bucket is not None
            # Split the path into bucket_name and object_name
            head, tail = path[:i], path[i:]
            bucket_path = "/".join(head)
            object_key = "/".join(tail)

            return BucketMapEntry(
                bucket=self.bucket_name_prefix + bucket,
                bucket_path=bucket_path,
                object_key=object_key,
                headers=headers or {},
                _access_control=self._get_access_control(bucket_path)
            )

        return None

    def _get_access_control(self, bucket_path: str) -> dict:
        # TODO(reweeden): Pre-parse this for the whole bucket map
        access_control = {}
        num_parts = bucket_path.count("/") + 1

        for entry in self._get_bucket_group("PUBLIC_BUCKETS"):
            if entry.startswith(bucket_path):
                parts = entry.split("/")
                key_prefix = "/".join(parts[num_parts:])
                access_control[key_prefix] = _PUBLIC

        private_buckets = self.bucket_map.get("PRIVATE_BUCKETS", {})
        for entry in self._get_bucket_group("PRIVATE_BUCKETS"):
            if entry.startswith(bucket_path):
                parts = entry.split("/")
                key_prefix = "/".join(parts[num_parts:])
                access_control[key_prefix] = set(private_buckets[entry])

        return dict(access_control)

    def _get_bucket_group(self, group: str) -> list:
        obj = self.bucket_map.get(group)
        if obj is None:
            return []

        # obj SHOULD be a dict, but any iterable actually works.
        try:
            return sorted(iter(obj), key=_num_parts, reverse=True)
        except TypeError:
            return []


def _num_parts(key: str):
    return key.count("/")
