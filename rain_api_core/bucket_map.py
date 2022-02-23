from collections import defaultdict
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

    def is_accessible(self, groups: Iterable[str] = None) -> bool:
        """Check if the object is accessible with the given permissions.

        Setting `groups` to an iterable implies that the user has logged in,
        which is different from setting it to None which implies public access
        is needed.
        """

        required_groups = self.get_required_groups()
        # Check for public access
        if required_groups is None:
            return True

        # At this point public access is not allowed
        if groups is None:
            return False

        return not required_groups or not required_groups.isdisjoint(groups)

    def get_required_groups(self) -> Optional[set]:
        """Get a set of permissions protecting this object.

        It is sufficient to have one of the permissions in the set in order to
        access the object. Returns None if the object has public access. An
        empty set means any logged in user can access the object.
        """
        if not self._access_control:
            # By default, buckets are accessible to any logged in users
            return set()

        # NOTE: Key order is important here. Most deeply nested keys need to be
        # checked first.
        for key_prefix, access in self._access_control.items():
            if not self.object_key.startswith(key_prefix):
                continue

            if access is _PUBLIC:
                return None

            return access

        return set()


class BucketMap():
    def __init__(
        self,
        bucket_map: dict,
        bucket_name_prefix: str = "",
        reverse: bool = False
    ):
        self.bucket_map = bucket_map
        self.access_control = _parse_access_control(bucket_map)
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
                # TODO(reweeden): Do we really want to be control access by
                # bucket? Wouldn't it make more sense to control access by
                # path instead?
                _access_control=self.access_control.get(bucket)
            )

        return None


def _parse_access_control(bucket_map: dict) -> dict:
    """Turn the access definitions into a dictionary of rules that should be
    checked in order.

    The rules will be sorted by most deeply nested first. An example may look
    like this:

    {
        "bucket1": {
            "key/foo/bar": _PUBLIC,
            "key/bar/baz": {"group"},
            "key": {"group2"}
        },
        "bucket2": {
            "": _PUBLIC
        },
        "bucket3": {
            "": {"group3"}
        }
    }
    """
    public_buckets = bucket_map.get("PUBLIC_BUCKETS", ())
    private_buckets = bucket_map.get("PRIVATE_BUCKETS", {})

    try:
        access_list = [(rule, _PUBLIC) for rule in public_buckets]
    except TypeError:
        access_list = []
    access_list.extend((rule, set(groups)) for rule, groups in private_buckets.items())

    # Relying on the fact that `sort` is stable. The order in which we add
    # public/private rules to `access_list` is therefore important.
    access_list.sort(key=lambda item: item[0].count("/"), reverse=True)

    # Convert to dictionary for easier lookup on individual buckets
    # We're relying on python's dictionary keys being insertion ordered
    access = defaultdict(dict)
    for (rule, obj) in access_list:
        bucket, *prefix = rule.split("/", 1)
        access[bucket]["".join(prefix)] = obj

    return dict(access)
