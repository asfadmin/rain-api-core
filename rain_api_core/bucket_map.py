from collections import defaultdict
from dataclasses import dataclass, field
from typing import Generator, Iterable, Optional, Sequence, Tuple

# A unique object to signal that a bucket is public
_PUBLIC = object()


def _is_accessible(
    required_groups: Optional[set],
    groups: Optional[Iterable[str]]
) -> bool:
    # Check for public access
    if required_groups is None or required_groups is _PUBLIC:
        return True

    # At this point public access is not allowed
    if groups is None:
        return False

    return not required_groups or not required_groups.isdisjoint(groups)


@dataclass()
class BucketMapEntry():
    bucket: str
    bucket_path: str
    object_key: str
    headers: dict = field(default_factory=dict)
    _access_control: Optional[dict] = None

    def is_accessible(self, groups: Iterable[str] = None) -> bool:
        """Check if the object is accessible with the given permissions.

        Setting `groups` to an iterable implies that the user has logged in,
        which is different from setting it to None which implies public access
        is needed.
        """

        required_groups = self.get_required_groups()
        return _is_accessible(required_groups, groups)

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
        node = self._get_map()

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

            return self._make_entry(
                bucket=bucket,
                bucket_path=bucket_path,
                object_key=object_key,
                headers=headers
            )

        return None

    def entries(self):
        for bucket, path_parts, headers in _walk_entries(self._get_map()):
            yield self._make_entry(
                bucket=bucket,
                bucket_path="/".join(path_parts),
                object_key="",
                headers=headers
            )

    def to_iam_policy(self, groups: Iterable[str] = None) -> dict:
        generator = IamPolicyGenerator(groups)
        return generator.generate_policy(self.entries())

    def _get_map(self) -> dict:
        # Old and REVERSE format has no 'MAP'.
        return self.bucket_map.get("MAP", self.bucket_map)

    def _make_entry(
        self,
        bucket: str,
        bucket_path: str,
        object_key: str,
        headers: Optional[dict] = None
    ):
        return BucketMapEntry(
            bucket=self.bucket_name_prefix + bucket,
            bucket_path=bucket_path,
            object_key=object_key,
            headers=headers or {},
            # TODO(reweeden): Do we really want to control access by
            # bucket? Wouldn't it make more sense to control access by
            # path instead?
            _access_control=self.access_control.get(bucket)
        )


def _walk_entries(node: dict, path=()) -> Generator[Tuple[str, tuple, Optional[dict]], None, None]:
    """A generator to recursively yield all leaves of a bucket map"""

    for key, val in node.items():
        if key in ("PUBLIC_BUCKETS", "PRIVATE_BUCKETS"):
            continue

        path_parts = (*path, key)

        # Check if we hit a leaf of the YAML tree
        if isinstance(val, str):
            yield val, path_parts, None
        elif "bucket" in val:
            yield val["bucket"], path_parts, val.get("headers")

        elif val:
            yield from _walk_entries(val, path_parts)


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


class IamPolicyGenerator:
    def __init__(self, groups: Iterable[str] = None):
        self.groups = groups

    def _is_accessible(self, required_groups: Optional[set]) -> bool:
        return _is_accessible(required_groups, self.groups)

    def generate_policy(self, entries: Iterable[BucketMapEntry]) -> dict:
        full_access_entries = []
        partial_access_entries = []

        for entry in entries:
            if self._is_whole_bucket_accessible(entry):
                collection = full_access_entries
            else:
                collection = partial_access_entries
            collection.append(entry)

        full_access_statement = ({
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [
                resource
                for entry in full_access_entries
                for resource in (
                    f"arn:aws:s3:::{entry.bucket}",
                    f"arn:aws:s3:::{entry.bucket}/*"
                )
            ]
        },) if full_access_entries else ()

        statement = [
            *full_access_statement,
            *(
                statement
                for entry in partial_access_entries
                for statement in self._generate_iam_statements(entry)
            )
        ]
        policy = {
            "Version": "2012-10-17",
            "Statement": statement or [
                # Special case noop statement that will never match anything.
                # We need this because IAM doesn't allow empty statement lists
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["*"],
                    "Condition": {
                        "StringNotLike": {
                            "s3:prefix": [""]
                        }
                    }
                }
            ]
        }

        return policy

    def _is_whole_bucket_accessible(self, entry: BucketMapEntry) -> bool:
        if entry._access_control is None:
            return True

        return all(
            self._is_accessible(required_groups)
            for required_groups in entry._access_control.values()
        )

    def _generate_iam_statements(self, entry: BucketMapEntry) -> Generator[dict, None, None]:
        assert entry._access_control, "Public buckets should be handled already"

        for condition in self._generate_iam_conditions(entry._access_control):
            statement = {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    f"arn:aws:s3:::{entry.bucket}",
                    f"arn:aws:s3:::{entry.bucket}/*"
                ]
            }
            if condition:
                statement["Condition"] = condition

            yield statement

    def _generate_iam_conditions(self, access_control: dict) -> Generator[dict, None, None]:
        access_control = dict(access_control)
        access_control.setdefault("", None)

        conditions = self._generate_string_match_conditions(access_control)

        for string_like, string_not_like in conditions:
            condition = {}
            if string_like:
                condition["StringLike"] = {
                    "s3:prefix": string_like
                }
            if string_not_like:
                condition["StringNotLike"] = {
                    "s3:prefix": string_not_like
                }

            yield condition

    def _generate_string_match_conditions(
        self,
        access_control: dict
    ) -> Generator[Tuple[list, list], None, None]:
        """Generate StringLike and StringNotLike lists needed to describe
        bucket permissions in IAM policy terms.

        Each pair of lists should be added as conditions on new allow
        statement for the entire bucket.
        """
        # Since we are limited to using prefix matching, we can only describe
        # one nested interval per IAM statement.
        #     public/private/public/
        #     ^^^^^^^ allow
        #     ^^^^^^^^^^^^^^^ deny
        # Will allow anything in public/ but not public/private/. If we need to
        # allow more stuff in public/private/public/ we'll need to use a second
        # IAM statement for that.

        # Find all prefix intervals which we should be allowed to access
        # Examples (allow, deny):
        #    (public/, public/private/)
        #    (public/private/public, public/private/public/private)
        #    (, private/)
        allowed_intervals = {}
        for key_prefix, access in reversed(access_control.items()):
            if self._is_accessible(access):
                assert key_prefix not in allowed_intervals
                allowed_intervals[key_prefix] = []
                continue

            # NOTE: O(n**2) for n = len(access_control).
            # Not a big deal unless someone has a seriously insane auto
            # generated bucketmap that makes heavy use of prefix permissions
            longest_prefix, _ = max(
                ((k, len(k)) for k in allowed_intervals if key_prefix.startswith(k)),
                key=lambda x: x[1],
                default=(None, 0)
            )
            if longest_prefix is None:
                continue

            allowed_intervals[longest_prefix].append(key_prefix)

        # Merge endpoints
        # For example we may have a bunch of open intervals:
        #     (public1/, )
        #     (public2/, )
        # Which should be merged into a single condition
        allowed_intervals_endpoints = defaultdict(list)
        for start_point, end_points in allowed_intervals.items():
            allowed_intervals_endpoints[tuple(end_points)].append(start_point)

        # Transform output so it makes more sense to humans
        # Reversing list order is purely aesthetic so that the generated
        # condition values are in the same order as in the bucket map.
        yield from (
            (
                [s for s in like[::-1] if s],
                [s for s in not_like[::-1] if s]
            )
            for not_like, like in allowed_intervals_endpoints.items()
        )
