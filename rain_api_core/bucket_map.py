from collections import defaultdict
from dataclasses import dataclass, field
from typing import (
    Dict,
    Generator,
    Iterable,
    List,
    Literal,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

# By default, buckets are accessible to any logged in users. This is
# represented by an empty set.
_DEFAULT_PERMISSION_FACTORY = set

AccessPermission = Union[Set[str], None, Literal[False]]
PublicAccess = None
NoAccess: Literal[False] = False


def _is_accessible(
    required_groups: AccessPermission,
    groups: Optional[Iterable[str]]
) -> bool:
    # Check for public access
    if required_groups is PublicAccess:
        return True

    if required_groups is NoAccess:
        return False

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
    _access_control: Optional[Dict[str, AccessPermission]] = None

    def is_accessible(self, groups: Iterable[str] = None) -> bool:
        """Check if the object is accessible with the given permissions.

        Setting `groups` to an iterable implies that the user has logged in,
        which is different from setting it to None which implies public access
        is needed.
        """

        required_groups = self.get_required_groups()
        return _is_accessible(required_groups, groups)

    def get_required_groups(self) -> AccessPermission:
        """Get a set of permissions protecting this object.

        It is sufficient to have one of the permissions in the set in order to
        access the object. An empty set means any logged in user can access the
        object.

        :returns: Set[str] -- Can access the object if any permission matches
        :returns: None -- The object has public access
        :returns: False -- The object cannot be accessed by anyone
        """
        if not self._access_control:
            return _DEFAULT_PERMISSION_FACTORY()

        # NOTE: Key order is important here. Most deeply nested keys need to be
        # checked first.
        for key_prefix, access in self._access_control.items():
            if self.object_key.startswith(key_prefix):
                return access

        return _DEFAULT_PERMISSION_FACTORY()


class BucketMap():
    def __init__(
        self,
        bucket_map: dict,
        bucket_name_prefix: str = "",
        reverse: bool = False,
        iam_compatible: bool = True
    ):
        self.bucket_map = bucket_map
        self.access_control = _parse_access_control(bucket_map)
        self._iam_compatible = iam_compatible
        if iam_compatible:
            _check_iam_compatible(self.access_control)
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
        if not self._iam_compatible:
            _check_iam_compatible(self.access_control)
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
        if key in ("PUBLIC_BUCKETS", "PRIVATE_BUCKETS", "NOACCESS_BUCKETS"):
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
            "key/foo/bar": None,
            "key/bar/baz": {"group"},
            "key": {"group2"},
            "": set()
        },
        "bucket2": {
            "": None
        },
        "bucket3": {
            "": {"group3"}
        }
    }
    """
    public_buckets = bucket_map.get("PUBLIC_BUCKETS", ())
    private_buckets = bucket_map.get("PRIVATE_BUCKETS", {})
    no_access_buckets = bucket_map.get("NOACCESS_BUCKETS", ())

    try:
        access_list: List[Tuple[str, AccessPermission]] = [
            (rule, PublicAccess) for rule in public_buckets
        ]
    except TypeError:
        access_list = []
    access_list.extend((rule, set(groups)) for rule, groups in private_buckets.items())
    access_list.extend((rule, NoAccess) for rule in no_access_buckets)

    # Relying on the fact that `sort` is stable. The order in which we add
    # public/private rules to `access_list` is therefore important.
    access_list.sort(key=lambda item: len(item[0]), reverse=True)

    # Convert to dictionary for easier lookup on individual buckets
    # We're relying on python's dictionary keys being insertion ordered
    access: Dict[str, Dict[str, AccessPermission]] = defaultdict(dict)
    for (rule, permission) in access_list:
        bucket, *prefix = rule.split("/", 1)
        access[bucket]["".join(prefix)] = permission

    # Set default permissions. We do this after the other rules have been added
    # so that the default permission rule always comes last.
    for obj in access.values():
        if "" not in obj:
            obj[""] = _DEFAULT_PERMISSION_FACTORY()

    return dict(access)


def _check_iam_compatible(access_control: dict):
    """Check that the access control configuration is compatible with IAM.

    This means nested prefixes must always be accessible to a superset of their
    parents e.g. if `foo/` is accessible to `group_1` and `group_2`, then
    `foo/bar/` must also be accessible to at least `group_1` and `group_2`.

    :param access_control: dict of access rules as returned by
        `_parse_access_control`
    :raises: ValueError if the access control list contains incompatible rules
    """

    for bucket, access_rules in access_control.items():
        for key_prefix, access in reversed(access_rules.items()):
            longest_prefix = _get_longest_prefix(key_prefix, access_rules)
            if longest_prefix is None:
                continue

            parent_access = access_rules[longest_prefix]
            if access is PublicAccess or parent_access is NoAccess:
                # Public access is always allowed.
                # If the parent has no access, then it is impossible for the
                # child to be more restrictive, so any permission is allowed.
                continue

            if parent_access is not PublicAccess:
                if not access or parent_access and parent_access <= access:
                    continue

            raise ValueError(
                f"Invalid prefix permissions for bucket '{bucket}': "
                f"'{key_prefix}' has {_access_text(access)} but "
                f"'{longest_prefix}' has {_access_text(parent_access)}"
            )


def _get_longest_prefix(key: str, prefixes: Iterable[str]) -> Optional[str]:
    # NOTE: O(n**2) for n = len(access_control).
    # Not a big deal unless someone has a seriously insane auto
    # generated bucketmap that makes heavy use of prefix permissions
    longest_prefix, _ = max(
        (
            (k, len(k))
            for k in prefixes
            if key.startswith(k) and key != k
        ),
        key=lambda x: x[1],
        default=(None, 0)
    )
    return longest_prefix


def _access_text(access) -> str:
    if access is PublicAccess:
        return "public access"
    if access is NoAccess:
        return "no access"
    if access == set():
        return "protected access"

    return str(access)


class IamPolicyGenerator:
    def __init__(self, groups: Iterable[str]):
        self.groups = groups

    def _is_accessible(self, required_groups: Optional[set]) -> bool:
        return _is_accessible(required_groups, self.groups)

    def generate_policy(self, entries: Iterable[BucketMapEntry]) -> Optional[dict]:
        # Dedupe across buckets
        bucket_access = {
            entry.bucket: entry._access_control
            for entry in entries
        }

        get_object_statement = _IamStatement(effect="Allow", action=["s3:GetObject"])
        list_bucket_prefixes = defaultdict(list)
        for bucket, access_control in bucket_access.items():
            consolidated = self._consolidate_access_rules(access_control)

            for key_prefix, _ in reversed(consolidated.items()):
                if key_prefix:
                    list_bucket_prefixes[key_prefix].append(bucket)
                else:
                    get_object_statement.add_action("s3:ListBucket")
                    get_object_statement.add_resource(f"arn:aws:s3:::{bucket}")

                get_object_statement.add_resource(f"arn:aws:s3:::{bucket}/{key_prefix}*")

        if not get_object_statement.resource:
            return None

        # Merge prefixes when all resources match
        list_bucket_conditions = defaultdict(list)
        for prefix, buckets in list_bucket_prefixes.items():
            list_bucket_conditions[tuple(sorted(buckets))].append(prefix)

        return {
            "Version": "2012-10-17",
            "Statement": [
                get_object_statement.to_dict(),
                *(
                    _IamStatement(
                        effect="Allow",
                        action=["s3:ListBucket"],
                        resource=[f"arn:aws:s3:::{bucket}" for bucket in buckets],
                        condition={
                            "StringLike": {
                                "s3:prefix": [f"{prefix}*" for prefix in prefixes]
                            }
                        }
                    ).to_dict()
                    for buckets, prefixes in list_bucket_conditions.items()
                )
            ]
        }

    def _consolidate_access_rules(self, access_control: Optional[dict]) -> dict:
        """Removes redundant rules by finding the shortest prefixes that
        are accessible.

        For example if our access rules look like this:
        {
            "key1/foo/bar": None,
            "key1/bar/baz": set(),
            "key1/": {"group", "group2"},
            "key2/": {"group", "group2", "group3"},
            "key3/": {"group2", "group3"},
            "": {"group2"}
        }

        Our consolidated access rules for a user in 'group' look like this:
        {
            "key1/": {"group", "group2"},
            "key2/": {"group", "group2", "group3"},
        }
        """
        if access_control is None:
            return {"": None}

        consolidated = {}
        for key_prefix, access in reversed(access_control.items()):
            if self._is_accessible(access):
                longest_prefix = _get_longest_prefix(key_prefix, consolidated)
                if longest_prefix is None:
                    consolidated[key_prefix] = access

        return consolidated


class _IamStatement:
    """A helper for generating valid IAM statements"""

    def __init__(
        self,
        effect: Optional[str] = None,
        action: Iterable[str] = (),
        resource: Iterable[str] = (),
        condition: Optional[dict] = None,
    ):
        self.effect = effect
        # Using dict instead of set because sets are unordered.
        self.action = dict((val, None) for val in action)
        self.resource = dict((val, None) for val in resource)
        self.condition = condition

    def add_action(self, value: str):
        self.action[value] = None

    def add_resource(self, value: str):
        self.resource[value] = None

    def to_dict(self) -> dict:
        if not self.effect:
            raise ValueError("'effect' must have a value")
        if not self.action:
            raise ValueError("'action' must have a value")
        if not self.resource:
            raise ValueError("'resource' must have a value")

        statement = {
            "Effect": self.effect,
            "Action": list(self.action),
            "Resource": list(self.resource)
        }
        if self.condition is not None:
            statement["Condition"] = self.condition

        return statement
