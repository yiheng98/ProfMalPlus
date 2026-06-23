from object_type_dict import OBJECT


class Object:
    def __init__(
        self,
        name: str,
        object_type: str,
        source_pdg: int | None,
        qualified_name: str | None = None,
    ):
        self.object_name = name  # Object name, mainly kept for debugging.
        self.object_type = object_type  # Identifier type, e.g. OBJECT or GLOBAL_OBJECT.
        self.source_pdg = source_pdg  # PDG this object belongs to.
        self.qualified_name = qualified_name  # full name of the object
        self.property_dict: dict[str, "Object | str | None"] = {}

    def get_name(self) -> str:
        return self.object_name

    def get_object_type(self) -> str:
        return self.object_type

    def set_object_type(self, object_type: str) -> None:
        self.object_type = object_type

    def get_pdg(self) -> int | None:
        return self.source_pdg

    def set_qualified_name(self, qualified_name: str | None) -> None:
        self.qualified_name = qualified_name

    def get_qualified_name(self) -> str | None:
        return self.qualified_name

    def _new_wildcard(self, qualified_name: str | None = None) -> "Object":
        """
        Create a wildcard Object that uses the *current* object's source_pdg.
        Centralizing this avoids accidentally using the root caller's
        source_pdg when wildcards are inserted deep in a chain.
        """
        return Object(
            name="wildcard",
            object_type=OBJECT,
            source_pdg=self.source_pdg,
            qualified_name=qualified_name,
        )

    def set_property(self, property_list: list[str], target) -> None:
        """
        Set the value at the path described by ``property_list``.

        Walks the property tree, creating wildcard placeholders for any
        intermediate path component that does not already point to an
        ``Object``. If the intermediate slot currently holds a ``str``
        (e.g. a qualified-name fragment such as ``"crypto"``), the string
        is lifted onto the new wildcard's ``qualified_name`` so the
        identification chain is not lost.
        """
        if not property_list:
            return
        current_object = self
        last_index = len(property_list) - 1
        for index, prop in enumerate(property_list):
            if index == last_index:
                current_object.property_dict[prop] = target
                return
            existing = current_object.property_dict.get(prop)
            if isinstance(existing, Object):
                current_object = existing
            else:
                # The intermediate path is not an Object (None, str, or missing).
                # Insert a wildcard placeholder; if the slot is a string, promote
                # it to the wildcard's qualified_name so the known chain survives.
                qualified = existing if isinstance(existing, str) else None
                wildcard = current_object._new_wildcard(qualified_name=qualified)
                current_object.property_dict[prop] = wildcard
                current_object = wildcard

    def resolve_qualified_path(self, property_list: list[str]) -> tuple["Object", list[str]]:
        """
        Walk into nested ``Object`` properties as far as possible, stopping
        when only one property remains (so the leaf name is preserved for
        the caller) or when the next slot is not an ``Object``.
        """
        if not property_list or len(property_list) <= 1:
            return self, property_list

        current = self
        remaining = list(property_list)
        while len(remaining) > 1:
            first = remaining[0]
            value = current.property_dict.get(first)
            if isinstance(value, Object):
                current = value
                remaining = remaining[1:]
            else:
                break
        return current, remaining

    def get_property_actual_value(self, property_list: list[str]) -> "Object | str | None":
        """
        Resolve the value at ``property_list`` relative to ``self``.

        Returns:
            - ``Object`` if the path resolves to a known ``Object``
              (including wildcards).
            - ``str`` if the path resolves to a string (e.g. a qualified
              name fragment) — possibly composed with the remaining path.
            - ``None`` if the path is unresolvable.
        """
        if not property_list or len(property_list) == 0:
            return self

        first_property = property_list[0]
        left_property_list = property_list[1:]
        if first_property in self.property_dict:
            property_value = self.property_dict[first_property]
            if isinstance(property_value, Object):
                return property_value.get_property_actual_value(left_property_list)
            elif property_value is None:
                return None
            else:
                # property_value is a string, such as a qualified name; append the remaining path.
                if not left_property_list:
                    return property_value
                return f"{property_value}.{'.'.join(left_property_list)}"
        else:
            if self.qualified_name is not None:
                return f"{self.qualified_name}.{'.'.join(property_list)}"
            else:
                return None

    def compose_qualified_string(self, property_list: list[str]) -> str | None:
        """
        Rules:
        1. Walk through ``property_dict`` and descend when an ``Object`` is found.
        2. When a ``str`` property value is found, append the remaining properties to it.
        3. When the walk cannot continue because the property is missing or ``None``,
           append the remaining properties to the deepest ``Object``'s
           ``qualified_name``; return ``None`` if that name is also ``None`` and
           unmatched properties remain.
        4. If the walk consumes the full path, return the deepest ``Object``'s
           ``qualified_name``, which may be ``None``.
        """
        current = self
        remaining = list(property_list)

        while remaining:
            first = remaining[0]
            value = current.property_dict.get(first)
            if isinstance(value, Object):
                current = value
                remaining = remaining[1:]
                continue
            if isinstance(value, str):
                tail = remaining[1:]
                if not tail:
                    return value
                return f"{value}.{'.'.join(tail)}"
            # value is None / key missing
            break

        if not remaining:
            return current.qualified_name
        if current.qualified_name is None:
            return None
        return f"{current.qualified_name}.{'.'.join(remaining)}"

    def __repr__(self) -> str:
        return (
            f"Object(name={self.object_name!r}, object_type={self.object_type!r}, "
            f"full_name={self.qualified_name!r}, property_dict={self.property_dict!r})"
        )
