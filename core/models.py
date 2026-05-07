"""Domain models returned by this OAuth client library."""


class User:
    """Represents an authenticated user from the OAuth/account server."""

    def __init__(self, _id, name, email, nickname, avatar):
        self.id = _id
        self.name = name
        self.email = email
        self.nickname = nickname
        self.avatar = avatar
        self.groups = []

    def __repr__(self):
        return "<User %r>" % self.name

    def to_dict(self):
        return dict(
            id=self.id,
            name=self.name,
            email=self.email,
            nickname=self.nickname,
            avatar=self.avatar,
            groups=[group.to_dict() for group in self.groups],
        )


class Group:
    """Represents a group that can be attached to a user."""

    def __init__(self, _id, name, description):
        self.id = _id
        self.name = name
        self.description = description

    def __repr__(self):
        return "<Group %r>" % self.name

    def to_dict(self):
        return dict(id=self.id, name=self.name, description=self.description)
