"""Pagination helpers for SQLAlchemy queries."""

from math import ceil

from flask import request


class Pagination:
    """Small pagination object compatible with Flask SQLAlchemy templates."""

    def __init__(self, query, page, per_page, total, items):
        self.query = query
        self.page = page
        self.per_page = per_page
        self.total = total
        self.items = items

    @property
    def has_prev(self):
        return self.page > 1

    @property
    def has_next(self):
        return self.page * self.per_page < self.total

    @property
    def prev_num(self):
        return self.page - 1

    @property
    def next_num(self):
        return self.page + 1

    @property
    def pages(self):
        if self.per_page <= 0:
            return 0
        return int(ceil(self.total / float(self.per_page)))

    def iter_pages(self, left_edge=2, left_current=2, right_current=3, right_edge=2):
        last = 0
        for number in range(1, self.pages + 1):
            if (
                number <= left_edge
                or self.page - left_current - 1 < number < self.page + right_current
                or number > self.pages - right_edge
            ):
                if last + 1 != number:
                    yield None
                yield number
                last = number


def paginate_query(query, page, per_page=25):
    """Return a Pagination object for a SQLAlchemy query."""
    page = max(int(page or 1), 1)
    per_page = min(max(int(per_page or 25), 1), 100)
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return Pagination(query=query, page=page, per_page=per_page, total=total, items=items)


def get_page_from_request(default=1):
    """Read the page number from request arguments."""
    try:
        return max(int(request.args.get("page", default)), 1)
    except (TypeError, ValueError):
        return default
