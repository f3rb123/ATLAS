from concurrent.futures import ThreadPoolExecutor
from atlas.db import session, Document
from atlas.gateway import reserve, ProviderError


def test_concurrent_first_reservations_do_not_oversubscribe(db):
    def attempt(i):
        with session() as other:
            try:
                return reserve(other, "u", str(i), 25)
            except ProviderError:
                return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(attempt, range(8)))
    assert sum(r is not None for r in results) == 4
    db.expire_all()
    budget = db.get(Document, "budget-global").value()
    assert sum(r["amount"] for r in budget["reserved"].values()) == 100
