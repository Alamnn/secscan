from secscan import idor_candidates, PageParser


def test_idor_path_and_query():
    f = idor_candidates("http://x/orders/1001?user_id=7")
    assert len(f) == 2


def test_idor_none():
    assert idor_candidates("http://x/about") == []


def test_parser_collects_inputs_and_links():
    p = PageParser()
    p.feed('<a href="/a?x=1"></a><input name="user">')
    assert p.links == ["/a?x=1"] and p.inputs == ["user"]
