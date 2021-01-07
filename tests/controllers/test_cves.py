import pytest
from flask import request


def test_list_no_cves(client):
    response = client.get("/cve")
    assert response.status_code == 200
    assert b"No CVE found." in response.data


def test_list_all_cves(client, create_cve, make_soup, get_cve_names):
    create_cve("CVE-2018-18074")
    create_cve("CVE-2020-9392")
    create_cve("CVE-2020-26116")
    create_cve("CVE-2020-27781")

    response = client.get("/cve")
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert response.status_code == 200
    assert sorted(cves) == [
        "CVE-2018-18074",
        "CVE-2020-26116",
        "CVE-2020-27781",
        "CVE-2020-9392",
    ]


def test_list_cves_paginated(app, client, create_cve, make_soup, get_cve_names):
    old = app.config["CVES_PER_PAGE"]
    app.config["CVES_PER_PAGE"] = 3

    create_cve("CVE-2018-18074")
    create_cve("CVE-2020-9392")
    create_cve("CVE-2020-26116")
    create_cve("CVE-2020-27781")
    create_cve("CVE-2019-17052")

    response = client.get("/cve")
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert len(cves) == 3
    assert sorted(cves) == ["CVE-2019-17052", "CVE-2020-26116", "CVE-2020-27781"]

    response = client.get("/cve?page=1")
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert len(cves) == 3
    assert sorted(cves) == ["CVE-2019-17052", "CVE-2020-26116", "CVE-2020-27781"]

    response = client.get("/cve?page=2")
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert len(cves) == 2
    assert sorted(cves) == ["CVE-2018-18074", "CVE-2020-9392"]

    response = client.get("/cve?page=3")
    assert response.status_code == 404

    app.config["CVES_PER_PAGE"] = old


@pytest.mark.parametrize(
    "url,result",
    [
        ("/cve?search=nonexistingkeyword", []),
        ("/cve?search=CRLF", ["CVE-2020-26116"]),
        ("/cve?search=http", ["CVE-2018-18074", "CVE-2020-26116"]),
    ],
)
def test_search_cves(client, create_cve, make_soup, get_cve_names, url, result):
    create_cve("CVE-2018-18074")
    create_cve("CVE-2020-9392")
    create_cve("CVE-2020-26116")

    response = client.get(url)
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert sorted(cves) == result


@pytest.mark.parametrize(
    "url,result",
    [
        (
            "/cve?cwe=",
            ["CVE-2018-18074", "CVE-2020-26116", "CVE-2020-27781", "CVE-2020-9392"],
        ),
        ("/cve?cwe=CWE-276", ["CVE-2020-9392"]),
        ("/cve?cwe=CWE-522", ["CVE-2018-18074", "CVE-2020-27781"]),
        ("/cve?cwe=CWE-1234", []),
    ],
)
def test_filtered_by_cwe(client, create_cve, make_soup, get_cve_names, url, result):
    create_cve("CVE-2018-18074")
    create_cve("CVE-2020-9392")
    create_cve("CVE-2020-26116")
    create_cve("CVE-2020-27781")

    response = client.get(url)
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert sorted(cves) == result


@pytest.mark.parametrize(
    "url,result",
    [
        ("/cve?cvss=low", ["CVE-2019-17052"]),
        ("/cve?cvss=medium", ["CVE-2020-26116", "CVE-2020-27781", "CVE-2020-9392"]),
        ("/cve?cvss=high", ["CVE-2018-18074"]),
    ],
)
def test_filtered_by_cvss(client, create_cve, make_soup, get_cve_names, url, result):
    create_cve("CVE-2018-18074")
    create_cve("CVE-2020-9392")
    create_cve("CVE-2020-26116")
    create_cve("CVE-2020-27781")
    create_cve("CVE-2019-17052")

    response = client.get(url)
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert sorted(cves) == result


@pytest.mark.parametrize(
    "url,result",
    [
        (
            "/cve?vendor=&product=",
            ["CVE-2019-17052", "CVE-2019-8075", "CVE-2020-27781"],
        ),
        ("/cve?vendor=foo&product=bar", []),
        ("/cve?vendor=redhat&product=ceph_storage", ["CVE-2020-27781"]),
        ("/cve?vendor=linux&product=linux_kernel", ["CVE-2019-17052", "CVE-2019-8075"]),
        ("/cve?vendor=", ["CVE-2019-17052", "CVE-2019-8075", "CVE-2020-27781"]),
        ("/cve?vendor=foo", []),
        ("/cve?vendor=redhat", ["CVE-2020-27781"]),
        ("/cve?vendor=linux", ["CVE-2019-17052", "CVE-2019-8075"]),
    ],
)
def test_filtered_by_vendors_products(
    client, create_cve, make_soup, get_cve_names, url, result
):
    create_cve("CVE-2019-8075")
    create_cve("CVE-2019-17052")
    create_cve("CVE-2020-27781")

    response = client.get(url)
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert sorted(cves) == result
